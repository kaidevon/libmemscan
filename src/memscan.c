/*
 * Copyright (C) 2026 kaidev
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; version 3 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "memscan.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

struct task_perf {
    uint64_t bytes;
    uint64_t cb_count;
    uint64_t found;
};

/* Task for multi-value integer scan */
struct scan_task_multi {
    pid_t pid;
    struct vm_area* vm_area;
    const uint64_t* values;
    size_t value_count;
    int value_size;
    int align;
    struct ms_progress* progress;
    struct ms_result** result;
    process_reader_t process_reader;
    struct task_perf perf;
    int ret;
};

/* Task for generic single-pattern scan */
struct scan_task_generic {
    pid_t pid;
    struct vm_area* vm_area;
    const void* src;
    size_t size;
    int align;
    struct ms_progress* progress;
    struct ms_result** result;
    process_reader_t process_reader;
    struct task_perf perf;
    int ret;
};

/* Task for callback-based block matching scan */
struct scan_task_callback {
    pid_t pid;
    struct vm_area* vm_area;
    const void** src;
    size_t* size;
    int* align;
    int count;
    struct ms_progress* progress;
    struct ms_result** result;
    process_reader_t process_reader;
    memscanv_compar_t compar;
    void *userdata;
    struct task_perf perf;
    int ret;
};

static inline void global_perf_start(struct ms_perf* p, int nthreads) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    atomic_init(&p->start_ns, (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
    atomic_init(&p->end_ns, 0);
    atomic_init(&p->bytes, 0);
    atomic_init(&p->cb_count, 0);
    atomic_init(&p->found, 0);
    p->thread_count = nthreads;
}

static inline void global_perf_stop(struct ms_perf* p) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    atomic_store(&p->end_ns, (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec);
}

static void global_perf_report(const struct ms_perf* p) {
    uint64_t start = atomic_load(&p->start_ns);
    uint64_t end   = atomic_load(&p->end_ns);
    double elapsed = (end - start) / 1e9;
    fprintf(stderr,
        "=== memscan perf ===\n"
        "  threads    : %d\n"
        "  elapsed    : %.3f s\n"
        "  bytes read : %llu (%.2f MB)\n"
        "  cb_counts  : %llu\n"
        "  found      : %llu\n",
        p->thread_count,
        elapsed,
        (unsigned long long)atomic_load(&p->bytes),
        (double)atomic_load(&p->bytes) / (1024.0 * 1024.0),
        (unsigned long long)atomic_load(&p->cb_count),
        (unsigned long long)atomic_load(&p->found)
    );
}

static void merge_task_perf(struct ms_perf* global, const struct task_perf* local) {
    if (!global || !local) return;
    atomic_fetch_add(&global->bytes, local->bytes);
    atomic_fetch_add(&global->cb_count, local->cb_count);
    atomic_fetch_add(&global->found, local->found);
}

static int add_result(struct ms_result **result, uint64_t addr) {
    if (!result)
        return -1;

    if (*result == NULL) {
        *result = (struct ms_result *)calloc(1, sizeof(struct ms_result));
        if (!*result)
            return -1;
        pthread_mutex_init(&(*result)->lock, NULL);
        (*result)->perf = NULL;
    }

    struct ms_result *res = *result;
    pthread_mutex_lock(&res->lock);

    struct vm_list *tail = res->tail;
    if (!tail) {
        tail = (struct vm_list *)calloc(1, sizeof(struct vm_list));
        if (!tail) {
            pthread_mutex_unlock(&res->lock);
            return -1;
        }
        tail->used = 0;
        tail->next = NULL;
        res->head = res->tail = tail;
    }

    int idx = tail->used;
    if (idx < VM_LIST_CAPACITY) {
        tail->addr[idx] = addr;
        tail->used = idx + 1;
        pthread_mutex_unlock(&res->lock);
        return 0;
    }

    struct vm_list *new_block = (struct vm_list *)calloc(1, sizeof(struct vm_list));
    if (!new_block) {
        pthread_mutex_unlock(&res->lock);
        return -1;
    }
    new_block->used = 0;
    new_block->next = NULL;

    tail->next = new_block;
    res->tail = new_block;

    new_block->addr[0] = addr;
    new_block->used = 1;

    pthread_mutex_unlock(&res->lock);
    return 0;
}

void free_ms_result(struct ms_result** result) {
    if (!result || !*result)
        return;
    struct ms_result* res = *result;
    struct vm_list* block = res->head;
    while (block) {
        struct vm_list* next = block->next;
        free(block);
        block = next;
    }
    free(res->perf);
    pthread_mutex_destroy(&res->lock);
    free(res);
    *result = NULL;
}

struct ms_progress* create_ms_progress(void) {
    struct ms_progress* p = (struct ms_progress*)calloc(1, sizeof(struct ms_progress));
    if (!p)
        return NULL;

    atomic_init(&p->tot_len, 0);
    atomic_init(&p->current_pos, 0);
    atomic_init(&p->total_found, 0);
    atomic_init(&p->cancel, 0);
    atomic_init(&p->pause, 0);

    pthread_mutex_init(&p->mtx, NULL);
    pthread_cond_init(&p->cond, NULL);

    return p;
}

void free_ms_progress(struct ms_progress* progress) {
    if (progress) {
        pthread_mutex_destroy(&progress->mtx);
        pthread_cond_destroy(&progress->cond);
        free(progress);
    }
}

void ms_progress_pause(struct ms_progress* p) {
    if (!p) return;
    atomic_store(&p->pause, 1);
}

void ms_progress_resume(struct ms_progress* p) {
    if (!p) return;
    pthread_mutex_lock(&p->mtx);
    atomic_store(&p->pause, 0);
    pthread_cond_broadcast(&p->cond);
    pthread_mutex_unlock(&p->mtx);
}

void ms_progress_cancel(struct ms_progress* p) {
    if (!p) return;
    int expected = 0;
    if (atomic_compare_exchange_strong(&p->cancel, &expected, 1)) {
        pthread_mutex_lock(&p->mtx);
        pthread_cond_broadcast(&p->cond);
        pthread_mutex_unlock(&p->mtx);
    }
}

static int compare_uint64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static int value_in_set(uint64_t val, const uint64_t *sorted, size_t n) {
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (sorted[mid] < val)
            lo = mid + 1;
        else if (sorted[mid] > val)
            hi = mid;
        else
            return 1;
    }
    return 0;
}

static int scan_fast_int_multi(const unsigned char *buf, size_t buf_len,
                               const uint64_t *sorted_values, size_t value_count,
                               int value_size, int align, uint64_t base,
                               struct ms_result **result,
                               struct ms_progress *progress,
                               struct task_perf *tperf)
{
    if (value_size == 4) {
        for (size_t i = 0; i + 4 <= buf_len; i += align) {
            uint32_t val;
            memcpy(&val, buf + i, 4);
            if (value_in_set((uint64_t)val, sorted_values, value_count)) {
                if (add_result(result, base + i) != 0) return -1;
                if (progress) atomic_fetch_add(&progress->total_found, 1);
                if (tperf) tperf->found++;
            }
        }
    } else if (value_size == 8) {
        for (size_t i = 0; i + 8 <= buf_len; i += align) {
            uint64_t val;
            memcpy(&val, buf + i, 8);
            if (value_in_set(val, sorted_values, value_count)) {
                if (add_result(result, base + i) != 0) return -1;
                if (progress) atomic_fetch_add(&progress->total_found, 1);
                if (tperf) tperf->found++;
            }
        }
    } else {
        return -1;
    }
    return 0;
}

static inline int search_buffer_multi(const unsigned char *buf, size_t buf_len,
                                      const uint64_t *sorted_values, size_t value_count,
                                      int value_size, int align, uint64_t base,
                                      struct ms_result **result,
                                      struct ms_progress *progress,
                                      struct task_perf *tperf)
{
    if (value_size == 4 || value_size == 8)
        return scan_fast_int_multi(buf, buf_len, sorted_values, value_count,
                                   value_size, align, base, result, progress, tperf);
    return -1;
}

static int do_memscanv_multi(pid_t pid, struct vm_area* vm_area,
                             const uint64_t* values, size_t value_count, int value_size,
                             int align,
                             struct ms_progress* progress,
                             struct ms_result** result,
                             process_reader_t process_reader,
                             struct task_perf* tperf)
{
    if (!values || value_count == 0 || !result || !process_reader) return -1;
    if (value_size != 4 && value_size != 8) return -1;
    if (align == 0 || (align & (align - 1)) != 0) return -1;
    if (!vm_area) return 0;

    size_t buf_size = CHUNK_READ_SIZE + value_size - 1;
    unsigned char *buf = malloc(buf_size);
    if (!buf) return -1;

    for (struct vm_area *cur = vm_area; cur; cur = cur->next) {
        uintptr_t pos = cur->start;
        uintptr_t end = cur->end;

        while (pos + value_size <= end) {
            if (progress) {
                if (atomic_load(&progress->cancel)) {
                    free(buf);
                    return -2;
                }
                if (atomic_load(&progress->pause)) {
                    pthread_mutex_lock(&progress->mtx);
                    while (atomic_load(&progress->pause) && !atomic_load(&progress->cancel)) {
                        pthread_cond_wait(&progress->cond, &progress->mtx);
                    }
                    pthread_mutex_unlock(&progress->mtx);
                    if (atomic_load(&progress->cancel)) {
                        free(buf);
                        return -2;
                    }
                }
            }

            size_t to_read = buf_size;
            if (pos + to_read > end) {
                to_read = end - pos;
            }

            struct iovec local_iov = { .iov_base = buf, .iov_len = to_read };
            struct iovec remote_iov = { .iov_base = (void *)pos, .iov_len = to_read };
            ssize_t nread = process_reader(pid, &local_iov, 1, &remote_iov, 1, cur);

            size_t advance;
            if (nread > 0) {
                size_t valid_len = (size_t)nread;
                if (tperf) tperf->bytes += valid_len;

                if (valid_len >= value_size) {
                    if (tperf) tperf->cb_count++;
                    if (search_buffer_multi(buf, valid_len,
                                            values, value_count, value_size,
                                            align, (uint64_t)pos,
                                            result, progress, tperf) != 0) {
                        free(buf);
                        return -1;
                    }
                }
                advance = (valid_len < value_size) ? valid_len : valid_len - (value_size - 1);
            } else {
                size_t remaining = end - pos;
                advance = (CHUNK_READ_SIZE < remaining) ? CHUNK_READ_SIZE : remaining;
            }

            pos += advance;
            size_t effective_advance = advance;

            if (align > 1) {
                uint64_t misalign = pos % align;
                if (misalign) {
                    size_t skip = align - misalign;
                    if (skip > (size_t)(end - pos)) {
                        skip = end - pos;
                    }
                    pos += skip;
                    effective_advance += skip;
                }
            }

            if (progress) {
                atomic_fetch_add(&progress->current_pos, effective_advance);
            }
        }

        if (pos < end) {
            uintptr_t tail_bytes = end - pos;
            pos = end;
            if (progress) {
                atomic_fetch_add(&progress->current_pos, tail_bytes);
            }
        }
    }

    free(buf);
    return 0;
}

static void build_bad_char_skip(const unsigned char *needle, size_t nlen,
                                size_t skip[256]) {
    for (int i = 0; i < 256; i++)
        skip[i] = nlen;
    for (size_t i = 0; i < nlen - 1; i++)
        skip[needle[i]] = nlen - 1 - i;
    if (nlen > 0)
        skip[needle[nlen - 1]] = 3;
}

static int scan_fast_int(const unsigned char *buf, size_t buf_len,
                         const unsigned char *needle, size_t nlen,
                         int align, uint64_t base,
                         struct ms_result **result,
                         struct ms_progress *progress,
                         struct task_perf *tperf)
{
    if (nlen == 4) {
        uint32_t target;
        memcpy(&target, needle, 4);
        for (size_t i = 0; i + 4 <= buf_len; i += align) {
            uint32_t val;
            memcpy(&val, buf + i, 4);
            if (val == target) {
                if (add_result(result, base + i) != 0) return -1;
                if (progress) atomic_fetch_add(&progress->total_found, 1);
                if (tperf) tperf->found++;
            }
        }
    } else if (nlen == 8) {
        uint64_t target;
        memcpy(&target, needle, 8);
        for (size_t i = 0; i + 8 <= buf_len; i += align) {
            uint64_t val;
            memcpy(&val, buf + i, 8);
            if (val == target) {
                if (add_result(result, base + i) != 0) return -1;
                if (progress) atomic_fetch_add(&progress->total_found, 1);
                if (tperf) tperf->found++;
            }
        }
    } else {
        return -1;
    }
    return 0;
}

static int scan_short_step(const unsigned char *buf, size_t buf_len,
                           const unsigned char *needle, size_t nlen,
                           int align, uint64_t base,
                           struct ms_result **result,
                           struct ms_progress *progress,
                           struct task_perf *tperf)
{
    for (size_t i = 0; i + nlen <= buf_len; i += align) {
        if (__builtin_memcmp(buf + i, needle, nlen) == 0) {
            if (add_result(result, base + i) != 0) return -1;
            if (progress) atomic_fetch_add(&progress->total_found, 1);
            if (tperf) tperf->found++;
        }
    }
    return 0;
}

static int scan_bmh(const unsigned char *buf, size_t buf_len,
                    const unsigned char *needle, size_t nlen,
                    uint64_t base,
                    struct ms_result **result,
                    struct ms_progress *progress,
                    struct task_perf *tperf)
{
    size_t skip[256];
    build_bad_char_skip(needle, nlen, skip);
    size_t pos = 0;
    while (pos + nlen <= buf_len) {
        if (__builtin_memcmp(buf + pos, needle, nlen) == 0) {
            if (add_result(result, base + pos) != 0) return -1;
            if (progress) atomic_fetch_add(&progress->total_found, 1);
            if (tperf) tperf->found++;
        }
        unsigned char last_byte = buf[pos + nlen - 1];
        pos += skip[last_byte];
    }
    return 0;
}

static inline int search_buffer_generic(const unsigned char *buf, size_t buf_len,
                                        const unsigned char *needle, size_t nlen,
                                        int align, uint64_t base,
                                        struct ms_result **result,
                                        struct ms_progress *progress,
                                        struct task_perf *tperf)
{
    if (align >= (int)nlen && (nlen == 4 || nlen == 8)) {
        return scan_fast_int(buf, buf_len, needle, nlen, align,
                             base, result, progress, tperf);
    } else if (nlen <= 4) {
        return scan_short_step(buf, buf_len, needle, nlen, align,
                               base, result, progress, tperf);
    } else {
        if (align > 1)
            return scan_short_step(buf, buf_len, needle, nlen, align,
                                   base, result, progress, tperf);
        else
            return scan_bmh(buf, buf_len, needle, nlen,
                            base, result, progress, tperf);
    }
}

static int do_memscan_generic(pid_t pid, struct vm_area* vm_area,
                              const void* src, size_t size, int align,
                              struct ms_progress* progress,
                              struct ms_result** result,
                              process_reader_t process_reader,
                              struct task_perf* tperf)
{
    if (!src || !result || !process_reader) return -1;
    if (size == 0 || align == 0 || (align & (align - 1)) != 0) return -1;
    if (!vm_area) return 0;

    size_t buf_size = CHUNK_READ_SIZE + size - 1;
    unsigned char *buf = malloc(buf_size);
    if (!buf) return -1;

    for (struct vm_area *cur = vm_area; cur; cur = cur->next) {
        uintptr_t pos = cur->start;
        uintptr_t end = cur->end;

        while (pos + size <= end) {
            if (progress) {
                if (atomic_load(&progress->cancel)) {
                    free(buf);
                    return -2;
                }
                if (atomic_load(&progress->pause)) {
                    pthread_mutex_lock(&progress->mtx);
                    while (atomic_load(&progress->pause) && !atomic_load(&progress->cancel)) {
                        pthread_cond_wait(&progress->cond, &progress->mtx);
                    }
                    pthread_mutex_unlock(&progress->mtx);
                    if (atomic_load(&progress->cancel)) {
                        free(buf);
                        return -2;
                    }
                }
            }

            size_t to_read = buf_size;
            if (pos + to_read > end) {
                to_read = end - pos;
            }

            struct iovec local_iov = { .iov_base = buf, .iov_len = to_read };
            struct iovec remote_iov = { .iov_base = (void *)pos, .iov_len = to_read };
            ssize_t nread = process_reader(pid, &local_iov, 1, &remote_iov, 1, cur);

            size_t advance;
            if (nread > 0) {
                size_t valid_len = (size_t)nread;
                if (tperf) tperf->bytes += valid_len;

                if (valid_len >= size) {
                    if (tperf) tperf->cb_count++;
                    if (search_buffer_generic(buf, valid_len,
                                              (const unsigned char *)src, size,
                                              align, (uint64_t)pos,
                                              result, progress, tperf) != 0) {
                        free(buf);
                        return -1;
                    }
                }
                advance = (valid_len < size) ? valid_len : valid_len - (size - 1);
            } else {
                size_t remaining = end - pos;
                advance = (CHUNK_READ_SIZE < remaining) ? CHUNK_READ_SIZE : remaining;
            }

            pos += advance;
            size_t effective_advance = advance;

            if (align > 1) {
                uint64_t misalign = pos % align;
                if (misalign) {
                    size_t skip = align - misalign;
                    if (skip > (size_t)(end - pos)) {
                        skip = end - pos;
                    }
                    pos += skip;
                    effective_advance += skip;
                }
            }

            if (progress) {
                atomic_fetch_add(&progress->current_pos, effective_advance);
            }
        }

        if (pos < end) {
            uintptr_t tail_bytes = end - pos;
            pos = end;
            if (progress) {
                atomic_fetch_add(&progress->current_pos, tail_bytes);
            }
        }
    }

    free(buf);
    return 0;
}

static void* scan_thread_multi(void* arg) {
    struct scan_task_multi* task = (struct scan_task_multi*)arg;
    task->ret = do_memscanv_multi(task->pid, task->vm_area,
                                  task->values, task->value_count, task->value_size,
                                  task->align,
                                  task->progress, task->result,
                                  task->process_reader,
                                  &task->perf);
    free_vm_area(task->vm_area);
    task->vm_area = NULL;
    struct ms_result* res = task->result ? *task->result : NULL;
    if (res && res->perf) {
        merge_task_perf(res->perf, &task->perf);
    }
    return NULL;
}

static void* scan_thread_generic(void* arg) {
    struct scan_task_generic* task = (struct scan_task_generic*)arg;
    task->ret = do_memscan_generic(task->pid, task->vm_area,
                                   task->src, task->size, task->align,
                                   task->progress, task->result,
                                   task->process_reader,
                                   &task->perf);
    free_vm_area(task->vm_area);
    task->vm_area = NULL;
    struct ms_result* res = task->result ? *task->result : NULL;
    if (res && res->perf) {
        merge_task_perf(res->perf, &task->perf);
    }
    return NULL;
}

static void* scan_thread_callback(void* arg) {
    struct scan_task_callback* task = (struct scan_task_callback*)arg;

    int step = task->align[0];

    /* Calculate maximum pattern length */
    size_t max_len = 0;
    for (int i = 0; i < task->count; i++) {
        if (task->size[i] > max_len)
            max_len = task->size[i];
    }
    if (max_len == 0) {
        task->ret = -1;
        free_vm_area(task->vm_area);
        task->vm_area = NULL;
        return NULL;
    }

    size_t buf_size = CHUNK_READ_SIZE + max_len - 1;
    uint8_t *buf = malloc(buf_size);
    if (!buf) {
        task->ret = -1;
        free_vm_area(task->vm_area);
        task->vm_area = NULL;
        return NULL;
    }

    size_t mask_words = (CHUNK_READ_SIZE / step + 63) / 64;
    uint64_t *mask = malloc(mask_words * sizeof(uint64_t));
    if (!mask) {
        free(buf);
        task->ret = -1;
        free_vm_area(task->vm_area);
        task->vm_area = NULL;
        return NULL;
    }

    for (struct vm_area *cur = task->vm_area; cur; cur = cur->next) {
        uintptr_t pos = cur->start;
        uintptr_t end = cur->end;

        while (pos < end) {
            /* Ensure pos is aligned to step before each read */
            if (pos % step != 0) {
                size_t skip = step - (pos % step);
                if (skip > (size_t)(end - pos)) {
                    skip = end - pos;
                }
                pos += skip;
                if (task->progress)
                    atomic_fetch_add(&task->progress->current_pos, skip);
                if (pos >= end)
                    break;
            }

            if (task->progress) {
                if (atomic_load(&task->progress->cancel)) {
                    task->ret = -2;
                    goto cleanup;
                }
                if (atomic_load(&task->progress->pause)) {
                    pthread_mutex_lock(&task->progress->mtx);
                    while (atomic_load(&task->progress->pause) &&
                           !atomic_load(&task->progress->cancel)) {
                        pthread_cond_wait(&task->progress->cond, &task->progress->mtx);
                    }
                    pthread_mutex_unlock(&task->progress->mtx);
                    if (atomic_load(&task->progress->cancel)) {
                        task->ret = -2;
                        goto cleanup;
                    }
                }
            }

            size_t to_read = buf_size;
            if (pos + to_read > end)
                to_read = end - pos;

            struct iovec local_iov = { .iov_base = buf, .iov_len = to_read };
            struct iovec remote_iov = { .iov_base = (void *)pos, .iov_len = to_read };
            ssize_t nread = task->process_reader(task->pid, &local_iov, 1, &remote_iov, 1, cur);

            if (nread > 0) {
                size_t valid_len = (size_t)nread;
                task->perf.bytes += valid_len;

                size_t match_len = 0;
                if (valid_len >= max_len) {
                    match_len = valid_len - (max_len - 1);
                }

                if (match_len > 0) {
                    memset(mask, 0, mask_words * sizeof(uint64_t));
                    if (task->compar(buf, match_len,
                                     task->src, task->size, task->align,
                                     task->count, mask, mask_words,
                                     task->userdata) != 0) {
                        task->ret = -1;
                        goto cleanup;
                    }

                    size_t positions = match_len / step;
                    for (size_t word = 0; word < mask_words && word * 64 < positions; word++) {
                        uint64_t bits = mask[word];
                        while (bits) {
                            int bit = __builtin_ctzll(bits);
                            size_t idx = word * 64 + bit;
                            if (idx >= positions) break;
                            uint64_t addr = pos + idx * step;
                            if (add_result(task->result, addr) != 0) {
                                task->ret = -1;
                                goto cleanup;
                            }
                            task->perf.found++;
                            if (task->progress) {
                                atomic_fetch_add(&task->progress->total_found, 1);
                            }
                            bits &= bits - 1;
                        }
                    }
                    task->perf.cb_count++;
                }

                size_t advance;
                if (valid_len < max_len) {
                    advance = valid_len;
                } else {
                    advance = match_len;
                }
                pos += advance;
                if (task->progress)
                    atomic_fetch_add(&task->progress->current_pos, advance);
            } else {
                size_t remaining = end - pos;
                size_t advance = (CHUNK_READ_SIZE < remaining) ? CHUNK_READ_SIZE : remaining;
                pos += advance;
                if (task->progress)
                    atomic_fetch_add(&task->progress->current_pos, advance);
            }
        }
    }

    task->ret = 0;

cleanup:
    free(buf);
    free(mask);
    free_vm_area(task->vm_area);
    task->vm_area = NULL;

    struct ms_result* res = task->result ? *task->result : NULL;
    if (res && res->perf) {
        merge_task_perf(res->perf, &task->perf);
    }
    return NULL;
}

static struct vm_area* slice_vm_list(struct vm_area **list, size_t target_len) {
    struct vm_area *head = NULL, *tail = NULL;
    size_t cur_len = 0;

    while (*list && cur_len < target_len) {
        uintptr_t seg_start = (*list)->start;
        uintptr_t seg_end   = (*list)->end;
        size_t avail = (size_t)(seg_end - seg_start);

        if (cur_len + avail <= target_len) {
            struct vm_area *node = *list;
            *list = node->next;
            node->next = NULL;
            if (!head) head = tail = node;
            else { tail->next = node; tail = node; }
            cur_len += avail;
        } else {
            size_t need = target_len - cur_len;
            uintptr_t cut_end = seg_start + need;
            struct vm_area *node = malloc(sizeof(struct vm_area));
            if (!node) {
                struct vm_area *tmp = head;
                while (tmp) {
                    struct vm_area *next = tmp->next;
                    free(tmp->pathname);
                    free(tmp);
                    tmp = next;
                }
                return NULL;
            }

            memcpy(node->perm, (*list)->perm, 4);
            node->offset = (*list)->offset;
            node->dev    = (*list)->dev;
            node->inode  = (*list)->inode;

            if ((*list)->pathname) {
                size_t plen = strlen((*list)->pathname) + 1;
                node->pathname = malloc(plen);
                if (!node->pathname) {
                    free(node);
                    struct vm_area *tmp = head;
                    while (tmp) {
                        struct vm_area *next = tmp->next;
                        free(tmp->pathname);
                        free(tmp);
                        tmp = next;
                    }
                    return NULL;
                }
                memcpy(node->pathname, (*list)->pathname, plen);
            } else {
                node->pathname = NULL;
            }

            node->start = seg_start;
            node->end   = cut_end;
            node->next  = NULL;
            if (!head) head = tail = node;
            else { tail->next = node; tail = node; }
            (*list)->start = cut_end;
            cur_len += need;
            break;
        }
    }
    return head;
}

static int memscan_generic_mt(pid_t pid, struct vm_area* vm_area,
                              const void* src, size_t size, int align,
                              struct ms_progress* progress,
                              struct ms_result** result,
                              process_reader_t process_reader,
                              int jobs)
{
    if (!vm_area || !src || !result || !process_reader) return -1;
    if (size == 0 || align == 0 || (align & (align - 1)) != 0) return -1;

    uintptr_t total_len = 0;
    for (struct vm_area *cur = vm_area; cur; cur = cur->next)
        total_len += (cur->end - cur->start);
    if (total_len == 0) return 0;

    int num_threads = jobs > 0 ? jobs : 1;
    int final_ret = 0;

    if (num_threads <= 1) {
        struct task_perf tperf = {0};
        final_ret = do_memscan_generic(pid, vm_area, src, size, align,
                                       progress, result, process_reader, &tperf);
        merge_task_perf((*result)->perf, &tperf);
    } else {
        size_t per = total_len / num_threads;
        size_t rem = total_len % num_threads;

        struct scan_task_generic *tasks = calloc(num_threads, sizeof(struct scan_task_generic));
        if (!tasks) return -1;

        struct vm_area *copy_list = vm_area_copy(vm_area);
        if (!copy_list) {
            free(tasks);
            return -1;
        }

        struct vm_area *remain = copy_list;
        for (int i = 0; i < num_threads; i++) {
            size_t target = per + (i < (int)rem ? 1 : 0);
            struct vm_area *sub = slice_vm_list(&remain, target);
            if (!sub && target > 0) {
                for (int j = 0; j < i; j++)
                    free_vm_area(tasks[j].vm_area);
                free_vm_area(remain);
                free(tasks);
                return -1;
            }
            tasks[i].vm_area = sub;
            tasks[i].pid = pid;
            tasks[i].src = src;
            tasks[i].size = size;
            tasks[i].align = align;
            tasks[i].progress = progress;
            tasks[i].result = result;
            tasks[i].process_reader = process_reader;
            tasks[i].ret = 0;
            memset(&tasks[i].perf, 0, sizeof(tasks[i].perf));
        }

        if (remain) {
            int last = num_threads - 1;
            while (last >= 0 && !tasks[last].vm_area) last--;
            if (last >= 0) {
                struct vm_area *tail = tasks[last].vm_area;
                if (!tail) {
                    tasks[last].vm_area = remain;
                } else {
                    while (tail->next) tail = tail->next;
                    tail->next = remain;
                }
            } else {
                free_vm_area(remain);
            }
        }

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        if (!threads) {
            for (int i = 0; i < num_threads; i++)
                free_vm_area(tasks[i].vm_area);
            free(tasks);
            return -1;
        }

        for (int i = 0; i < num_threads; i++) {
            if (pthread_create(&threads[i], NULL, scan_thread_generic, &tasks[i]) != 0) {
                if (progress) atomic_store(&progress->cancel, 1);
                if (progress) {
                    pthread_mutex_lock(&progress->mtx);
                    pthread_cond_broadcast(&progress->cond);
                    pthread_mutex_unlock(&progress->mtx);
                }
                for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
                free(threads);
                for (int j = i; j < num_threads; j++)
                    free_vm_area(tasks[j].vm_area);
                free(tasks);
                return -1;
            }
        }

        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
            if (tasks[i].ret == -2) final_ret = -2;
            else if (tasks[i].ret != 0 && final_ret == 0) final_ret = tasks[i].ret;
        }

        free(threads);
        free(tasks);
    }

    return final_ret;
}

static int memscanv_callback(pid_t pid, struct vm_area* vm_area,
                             const void** src, size_t* size, int* align, int count,
                             struct ms_progress* progress,
                             struct ms_result** result,
                             process_reader_t process_reader,
                             memscanv_compar_t compar,
                             void *userdata,
                             int jobs)
{
    if (!vm_area || !src || !size || !align || count <= 0 || !result || !process_reader || !compar)
        return -1;

    int step = align[0];
    for (int i = 1; i < count; i++) {
        if (align[i] != step) {
            return -1;
        }
    }
    if (step <= 0 || (step & (step - 1)) != 0) {
        return -1;
    }

    uintptr_t total_len = 0;
    for (struct vm_area *cur = vm_area; cur; cur = cur->next)
        total_len += (cur->end - cur->start);

    if (progress) {
        atomic_store(&progress->tot_len, total_len);
        atomic_store(&progress->current_pos, 0);
        atomic_store(&progress->total_found, 0);
    }
    if (total_len == 0) return 0;

    int num_threads = jobs > 0 ? jobs : 1;
    global_perf_start((*result)->perf, num_threads);

    int final_ret = 0;

    if (num_threads <= 1) {
        /* Single-threaded: also copy vm_area to avoid freeing caller's list */
        struct vm_area *copy = vm_area_copy(vm_area);
        if (!copy) {
            final_ret = -1;
            goto done;
        }

        struct scan_task_callback task;
        memset(&task, 0, sizeof(task));
        task.pid = pid;
        task.vm_area = copy;
        task.src = src;
        task.size = size;
        task.align = align;
        task.count = count;
        task.progress = progress;
        task.result = result;
        task.process_reader = process_reader;
        task.compar = compar;
        task.userdata = userdata;
        task.ret = 0;

        scan_thread_callback(&task);
        final_ret = task.ret;
    } else {
        size_t per = total_len / num_threads;
        size_t rem = total_len % num_threads;

        struct scan_task_callback *tasks = calloc(num_threads, sizeof(struct scan_task_callback));
        if (!tasks) {
            final_ret = -1;
            goto done;
        }

        struct vm_area *copy_list = vm_area_copy(vm_area);
        if (!copy_list) {
            free(tasks);
            final_ret = -1;
            goto done;
        }

        struct vm_area *remain = copy_list;
        for (int i = 0; i < num_threads; i++) {
            size_t target = per + (i < (int)rem ? 1 : 0);
            struct vm_area *sub = slice_vm_list(&remain, target);
            if (!sub && target > 0) {
                for (int j = 0; j < i; j++)
                    free_vm_area(tasks[j].vm_area);
                free_vm_area(remain);
                free(tasks);
                final_ret = -1;
                goto done;
            }
            tasks[i].vm_area = sub;
            tasks[i].pid = pid;
            tasks[i].src = src;
            tasks[i].size = size;
            tasks[i].align = align;
            tasks[i].count = count;
            tasks[i].progress = progress;
            tasks[i].result = result;
            tasks[i].process_reader = process_reader;
            tasks[i].compar = compar;
            tasks[i].userdata = userdata;
            tasks[i].ret = 0;
            memset(&tasks[i].perf, 0, sizeof(tasks[i].perf));
        }

        if (remain) {
            int last = num_threads - 1;
            while (last >= 0 && !tasks[last].vm_area) last--;
            if (last >= 0) {
                struct vm_area *tail = tasks[last].vm_area;
                if (!tail) {
                    tasks[last].vm_area = remain;
                } else {
                    while (tail->next) tail = tail->next;
                    tail->next = remain;
                }
            } else {
                free_vm_area(remain);
            }
        }

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        if (!threads) {
            for (int i = 0; i < num_threads; i++)
                free_vm_area(tasks[i].vm_area);
            free(tasks);
            final_ret = -1;
            goto done;
        }

        for (int i = 0; i < num_threads; i++) {
            if (pthread_create(&threads[i], NULL, scan_thread_callback, &tasks[i]) != 0) {
                if (progress) atomic_store(&progress->cancel, 1);
                if (progress) {
                    pthread_mutex_lock(&progress->mtx);
                    pthread_cond_broadcast(&progress->cond);
                    pthread_mutex_unlock(&progress->mtx);
                }
                for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
                free(threads);
                for (int j = i; j < num_threads; j++)
                    free_vm_area(tasks[j].vm_area);
                free(tasks);
                final_ret = -1;
                goto done;
            }
        }

        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
            if (tasks[i].ret == -2) final_ret = -2;
            else if (tasks[i].ret != 0 && final_ret == 0) final_ret = tasks[i].ret;
        }

        free(threads);
        free(tasks);
    }

done:
    global_perf_stop((*result)->perf);
    global_perf_report((*result)->perf);
    return final_ret;
}

int memscanv(pid_t pid, struct vm_area* vm_area,
             const void** src, size_t* size, int* align, int count,
             struct ms_progress* progress,
             struct ms_result** result,
             process_reader_t process_reader,
             memscanv_compar_t compar,
             void *userdata,
             int jobs)
{
    if (!src || !size || !align || count <= 0 || !result || !process_reader)
        return -1;

    if (*result == NULL) {
        *result = calloc(1, sizeof(struct ms_result));
        if (!*result) return -1;
        pthread_mutex_init(&(*result)->lock, NULL);
    }
    if ((*result)->perf == NULL) {
        (*result)->perf = calloc(1, sizeof(struct ms_perf));
        if (!(*result)->perf) return -1;
    }

    if (compar != NULL) {
        return memscanv_callback(pid, vm_area, src, size, align, count,
                                 progress, result, process_reader, compar,
                                 userdata, jobs);
    }

    /* Original logic without callback */
    uintptr_t total_len = 0;
    for (struct vm_area *cur = vm_area; cur; cur = cur->next)
        total_len += (cur->end - cur->start);

    if (progress) {
        atomic_store(&progress->tot_len, total_len);
        atomic_store(&progress->current_pos, 0);
        atomic_store(&progress->total_found, 0);
    }
    if (total_len == 0) return 0;

    int num_threads = jobs > 0 ? jobs : 1;
    global_perf_start((*result)->perf, num_threads);

    int final_ret = 0;

    int fast_path = 1;
    int common_align = align[0];
    size_t first_size = size[0];
    for (int i = 0; i < count; i++) {
        if ((size[i] != 4 && size[i] != 8) ||
            size[i] != first_size ||
            align[i] != common_align ||
            align[i] == 0 || (align[i] & (align[i] - 1)) != 0) {
            fast_path = 0;
            break;
        }
    }

    if (progress && !fast_path) {
        atomic_store(&progress->tot_len, (uint64_t)total_len * (uint64_t)count);
    }

    if (fast_path) {
        size_t total_vals = count;
        uint64_t *values = malloc(total_vals * sizeof(uint64_t));
        if (!values) {
            final_ret = -1;
            goto done;
        }

        for (int i = 0; i < count; i++) {
            uint64_t val = 0;
            memcpy(&val, src[i], first_size);
            values[i] = val;
        }

        qsort(values, total_vals, sizeof(uint64_t), compare_uint64);
        size_t unique_count = 0;
        for (size_t i = 0; i < total_vals; i++) {
            if (i == 0 || values[i] != values[i - 1]) {
                values[unique_count++] = values[i];
            }
        }

        if (num_threads <= 1) {
            struct task_perf tperf = {0};
            final_ret = do_memscanv_multi(pid, vm_area,
                                          values, unique_count, first_size, common_align,
                                          progress, result, process_reader, &tperf);
            merge_task_perf((*result)->perf, &tperf);
        } else {
            size_t per = total_len / num_threads;
            size_t rem = total_len % num_threads;

            struct scan_task_multi *tasks = calloc(num_threads, sizeof(struct scan_task_multi));
            if (!tasks) {
                free(values);
                final_ret = -1;
                goto done;
            }

            struct vm_area *copy_list = vm_area_copy(vm_area);
            if (!copy_list) {
                free(tasks);
                free(values);
                final_ret = -1;
                goto done;
            }

            struct vm_area *remain = copy_list;
            for (int i = 0; i < num_threads; i++) {
                size_t target = per + (i < (int)rem ? 1 : 0);
                struct vm_area *sub = slice_vm_list(&remain, target);
                if (!sub && target > 0) {
                    for (int j = 0; j < i; j++)
                        free_vm_area(tasks[j].vm_area);
                    free_vm_area(remain);
                    free(tasks);
                    free(values);
                    final_ret = -1;
                    goto done;
                }
                tasks[i].vm_area = sub;
                tasks[i].pid = pid;
                tasks[i].values = values;
                tasks[i].value_count = unique_count;
                tasks[i].value_size = first_size;
                tasks[i].align = common_align;
                tasks[i].progress = progress;
                tasks[i].result = result;
                tasks[i].process_reader = process_reader;
                tasks[i].ret = 0;
                memset(&tasks[i].perf, 0, sizeof(tasks[i].perf));
            }

            if (remain) {
                int last = num_threads - 1;
                while (last >= 0 && !tasks[last].vm_area) last--;
                if (last >= 0) {
                    struct vm_area *tail = tasks[last].vm_area;
                    if (!tail) {
                        tasks[last].vm_area = remain;
                    } else {
                        while (tail->next) tail = tail->next;
                        tail->next = remain;
                    }
                } else {
                    free_vm_area(remain);
                }
            }

            pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
            if (!threads) {
                for (int i = 0; i < num_threads; i++)
                    free_vm_area(tasks[i].vm_area);
                free(tasks);
                free(values);
                final_ret = -1;
                goto done;
            }

            for (int i = 0; i < num_threads; i++) {
                if (pthread_create(&threads[i], NULL, scan_thread_multi, &tasks[i]) != 0) {
                    if (progress) atomic_store(&progress->cancel, 1);
                    if (progress) {
                        pthread_mutex_lock(&progress->mtx);
                        pthread_cond_broadcast(&progress->cond);
                        pthread_mutex_unlock(&progress->mtx);
                    }
                    for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
                    free(threads);
                    for (int j = i; j < num_threads; j++)
                        free_vm_area(tasks[j].vm_area);
                    free(tasks);
                    free(values);
                    final_ret = -1;
                    goto done;
                }
            }

            for (int i = 0; i < num_threads; i++) {
                pthread_join(threads[i], NULL);
                if (tasks[i].ret == -2) final_ret = -2;
                else if (tasks[i].ret != 0 && final_ret == 0) final_ret = tasks[i].ret;
            }

            free(threads);
            free(tasks);
        }

        free(values);
    } else {
        for (int i = 0; i < count; i++) {
            int ret = memscan_generic_mt(pid, vm_area,
                                         src[i], size[i], align[i],
                                         progress, result, process_reader, jobs);
            if (ret == -2) {
                final_ret = -2;
                break;
            } else if (ret != 0 && final_ret == 0) {
                final_ret = ret;
            }
        }
    }

done:
    global_perf_stop((*result)->perf);
    global_perf_report((*result)->perf);
    return final_ret;
}

int memscan(pid_t pid, struct vm_area* vm_area,
            const void* src, size_t size, int align,
            struct ms_progress* progress,
            struct ms_result** result,
            process_reader_t process_reader,
            int jobs)
{
    const void* src_arr[1] = { src };
    size_t size_arr[1] = { size };
    int align_arr[1] = { align };
    return memscanv(pid, vm_area, src_arr, size_arr, align_arr, 1,
                    progress, result, process_reader, NULL, NULL, jobs);
}