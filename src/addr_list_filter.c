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

#include "addr_list_filter.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <math.h>

struct filter_task {
    pid_t pid;
    const uint64_t *addrs;
    size_t start, end;
    const void *src;
    size_t size;
    int filter_type;
    struct ms_progress *progress;
    struct ms_result **result;
    process_reader_t reader;
    int ret;
    size_t found;
};

struct local_snapshot {
    uint64_t *addrs;
    uint8_t  *values;
    size_t    count;
    size_t    capacity;
    size_t    value_size;
};

struct snap_filter_task {
    pid_t pid;
    const struct addr_list_snapshot *snap;
    size_t start, end;
    int filter_type;
    uint64_t delta;
    struct ms_progress *progress;
    struct ms_result **result;
    process_reader_t reader;
    struct local_snapshot ls;
    int ret;
};

static int is_sorted_uint64(const uint64_t *arr, size_t n) {
    if (n < 2) return 1;
    for (size_t i = 1; i < n; ++i)
        if (arr[i] < arr[i - 1]) return 0;
    return 1;
}

static int cmp_uint64(const void *a, const void *b) {
    uint64_t ua = *(const uint64_t *)a;
    uint64_t ub = *(const uint64_t *)b;
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static void sort_and_dedup_addrlist(struct addr_list *list) {
    if (!list || !list->addrs || list->count <= 1) return;
    qsort(list->addrs, list->count, sizeof(uint64_t), cmp_uint64);
    size_t j = 1;
    for (size_t i = 1; i < list->count; ++i)
        if (list->addrs[i] != list->addrs[j - 1])
            list->addrs[j++] = list->addrs[i];
    list->count = j;
}

static uint64_t bytes2u64(const uint8_t *data, size_t size) {
    uint64_t val = 0;
    for (size_t i = 0; i < size && i < 8; ++i)
        val |= (uint64_t)data[i] << (i * 8);
    return val;
}

static int ucompare(const uint8_t *a, const uint8_t *b, size_t size) {
    uint64_t ua = bytes2u64(a, size);
    uint64_t ub = bytes2u64(b, size);
    if (ua < ub) return -1;
    if (ua > ub) return 1;
    return 0;
}

static double bytes_to_double(const uint8_t *data, size_t size, int is_float) {
    if (is_float) {
        if (size == 4) {
            float f;
            memcpy(&f, data, sizeof(f));
            return (double)f;
        } else {
            double d;
            memcpy(&d, data, sizeof(d));
            return d;
        }
    } else {
        return (double)bytes2u64(data, size);
    }
}

static double get_epsilon(int precision) {
    static const double table[] = {
        500000000.0,
        50000000.0,
        5000000.0,
        500000.0,
        50000.0,
        5000.0,
        500.0,
        50.0,
        5.0,
        0.5,
        0.05,
        0.005,
        0.0005,
        0.00005,
        0.000005,
        0.0000005,
        0.00000005,
        0.000000005,
        0.0000000005
    };
    return table[precision + 9];
}

static int get_precision_from_eq_op(int op) {
    if (op >= ADDR_LIST_FILTER_IEQ_M9 && op <= ADDR_LIST_FILTER_IEQ_9)
        return (op - ADDR_LIST_FILTER_IEQ_M9) - 9;
    if (op >= ADDR_LIST_FILTER_INE_M9 && op <= ADDR_LIST_FILTER_INE_9)
        return (op - ADDR_LIST_FILTER_INE_M9) - 9;
    if (op >= ADDR_LIST_FILTER_FEQ_M9 && op <= ADDR_LIST_FILTER_FEQ_9)
        return (op - ADDR_LIST_FILTER_FEQ_M9) - 9;
    if (op >= ADDR_LIST_FILTER_FNE_M9 && op <= ADDR_LIST_FILTER_FNE_9)
        return (op - ADDR_LIST_FILTER_FNE_M9) - 9;
    return 0;
}

static int get_precision_from_snap_op(int op) {
    if (op >= ADDR_LIST_SNAPSHOT_FILTER_ICHG_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_ICHG_9)
        return (op - ADDR_LIST_SNAPSHOT_FILTER_ICHG_M9) - 9;
    if (op >= ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_IUNCH_9)
        return (op - ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M9) - 9;
    if (op >= ADDR_LIST_SNAPSHOT_FILTER_FCHG_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_FCHG_9)
        return (op - ADDR_LIST_SNAPSHOT_FILTER_FCHG_M9) - 9;
    if (op >= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_9)
        return (op - ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M9) - 9;
    return 0;
}

static int float_cmp(double a, double b, int op) {
    if (isnan(a) || isnan(b)) {
        switch (op) {
            case ADDR_LIST_FILTER_FEQ: return 0;
            case ADDR_LIST_FILTER_FNE: return 1;
            default: return 0;
        }
    }
    switch (op) {
        case ADDR_LIST_FILTER_FEQ: return a == b;
        case ADDR_LIST_FILTER_FNE: return a != b;
        case ADDR_LIST_FILTER_FLT: return a < b;
        case ADDR_LIST_FILTER_FLE: return a <= b;
        case ADDR_LIST_FILTER_FGT: return a > b;
        case ADDR_LIST_FILTER_FGE: return a >= b;
        default: return 0;
    }
}

static int match_value(const uint8_t *cur, const uint8_t *ref, size_t size, int op) {
    if (op >= ADDR_LIST_FILTER_EQ && op <= ADDR_LIST_FILTER_GE) {
        int cmp = ucompare(cur, ref, size);
        switch (op) {
            case ADDR_LIST_FILTER_EQ: return cmp == 0;
            case ADDR_LIST_FILTER_NE: return cmp != 0;
            case ADDR_LIST_FILTER_LT: return cmp < 0;
            case ADDR_LIST_FILTER_LE: return cmp <= 0;
            case ADDR_LIST_FILTER_GT: return cmp > 0;
            case ADDR_LIST_FILTER_GE: return cmp >= 0;
            default: return 0;
        }
    }

    if (op >= ADDR_LIST_FILTER_FEQ && op <= ADDR_LIST_FILTER_FGE) {
        double a = bytes_to_double(cur, size, 1);
        double b = bytes_to_double(ref, size, 1);
        return float_cmp(a, b, op);
    }

    if ((op >= ADDR_LIST_FILTER_IEQ_M9 && op <= ADDR_LIST_FILTER_IEQ_9) ||
        (op >= ADDR_LIST_FILTER_INE_M9 && op <= ADDR_LIST_FILTER_INE_9)) {
        uint64_t ua = bytes2u64(cur, size);
        uint64_t ub = bytes2u64(ref, size);
        uint64_t diff = (ua > ub) ? (ua - ub) : (ub - ua);
        int precision = get_precision_from_eq_op(op);
        uint64_t eps = 0;
        if (precision < 0) {
            eps = (uint64_t)get_epsilon(precision);
        }
        int is_eq = (op >= ADDR_LIST_FILTER_IEQ_M9 && op <= ADDR_LIST_FILTER_IEQ_9);
        return is_eq ? (diff <= eps) : (diff > eps);
    }

    if ((op >= ADDR_LIST_FILTER_FEQ_M9 && op <= ADDR_LIST_FILTER_FEQ_9) ||
        (op >= ADDR_LIST_FILTER_FNE_M9 && op <= ADDR_LIST_FILTER_FNE_9)) {
        double a = bytes_to_double(cur, size, 1);
        double b = bytes_to_double(ref, size, 1);
        if (isnan(a) || isnan(b)) {
            int is_ne = (op >= ADDR_LIST_FILTER_FNE_M9 && op <= ADDR_LIST_FILTER_FNE_9);
            return is_ne ? 1 : 0;
        }
        double diff = fabs(a - b);
        int precision = get_precision_from_eq_op(op);
        double eps = get_epsilon(precision);
        int is_eq = (op >= ADDR_LIST_FILTER_FEQ_M9 && op <= ADDR_LIST_FILTER_FEQ_9);
        return is_eq ? (diff <= eps) : (diff > eps);
    }

    return 0;
}

static int match_value_snap(const uint8_t *cur, const uint8_t *old,
                            size_t size, int op, int64_t delta) {
    (void)delta;

    if (op == ADDR_LIST_SNAPSHOT_FILTER_CHG)
        return memcmp(cur, old, size) != 0;
    if (op == ADDR_LIST_SNAPSHOT_FILTER_UNCH)
        return memcmp(cur, old, size) == 0;

    if (op == ADDR_LIST_SNAPSHOT_FILTER_FCHG ||
        op == ADDR_LIST_SNAPSHOT_FILTER_FUNCH) {
        double a = bytes_to_double(cur, size, 1);
        double b = bytes_to_double(old, size, 1);
        if (isnan(a) || isnan(b))
            return (op == ADDR_LIST_SNAPSHOT_FILTER_FUNCH) ? 1 : 0;
        int changed = (a != b);
        return (op == ADDR_LIST_SNAPSHOT_FILTER_FCHG) ? changed : !changed;
    }

    if ((op >= ADDR_LIST_SNAPSHOT_FILTER_ICHG_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_ICHG_9) ||
        (op >= ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_IUNCH_9)) {
        double a = bytes_to_double(cur, size, 0);
        double b = bytes_to_double(old, size, 0);
        double diff = fabs(a - b);
        int precision = get_precision_from_snap_op(op);
        double eps = get_epsilon(precision);
        int changed = (diff > eps);
        int is_chg = (op >= ADDR_LIST_SNAPSHOT_FILTER_ICHG_M9 &&
                      op <= ADDR_LIST_SNAPSHOT_FILTER_ICHG_9);
        return is_chg ? changed : !changed;
    }

    if ((op >= ADDR_LIST_SNAPSHOT_FILTER_FCHG_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_FCHG_9) ||
        (op >= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M9 && op <= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_9)) {
        double a = bytes_to_double(cur, size, 1);
        double b = bytes_to_double(old, size, 1);
        if (isnan(a) || isnan(b)) {
            int is_unch = (op >= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M9 &&
                           op <= ADDR_LIST_SNAPSHOT_FILTER_FUNCH_9);
            return is_unch ? 1 : 0;
        }
        double diff = fabs(a - b);
        int precision = get_precision_from_snap_op(op);
        double eps = get_epsilon(precision);
        int changed = (diff > eps);
        int is_chg = (op >= ADDR_LIST_SNAPSHOT_FILTER_FCHG_M9 &&
                      op <= ADDR_LIST_SNAPSHOT_FILTER_FCHG_9);
        return is_chg ? changed : !changed;
    }

    if (op == ADDR_LIST_SNAPSHOT_FILTER_INC) {
        return ucompare(cur, old, size) > 0;
    }
    if (op == ADDR_LIST_SNAPSHOT_FILTER_DEC) {
        return ucompare(cur, old, size) < 0;
    }
    if (op == ADDR_LIST_SNAPSHOT_FILTER_INC_BY) {
        uint64_t diff = bytes2u64(cur, size) - bytes2u64(old, size);
        return (int64_t)diff == delta;
    }
    if (op == ADDR_LIST_SNAPSHOT_FILTER_DEC_BY) {
        uint64_t diff = bytes2u64(old, size) - bytes2u64(cur, size);
        return (int64_t)diff == delta;
    }

    return 0;
}

static int add_addr_to_result(struct ms_result **result, uint64_t addr) {
    if (!result) return -1;
    if (*result == NULL) {
        *result = calloc(1, sizeof(struct ms_result));
        if (!*result) return -1;
        pthread_mutex_init(&(*result)->lock, NULL);
    }
    struct ms_result *res = *result;
    pthread_mutex_lock(&res->lock);

    struct vm_list *tail = res->tail;
    if (!tail) {
        tail = calloc(1, sizeof(struct vm_list));
        if (!tail) { pthread_mutex_unlock(&res->lock); return -1; }
        res->head = res->tail = tail;
    }
    if (tail->used < VM_LIST_CAPACITY) {
        tail->addr[tail->used++] = addr;
        pthread_mutex_unlock(&res->lock);
        return 0;
    }
    struct vm_list *newb = calloc(1, sizeof(struct vm_list));
    if (!newb) { pthread_mutex_unlock(&res->lock); return -1; }
    tail->next = newb;
    res->tail = newb;
    newb->addr[0] = addr;
    newb->used = 1;
    pthread_mutex_unlock(&res->lock);
    return 0;
}

static int do_addr_list_filter(pid_t pid,
                               const uint64_t *addrs, size_t start, size_t end,
                               const void *src, size_t size, int filter_type,
                               struct ms_progress *progress,
                               struct ms_result **result,
                               process_reader_t reader,
                               size_t *found_count) {
    if (!addrs || start >= end || !result || !reader) return -1;
    if (filter_type < ADDR_LIST_FILTER_EQ || filter_type > ADDR_LIST_FILTER_GE) return -1;
    if (filter_type != ADDR_LIST_FILTER_NE && !src) return -1;

    size_t page_size = sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;

    size_t i = start;
    *found_count = 0;

    while (i < end) {
        if (progress && atomic_load(&progress->cancel))
            return -2;

        uint64_t block_start = addrs[i];
        uint64_t block_end   = block_start + size;
        size_t j = i + 1;
        while (j < end && addrs[j] <= block_end + page_size) {
            uint64_t cand_end = addrs[j] + size;
            if (cand_end > block_end) block_end = cand_end;
            j++;
        }
        size_t block_len = block_end - block_start;
        uint8_t *buf = malloc(block_len);
        if (!buf) return -1;

        struct iovec local = { .iov_base = buf, .iov_len = block_len };
        struct iovec remote = { .iov_base = (void*)block_start, .iov_len = block_len };
        ssize_t nread = reader(pid, &local, 1, &remote, 1, NULL);

        if (nread > 0) {
            for (size_t k = i; k < j; k++) {
                uint64_t addr = addrs[k];
                if (addr + size > block_start + (size_t)nread) continue;
                size_t offset = addr - block_start;
                const uint8_t *cur_val = buf + offset;
                if (match_value(cur_val, (const uint8_t*)src, size, filter_type)) {
                    if (add_addr_to_result(result, addr) != 0) {
                        free(buf);
                        return -1;
                    }
                    (*found_count)++;
                }
            }
        }
        free(buf);

        if (progress)
            atomic_fetch_add(&progress->current_pos, j - i);
        i = j;
    }
    return 0;
}

static void* filter_thread(void *arg) {
    struct filter_task *task = (struct filter_task*)arg;
    task->ret = do_addr_list_filter(task->pid,
                                    task->addrs, task->start, task->end,
                                    task->src, task->size, task->filter_type,
                                    task->progress, task->result,
                                    task->reader, &task->found);
    return NULL;
}

static int local_snapshot_append(struct local_snapshot *ls,
                                 uint64_t addr, const uint8_t *val) {
    if (ls->count == ls->capacity) {
        size_t newcap = ls->capacity ? ls->capacity * 2 : 256;
        uint64_t *tmp_addrs = realloc(ls->addrs, newcap * sizeof(uint64_t));
        uint8_t  *tmp_vals  = realloc(ls->values, newcap * ls->value_size);
        if (!tmp_addrs || !tmp_vals) {
            free(tmp_addrs); free(tmp_vals);
            return -1;
        }
        ls->addrs = tmp_addrs;
        ls->values = tmp_vals;
        ls->capacity = newcap;
    }
    ls->addrs[ls->count] = addr;
    memcpy(ls->values + ls->count * ls->value_size, val, ls->value_size);
    ls->count++;
    return 0;
}

static int do_addr_list_snapshot_filter(pid_t pid,
    const struct addr_list_snapshot *snap,
    size_t start, size_t end,
    int filter_type, uint64_t delta,
    struct ms_progress *progress,
    struct ms_result **result,
    process_reader_t reader,
    struct local_snapshot *ls_out) {

    if (start >= end || !snap || !reader) return -1;
    size_t value_size = snap->value_size;
    size_t page_size = sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;

    size_t i = start;
    while (i < end) {
        if (progress && atomic_load(&progress->cancel))
            return -2;

        uint64_t block_start = snap->addrs[i];
        uint64_t block_end   = block_start + value_size;
        size_t j = i + 1;
        while (j < end && snap->addrs[j] <= block_end + page_size) {
            uint64_t cand_end = snap->addrs[j] + value_size;
            if (cand_end > block_end) block_end = cand_end;
            j++;
        }
        size_t block_len = block_end - block_start;
        uint8_t *buf = malloc(block_len);
        if (!buf) return -1;

        struct iovec local = { .iov_base = buf, .iov_len = block_len };
        struct iovec remote = { .iov_base = (void*)block_start, .iov_len = block_len };
        ssize_t nread = reader(pid, &local, 1, &remote, 1, NULL);

        if (nread > 0) {
            for (size_t k = i; k < j; k++) {
                uint64_t addr = snap->addrs[k];
                if (addr + value_size > block_start + (size_t)nread) continue;
                size_t offset = addr - block_start;
                const uint8_t *cur_val = buf + offset;
                const uint8_t *old_val = snap->values + k * value_size;
                if (match_value_snap(cur_val, old_val, value_size, filter_type, (int64_t)delta)) {
                    if (local_snapshot_append(ls_out, addr, cur_val) != 0) {
                        free(buf); return -1;
                    }
                    if (result)
                        add_addr_to_result(result, addr);
                }
            }
        }
        free(buf);

        if (progress)
            atomic_fetch_add(&progress->current_pos, j - i);
        i = j;
    }
    return 0;
}

static void* snap_filter_thread(void *arg) {
    struct snap_filter_task *task = (struct snap_filter_task*)arg;
    memset(&task->ls, 0, sizeof(task->ls));
    task->ls.value_size = task->snap->value_size;
    task->ret = do_addr_list_snapshot_filter(task->pid,
                 task->snap, task->start, task->end,
                 task->filter_type, task->delta,
                 task->progress, task->result, task->reader,
                 &task->ls);
    return NULL;
}

static int merge_local_snapshots(struct local_snapshot *locals, int n,
                                 struct addr_list_snapshot *snap) {
    size_t total = 0;
    for (int i = 0; i < n; i++) total += locals[i].count;
    if (total == 0) {
        free(snap->addrs); free(snap->values);
        snap->addrs = NULL; snap->values = NULL; snap->count = 0;
        for (int i = 0; i < n; i++) {
            free(locals[i].addrs);
            free(locals[i].values);
            locals[i].addrs = NULL;
            locals[i].values = NULL;
        }
        return 0;
    }

    uint64_t *all_addrs = malloc(total * sizeof(uint64_t));
    uint8_t  *all_vals  = malloc(total * snap->value_size);
    if (!all_addrs || !all_vals) {
        free(all_addrs); free(all_vals);
        return -1;
    }

    size_t pos = 0;
    for (int i = 0; i < n; i++) {
        size_t cnt = locals[i].count;
        memcpy(all_addrs + pos, locals[i].addrs, cnt * sizeof(uint64_t));
        memcpy(all_vals + pos * snap->value_size, locals[i].values,
               cnt * snap->value_size);
        pos += cnt;

        free(locals[i].addrs);
        free(locals[i].values);
        locals[i].addrs = NULL;
        locals[i].values = NULL;
        locals[i].count = 0;
    }

    free(snap->addrs);
    free(snap->values);
    snap->addrs = all_addrs;
    snap->values = all_vals;
    snap->count = total;
    return 0;
}

struct addr_list* vmlist2_addrlist(struct vm_list* vmlist) {
    if (!vmlist) return NULL;
    size_t count = 0;
    for (struct vm_list *cur = vmlist; cur; cur = cur->next)
        count += cur->used;

    struct addr_list *al = malloc(sizeof(struct addr_list));
    if (!al) return NULL;
    al->addrs = malloc(count * sizeof(uint64_t));
    if (!al->addrs) { free(al); return NULL; }
    al->count = count;

    size_t idx = 0;
    for (struct vm_list *cur = vmlist; cur; cur = cur->next) {
        size_t n = cur->used;
        memcpy(al->addrs + idx, cur->addr, n * sizeof(uint64_t));
        idx += n;
    }
    sort_and_dedup_addrlist(al);
    return al;
}

struct addr_list_snapshot* addrlist_snapshot(pid_t pid,
                                         struct addr_list* addrlist,
                                         size_t value_size,
                                         process_reader_t reader) {
    if (!addrlist || !addrlist->addrs || addrlist->count == 0 || !reader)
        return NULL;

    struct addr_list sorted;
    sorted.count = addrlist->count;
    sorted.addrs = malloc(sorted.count * sizeof(uint64_t));
    if (!sorted.addrs) return NULL;
    memcpy(sorted.addrs, addrlist->addrs, sorted.count * sizeof(uint64_t));
    sort_and_dedup_addrlist(&sorted);

    struct addr_list_snapshot *snap = calloc(1, sizeof(*snap));
    if (!snap) { free(sorted.addrs); return NULL; }
    snap->addrs = sorted.addrs;
    snap->count = sorted.count;
    snap->value_size = value_size;
    snap->values = malloc(snap->count * value_size);
    if (!snap->values) {
        free(snap->addrs); free(snap);
        return NULL;
    }

    size_t page_size = sysconf(_SC_PAGESIZE);
    if (page_size == 0) page_size = 4096;

    size_t i = 0;
    while (i < snap->count) {
        uint64_t block_start = snap->addrs[i];
        uint64_t block_end   = block_start + value_size;
        size_t j = i + 1;
        while (j < snap->count &&
               snap->addrs[j] <= block_end + page_size) {
            uint64_t cand_end = snap->addrs[j] + value_size;
            if (cand_end > block_end) block_end = cand_end;
            j++;
        }
        size_t block_len = block_end - block_start;
        uint8_t *buf = malloc(block_len);
        if (!buf) {
            free(snap->addrs); free(snap->values); free(snap);
            return NULL;
        }
        struct iovec local = { .iov_base = buf, .iov_len = block_len };
        struct iovec remote = { .iov_base = (void*)block_start, .iov_len = block_len };
        ssize_t nread = reader(pid, &local, 1, &remote, 1, NULL);
        if (nread > 0) {
            for (size_t k = i; k < j; k++) {
                uint64_t addr = snap->addrs[k];
                if (addr + value_size > block_start + (size_t)nread) continue;
                size_t offset = addr - block_start;
                memcpy(snap->values + k * value_size, buf + offset, value_size);
            }
        } else {
            for (size_t k = i; k < j; k++)
                memset(snap->values + k * value_size, 0, value_size);
        }
        free(buf);
        i = j;
    }
    return (struct addr_list_snapshot*)snap;
}

int addrlist_filter(pid_t pid,
                     const struct addr_list* addrlist,
                     int filter_type,
                     const void* src,
                     size_t size,
                     struct ms_progress* progress,
                     struct ms_result** result,
                     process_reader_t process_reader,
                     int jobs) {
    if (!addrlist || !addrlist->addrs || addrlist->count == 0 || !result || !process_reader)
        return -1;
    if (filter_type < ADDR_LIST_FILTER_EQ || filter_type > ADDR_LIST_FILTER_GE)
        return -1;
    if (filter_type != ADDR_LIST_FILTER_NE && !src)
        return -1;

    struct addr_list sorted;
    sorted.count = addrlist->count;
    sorted.addrs = malloc(sorted.count * sizeof(uint64_t));
    if (!sorted.addrs) return -1;
    memcpy(sorted.addrs, addrlist->addrs, sorted.count * sizeof(uint64_t));
    if (!is_sorted_uint64(sorted.addrs, sorted.count))
        sort_and_dedup_addrlist(&sorted);

    if (!*result) {
        *result = calloc(1, sizeof(struct ms_result));
        if (!*result) { free(sorted.addrs); return -1; }
        pthread_mutex_init(&(*result)->lock, NULL);
    }

    if (progress) {
        atomic_store(&progress->tot_len, sorted.count);
        atomic_store(&progress->current_pos, 0);
    }

    int num_threads = jobs > 0 ? jobs : 1;
    int final_ret = 0;

    if (num_threads <= 1) {
        size_t found = 0;
        final_ret = do_addr_list_filter(pid, sorted.addrs, 0, sorted.count,
                                        src, size, filter_type,
                                        progress, result, process_reader, &found);
    } else {
        struct filter_task *tasks = calloc(num_threads, sizeof(struct filter_task));
        if (!tasks) { free(sorted.addrs); return -1; }

        size_t chunk = sorted.count / num_threads;
        size_t rem = sorted.count % num_threads;
        size_t start = 0;
        for (int i = 0; i < num_threads; i++) {
            size_t cnt = chunk + (i < (int)rem ? 1 : 0);
            tasks[i].pid = pid;
            tasks[i].addrs = sorted.addrs;
            tasks[i].start = start;
            tasks[i].end = start + cnt;
            tasks[i].src = src;
            tasks[i].size = size;
            tasks[i].filter_type = filter_type;
            tasks[i].progress = progress;
            tasks[i].result = result;
            tasks[i].reader = process_reader;
            start += cnt;
        }

        pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
        if (!threads) { free(tasks); free(sorted.addrs); return -1; }

        for (int i = 0; i < num_threads; i++) {
            if (pthread_create(&threads[i], NULL, filter_thread, &tasks[i]) != 0) {
                if (progress) atomic_store(&progress->cancel, 1);
                for (int j = 0; j < i; j++) pthread_join(threads[j], NULL);
                free(threads); free(tasks); free(sorted.addrs);
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

    free(sorted.addrs);
    return final_ret;
}

int addrlist_snapshot_filter(pid_t pid,
                              const struct addr_list* addrlist,
                              int filter_type,
                              struct addr_list_snapshot* snapshot,
                              uint64_t delta,
                              struct ms_progress* progress,
                              struct ms_result** result,
                              process_reader_t process_reader,
                              int jobs) {
    (void)addrlist;
    if (!snapshot || !snapshot->addrs || snapshot->count == 0 || !result || !process_reader)
        return -1;
    if (filter_type < ADDR_LIST_SNAPSHOT_FILTER_CHG || filter_type > ADDR_LIST_SNAPSHOT_FILTER_FUNCH_9)
        return -1;

    if (result && !*result) {
        *result = calloc(1, sizeof(struct ms_result));
        if (!*result) return -1;
        pthread_mutex_init(&(*result)->lock, NULL);
    }

    if (progress) {
        atomic_store(&progress->tot_len, snapshot->count);
        atomic_store(&progress->current_pos, 0);
    }

    int num_threads = jobs > 0 ? jobs : 1;
    int final_ret = 0;

    if (num_threads <= 1) {
        struct local_snapshot ls = {0};
        ls.value_size = snapshot->value_size;
        final_ret = do_addr_list_snapshot_filter(pid, snapshot, 0, snapshot->count,
                                                 filter_type, delta,
                                                 progress, result, process_reader, &ls);
        if (final_ret == 0) {
            free(snapshot->addrs); free(snapshot->values);
            snapshot->addrs = ls.addrs;
            snapshot->values = ls.values;
            snapshot->count = ls.count;
        } else {
            free(ls.addrs); free(ls.values);
        }
        return final_ret;
    }

    struct snap_filter_task *tasks = calloc(num_threads, sizeof(*tasks));
    if (!tasks) return -1;

    size_t chunk = snapshot->count / num_threads;
    size_t rem = snapshot->count % num_threads;
    size_t start = 0;
    for (int i = 0; i < num_threads; i++) {
        size_t cnt = chunk + (i < (int)rem ? 1 : 0);
        tasks[i].pid = pid;
        tasks[i].snap = snapshot;
        tasks[i].start = start;
        tasks[i].end = start + cnt;
        tasks[i].filter_type = filter_type;
        tasks[i].delta = delta;
        tasks[i].progress = progress;
        tasks[i].result = result;
        tasks[i].reader = process_reader;
        start += cnt;
    }

    pthread_t *threads = malloc(num_threads * sizeof(pthread_t));
    if (!threads) {
        free(tasks);
        return -1;
    }

    int threads_created = 0;
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&threads[i], NULL, snap_filter_thread, &tasks[i]) != 0) {
            if (progress) atomic_store(&progress->cancel, 1);
            for (int j = 0; j < threads_created; j++) pthread_join(threads[j], NULL);
            for (int j = 0; j < num_threads; j++) {
                free(tasks[j].ls.addrs);
                free(tasks[j].ls.values);
            }
            free(threads);
            free(tasks);
            return -1;
        }
        threads_created++;
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
        if (tasks[i].ret == -2) final_ret = -2;
        else if (tasks[i].ret != 0 && final_ret == 0) final_ret = tasks[i].ret;
    }
    free(threads);

    if (final_ret == 0 || final_ret == -2) {
        struct local_snapshot *ls_array = malloc(num_threads * sizeof(struct local_snapshot));
        if (!ls_array) {
            final_ret = -1;
            goto cleanup;
        }
        for (int i = 0; i < num_threads; i++) {
            ls_array[i] = tasks[i].ls;
        }

        if (merge_local_snapshots(ls_array, num_threads, snapshot) != 0) {
            final_ret = -1;
            free(ls_array);
            goto cleanup;
        }

        free(ls_array);
        free(tasks);
        return final_ret;
    } else {
        goto cleanup;
    }

cleanup:
    for (int i = 0; i < num_threads; i++) {
        free(tasks[i].ls.addrs);
        free(tasks[i].ls.values);
    }
    free(tasks);
    return final_ret;
}