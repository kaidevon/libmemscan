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

#include "memscan/vma_filter.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

struct vma_filter_rule {
    const char *pathname;
    int is_substr;
    char perm[4];
    int is_anon;
};

static int compar(const struct vm_area *area, void *user_data) {
    struct vma_filter_rule *rule = user_data;

    if (area->perm[0] != rule->perm[0]) return 0;
    if (area->perm[1] != rule->perm[1]) return 0;
    if (area->perm[2] != rule->perm[2]) return 0;
    if (area->perm[3] != rule->perm[3]) return 0;

    if (rule->is_anon) {
        if (area->pathname != NULL && strcmp(area->pathname, "[anon]") != 0)
            return 0;
        return 1;
    } else {
        if (area->pathname == NULL || strcmp(area->pathname, "[anon]") == 0)
            return 0;
        if (rule->is_substr) {
            if (strstr(area->pathname, rule->pathname) == NULL)
                return 0;
        } else {
            if (strcmp(area->pathname, rule->pathname) != 0)
                return 0;
        }
        return 1;
    }
}

static int is_elf_file(const char *pathname) {
    if (!pathname) return 0;
    int fd = open(pathname, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char magic[4];
    ssize_t n = read(fd, magic, 4);
    close(fd);
    return (n == 4 && magic[0] == 0x7f && magic[1] == 'E' &&
            magic[2] == 'L'  && magic[3] == 'F');
}

int vm_area_filter(const struct vm_area *src,
                   struct vm_area **dst,
                   int (*compar)(const struct vm_area *, void *), void *user_data) {
    int ret = 0;
    if (!src || !dst || !compar) {
        return -1;   /* invalid argument */
    }

    *dst = NULL;
    struct vm_area *tail = NULL;
    int count = 0;

    for (const struct vm_area *cur = src; cur; cur = cur->next) {
        if (!compar(cur, user_data))
            continue;

        struct vm_area *new_node = malloc(sizeof(struct vm_area));
        if (!new_node) {
            ret = -2;   /* out of memory */
            goto cleanup;
        }

        *new_node = *cur;
        new_node->next = NULL;

        if (cur->pathname) {
            size_t len = strlen(cur->pathname) + 1;
            new_node->pathname = malloc(len);
            if (!new_node->pathname) {
                free(new_node);
                ret = -2;   /* out of memory */
                goto cleanup;
            }
            memcpy(new_node->pathname, cur->pathname, len);
        } else {
            new_node->pathname = NULL;
        }

        if (!*dst) {
            *dst = new_node;
            tail = new_node;
        } else {
            tail->next = new_node;
            tail = new_node;
        }
        count++;
    }

    return count;

cleanup:
    if (ret != 0 && *dst) {
        struct vm_area *cur_node = *dst;
        while (cur_node) {
            struct vm_area *next_node = cur_node->next;
            free(cur_node->pathname);
            free(cur_node);
            cur_node = next_node;
        }
        *dst = NULL;
    }
    return ret;
}

int vma_filter_named(struct vm_area **vm_area, const char *pathname,
                     int is_substr, char perm[4]) {
    if (!vm_area || !*vm_area || !pathname || !perm)
        return -1;

    struct vma_filter_rule rule;
    rule.pathname = pathname;
    rule.is_substr = is_substr;
    memcpy(rule.perm, perm, 4);
    rule.is_anon = 0;

    struct vm_area *filtered = NULL;
    int count = vm_area_filter(*vm_area, &filtered, compar, &rule);
    if (count < 0)
        return -1;

    free_vm_area(*vm_area);
    *vm_area = filtered;
    return count;
}

int vma_filter_anon(struct vm_area **vm_area, char perm[4]) {
    if (!vm_area || !*vm_area || !perm)
        return -1;

    struct vma_filter_rule rule;
    rule.pathname = NULL;       /* unused for anonymous */
    rule.is_substr = 0;
    memcpy(rule.perm, perm, 4);
    rule.is_anon = 1;

    struct vm_area *filtered = NULL;
    int count = vm_area_filter(*vm_area, &filtered, compar, &rule);
    if (count < 0)
        return -1;

    free_vm_area(*vm_area);
    *vm_area = filtered;
    return count;
}

static int do_vma_filter(struct vm_area** vm_area, int area_type, char perm[4]) {
    if (!vm_area || !*vm_area)
        return -1;

    struct vm_area *curr = *vm_area;
    struct vm_area *filtered = NULL;
    struct vm_area *tail = NULL;
    int count = 0;

    /* Cb depends on whether the previous area was Cd. */
    int last_was_Cd = 0;

    while (curr) {
        struct vm_area *next = curr->next;
        int match = 0;

        switch (area_type) {
        case VMA_FILTER_TYPE_Jh:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                curr->pathname &&
                strcmp(curr->pathname, "[anon:dalvik-main space (region space)]") == 0)
                match = 1;
            break;

        case VMA_FILTER_TYPE_J:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                curr->pathname &&
                strstr(curr->pathname, "[anon:dalvik-/") != NULL)
                match = 1;
            break;

        case VMA_FILTER_TYPE_Ch:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                curr->pathname &&
                strcmp(curr->pathname, "[heap]") == 0)
                match = 1;
            break;

        case VMA_FILTER_TYPE_Ca:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) && curr->pathname) {
                if (strcmp(curr->pathname, "[anon:libc_calloc]") == 0 ||
                    strcmp(curr->pathname, "[anon:libc_malloc]") == 0 ||
                    strstr(curr->pathname, "[anon:scudo:") != NULL ||
                    strstr(curr->pathname, "[anon:jemalloc") != NULL)
                    match = 1;
            }
            break;

        case VMA_FILTER_TYPE_Cd:
            /* Cd has fixed perms: either "rw-p" or "r--p". */
            if ((memcmp(curr->perm, "rw-p", 4) == 0 || memcmp(curr->perm, "r--p", 4) == 0) &&
                curr->pathname) {
                if (strstr(curr->pathname, ".so") != NULL ||
                    is_elf_file(curr->pathname))
                    match = 1;
            }
            /* Update last_was_Cd for subsequent Cb checking. */
            last_was_Cd = match;
            break;

        case VMA_FILTER_TYPE_Cb:
            /* Cb requires perm "rw-p". */
            if (memcmp(curr->perm, "rw-p", 4) == 0) {
                if ((curr->pathname && strcmp(curr->pathname, "[anon:.bss]") == 0) ||
                    last_was_Cd)
                    match = 1;
            }
            /* Update last_was_Cd using the current area's Cd status. */
            {
                int is_Cd = (curr->pathname &&
                             (memcmp(curr->perm, "rw-p", 4) == 0 || memcmp(curr->perm, "r--p", 4) == 0) &&
                             (strstr(curr->pathname, ".so") != NULL ||
                              is_elf_file(curr->pathname)));
                last_was_Cd = is_Cd;
            }
            break;

        case VMA_FILTER_TYPE_A:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                (curr->pathname == NULL || strcmp(curr->pathname, "[anon]") == 0))
                match = 1;
            break;

        case VMA_FILTER_TYPE_S:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                curr->pathname &&
                strcmp(curr->pathname, "[stack]") == 0)
                match = 1;
            break;

        case VMA_FILTER_TYPE_As:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) &&
                curr->pathname &&
                strstr(curr->pathname, "/dev/ashmem") != NULL)
                match = 1;
            break;

        case VMA_FILTER_TYPE_V:
            if ((perm == NULL || memcmp(curr->perm, perm, 4) == 0) && curr->pathname) {
                if (strstr(curr->pathname, "/dev/dri/") != NULL ||
                    strstr(curr->pathname, "/dev/nvidia") != NULL ||
                    strcmp(curr->pathname, "/dev/kgsl-3d0") == 0 ||
                    strcmp(curr->pathname, "/dev/mali0") == 0 ||
                    strcmp(curr->pathname, "/dev/pvrsrvkm") == 0 ||
                    strcmp(curr->pathname, "/dev/ion") == 0)
                    match = 1;
            }
            break;

        case VMA_FILTER_TYPE_B:
            /* B: perm != "r-xp", path contains "/system/", not .so and not ELF. */
            if (memcmp(curr->perm, "r-xp", 4) != 0 &&
                curr->pathname &&
                strstr(curr->pathname, "/system/") != NULL) {
                if (strstr(curr->pathname, ".so") == NULL &&
                    !is_elf_file(curr->pathname))
                    match = 1;
            }
            break;

        case VMA_FILTER_TYPE_Xa:
            /* Xa: perm == "r-xp", path contains "/data/app/", .so or ELF. */
            if (memcmp(curr->perm, "r-xp", 4) == 0 &&
                curr->pathname &&
                strstr(curr->pathname, "/data/app/") != NULL) {
                if (strstr(curr->pathname, ".so") != NULL ||
                    is_elf_file(curr->pathname))
                    match = 1;
            }
            break;

        case VMA_FILTER_TYPE_Xs:
            /* Xs: perm == "r-xp", path contains "/system", .so or ELF. */
            if (memcmp(curr->perm, "r-xp", 4) == 0 &&
                curr->pathname &&
                strstr(curr->pathname, "/system") != NULL) {
                if (strstr(curr->pathname, ".so") != NULL ||
                    is_elf_file(curr->pathname))
                    match = 1;
            }
            break;

        case VMA_FILTER_TYPE_O:
            /* Other: area does not belong to any defined type. */
            {
                int known = 0;

                /* Check types that use the caller-supplied perm. */
                if (perm == NULL || memcmp(curr->perm, perm, 4) == 0) {
                    if (curr->pathname) {
                        if (strcmp(curr->pathname, "[anon:dalvik-main space (region space)]") == 0 ||
                            strstr(curr->pathname, "[anon:dalvik-") ||
                            strcmp(curr->pathname, "[heap]") == 0 ||
                            strcmp(curr->pathname, "[anon:libc_malloc]") == 0 ||
                            strstr(curr->pathname, "[anon:scudo:") ||
                            strstr(curr->pathname, "[anon:jemalloc") ||
                            strcmp(curr->pathname, "[stack]") == 0 ||
                            strstr(curr->pathname, "/dev/ashmem") ||
                            strstr(curr->pathname, "/dev/dri/") ||
                            strstr(curr->pathname, "/dev/nvidia") ||
                            strcmp(curr->pathname, "/dev/kgsl-3d0") == 0 ||
                            strcmp(curr->pathname, "/dev/mali0") == 0 ||
                            strcmp(curr->pathname, "/dev/pvrsrvkm") == 0 ||
                            strcmp(curr->pathname, "/dev/ion") == 0)
                            known = 1;
                    } else {
                        known = 1;   /* Anonymous area belongs to A, not Other. */
                    }
                }

                /* Check types with fixed perm requirements. */
                if (!known && curr->pathname) {
                    /* Cd */
                    if ((memcmp(curr->perm, "rw-p", 4) == 0 || memcmp(curr->perm, "r--p", 4) == 0) &&
                        (strstr(curr->pathname, ".so") || is_elf_file(curr->pathname)))
                        known = 1;
                    /* B */
                    else if (memcmp(curr->perm, "r-xp", 4) != 0 &&
                             strstr(curr->pathname, "/system/") &&
                             strstr(curr->pathname, ".so") == NULL &&
                             !is_elf_file(curr->pathname))
                        known = 1;
                    /* Xa */
                    else if (memcmp(curr->perm, "r-xp", 4) == 0 &&
                             strstr(curr->pathname, "/data/app/") &&
                             (strstr(curr->pathname, ".so") || is_elf_file(curr->pathname)))
                        known = 1;
                    /* Xs */
                    else if (memcmp(curr->perm, "r-xp", 4) == 0 &&
                             strstr(curr->pathname, "/system") &&
                             (strstr(curr->pathname, ".so") || is_elf_file(curr->pathname)))
                        known = 1;
                }

                /* Also check Cb with fixed perm "rw-p". */
                if (!known && memcmp(curr->perm, "rw-p", 4) == 0) {
                    if (curr->pathname && strcmp(curr->pathname, "[anon:.bss]") == 0)
                        known = 1;
                }

                if (!known)
                    match = 1;
            }
            break;

        default:
            free_vm_area(filtered);
            while (curr) {
                struct vm_area *next = curr->next;
                free(curr->pathname);
                free(curr);
                curr = next;
            }
            *vm_area = NULL;
            return -1;
        }

        if (match) {
            curr->next = NULL;
            if (!filtered) {
                filtered = curr;
                tail = curr;
            } else {
                tail->next = curr;
                tail = curr;
            }
            count++;
        } else {
            free(curr->pathname);
            free(curr);
        }

        curr = next;
    }

    *vm_area = filtered;
    return count;
}

/* support combining multiple bitmasks */
int vma_filter(struct vm_area** vm_area, int area_type, char perm[4]) {
    if (!vm_area || !*vm_area) return -1;
    if (area_type == 0) return -1;

    struct vm_area *result = NULL;
    struct vm_area *result_tail = NULL;
    int total_count = 0;

    extern struct vm_area* vm_area_copy(const struct vm_area*);

    for (int t = 1; t <= VMA_FILTER_TYPE_Xs; t <<= 1) {
        if (area_type & t) {
            struct vm_area *copy = vm_area_copy(*vm_area);
            if (!copy) {
                while (result) {
                    struct vm_area *tmp = result;
                    result = result->next;
                    free(tmp->pathname);
                    free(tmp);
                }
                return -1;
            }

            int cnt = do_vma_filter(&copy, t, perm);
            if (cnt < 0) {
                if (copy) {
                    struct vm_area *node = copy;
                    while (node) {
                        struct vm_area *next = node->next;
                        free(node->pathname);
                        free(node);
                        node = next;
                    }
                }
                while (result) {
                    struct vm_area *tmp = result;
                    result = result->next;
                    free(tmp->pathname);
                    free(tmp);
                }
                return -1;
            }

            if (copy) {
                struct vm_area *sub_tail = copy;
                while (sub_tail->next) sub_tail = sub_tail->next;

                if (!result) {
                    result = copy;
                    result_tail = sub_tail;
                } else {
                    result_tail->next = copy;
                    result_tail = sub_tail;
                }
                total_count += cnt;
            }
        }
    }

    free_vm_area(*vm_area);
    *vm_area = result;
    return total_count;
}