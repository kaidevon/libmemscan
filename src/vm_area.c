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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/sysmacros.h>
#include <libelf/libelf.h>
#include <libelf/gelf.h>

#include "memscan/vm_area.h"

int vma_elf(struct vm_area *head) {
    if (!head)
        return -1;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return -1;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        page_size = 4096;

    /* 初始化所有 VMA */
    for (struct vm_area *v = head; v; v = v->next) {
        v->seg_type  = VMA_TYPE_UNKNOWN;
        v->seg_index = 0;
        v->module    = NULL;
    }

    /* 第一遍：识别可执行段（.text），作为模块根 */
    for (struct vm_area *v = head; v; v = v->next) {
        if (!v->pathname)
            continue;

        int fd = open(v->pathname, O_RDONLY);
        if (fd < 0)
            continue;

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            close(fd);
            continue;
        }

        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr) == NULL) {
            elf_end(elf);
            close(fd);
            continue;
        }

        size_t phnum;
        if (elf_getphdrnum(elf, &phnum) != 0) {
            elf_end(elf);
            close(fd);
            continue;
        }

        uintptr_t load_bias = 0;
        int bias_found = 0;
        for (size_t i = 0; i < phnum && !bias_found; i++) {
            GElf_Phdr phdr;
            if (gelf_getphdr(elf, i, &phdr) == NULL)
                continue;
            if (phdr.p_type != PT_LOAD)
                continue;
            if (v->offset >= phdr.p_offset &&
                v->offset < phdr.p_offset + phdr.p_filesz) {
                load_bias = v->start - (phdr.p_vaddr + (v->offset - phdr.p_offset));
                bias_found = 1;
            }
        }
        if (!bias_found)
            load_bias = v->start - v->offset;

        int is_text = 0;
        for (size_t i = 0; i < phnum && !is_text; i++) {
            GElf_Phdr phdr;
            if (gelf_getphdr(elf, i, &phdr) == NULL)
                continue;
            if (phdr.p_type != PT_LOAD)
                continue;
            if (!(phdr.p_flags & PF_X))
                continue;
            uintptr_t seg_start = load_bias + phdr.p_vaddr;
            uintptr_t seg_end   = seg_start + phdr.p_filesz;
            if (v->start >= seg_start && v->start < seg_end)
                is_text = 1;
        }

        elf_end(elf);
        close(fd);

        if (is_text) {
            v->seg_type = VMA_TYPE_TEXT;
            v->module   = v;
        }
    }

    /* 第二遍：基于 ELF 程序头为其余 VMA 分配段类型和模块 */
    for (struct vm_area *v = head; v; v = v->next) {
        if (v->seg_type != VMA_TYPE_UNKNOWN || !v->pathname)
            continue;

        int fd = open(v->pathname, O_RDONLY);
        if (fd < 0)
            continue;

        Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
        if (!elf) {
            close(fd);
            continue;
        }

        GElf_Ehdr ehdr;
        if (gelf_getehdr(elf, &ehdr) == NULL) {
            elf_end(elf);
            close(fd);
            continue;
        }

        size_t phnum;
        if (elf_getphdrnum(elf, &phnum) != 0) {
            elf_end(elf);
            close(fd);
            continue;
        }

        uintptr_t load_bias = 0;
        int bias_found = 0;
        for (size_t i = 0; i < phnum && !bias_found; i++) {
            GElf_Phdr phdr;
            if (gelf_getphdr(elf, i, &phdr) == NULL)
                continue;
            if (phdr.p_type != PT_LOAD)
                continue;
            if (v->offset >= phdr.p_offset &&
                v->offset < phdr.p_offset + phdr.p_filesz) {
                load_bias = v->start - (phdr.p_vaddr + (v->offset - phdr.p_offset));
                bias_found = 1;
            }
        }
        if (!bias_found)
            load_bias = v->start - v->offset;

        int seg_type = VMA_TYPE_UNKNOWN;
        for (size_t i = 0; i < phnum && seg_type == VMA_TYPE_UNKNOWN; i++) {
            GElf_Phdr phdr;
            if (gelf_getphdr(elf, i, &phdr) == NULL)
                continue;
            if (phdr.p_type != PT_LOAD)
                continue;
            uintptr_t seg_start = load_bias + phdr.p_vaddr;
            uintptr_t seg_end   = seg_start + phdr.p_filesz;
            if (v->start >= seg_start && v->start < seg_end) {
                if (phdr.p_flags & PF_X)
                    seg_type = VMA_TYPE_TEXT;
                else if (!(phdr.p_flags & PF_W))
                    seg_type = VMA_TYPE_RODATA;
                else
                    seg_type = VMA_TYPE_DATA;
            }
        }

        elf_end(elf);
        close(fd);

        if (seg_type != VMA_TYPE_UNKNOWN) {
            v->seg_type = seg_type;
            struct vm_area *root = NULL;
            for (struct vm_area *w = head; w; w = w->next) {
                if (w->seg_type == VMA_TYPE_TEXT &&
                    w->pathname && strcmp(w->pathname, v->pathname) == 0) {
                    root = w;
                    break;
                }
            }
            if (!root)
                root = v;
            v->module = root;
        }
    }

    /* 第三遍：识别 .bss（可写且不属于任何文件的匿名可写段） */
    for (struct vm_area *v = head; v; v = v->next) {
        if (v->seg_type != VMA_TYPE_UNKNOWN)
            continue;
        if (v->perm[1] != 'w')
            continue;

        for (struct vm_area *root = head; root; root = root->next) {
            if (root->seg_type != VMA_TYPE_TEXT || !root->pathname)
                continue;

            int fd = open(root->pathname, O_RDONLY);
            if (fd < 0)
                continue;

            Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
            if (!elf) {
                close(fd);
                continue;
            }

            GElf_Ehdr ehdr;
            if (gelf_getehdr(elf, &ehdr) == NULL) {
                elf_end(elf);
                close(fd);
                continue;
            }

            size_t phnum;
            if (elf_getphdrnum(elf, &phnum) != 0) {
                elf_end(elf);
                close(fd);
                continue;
            }

            uintptr_t load_bias = 0;
            int bias_found = 0;
            for (size_t i = 0; i < phnum && !bias_found; i++) {
                GElf_Phdr phdr;
                if (gelf_getphdr(elf, i, &phdr) == NULL)
                    continue;
                if (phdr.p_type != PT_LOAD)
                    continue;
                if (root->offset >= phdr.p_offset &&
                    root->offset < phdr.p_offset + phdr.p_filesz) {
                    load_bias = root->start - (phdr.p_vaddr + (root->offset - phdr.p_offset));
                    bias_found = 1;
                }
            }
            if (!bias_found)
                load_bias = root->start - root->offset;

            int in_bss = 0;
            for (size_t i = 0; i < phnum && !in_bss; i++) {
                GElf_Phdr phdr;
                if (gelf_getphdr(elf, i, &phdr) == NULL)
                    continue;
                if (phdr.p_type != PT_LOAD)
                    continue;
                if (phdr.p_memsz > phdr.p_filesz) {
                    uintptr_t bss_start = load_bias + phdr.p_vaddr + phdr.p_filesz;
                    uintptr_t bss_end   = load_bias + phdr.p_vaddr + phdr.p_memsz;

                    bss_start = (bss_start + page_size - 1) & ~(page_size - 1);
                    bss_end   = (bss_end + page_size - 1) & ~(page_size - 1);

                    if (v->start >= bss_start && v->start < bss_end)
                        in_bss = 1;
                }
            }

            elf_end(elf);
            close(fd);

            if (in_bss) {
                v->seg_type = VMA_TYPE_BSS;
                v->module   = root;
                break;
            }
        }
    }

    /*
     * 第四遍：计算 seg_index。
     *
     * 对每个已识别类型的 VMA，统计同一模块、同一段类型中起始地址更小的
     * VMA 数量，即为该 VMA 的索引。按地址升序排列，从 0 开始编号。
     * 绝大多数模块每种段类型只有一个 VMA，因此结果通常为 0。
     */
    for (struct vm_area *v = head; v; v = v->next) {
        if (v->seg_type == VMA_TYPE_UNKNOWN || !v->module) {
            v->seg_index = 0;
            continue;
        }

        uint32_t idx = 0;
        for (struct vm_area *w = head; w; w = w->next) {
            if (w == v)
                continue;
            if (w->module != v->module)
                continue;
            if (w->seg_type != v->seg_type)
                continue;
            if (w->start < v->start)
                idx++;
        }
        v->seg_index = idx;
    }

    return 0;
}

int parse_maps(pid_t pid, struct vm_area **vm_area_out) {
    if (!vm_area_out)
        return -EINVAL;

    *vm_area_out = NULL;

    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", (int)pid);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -errno;

    /* 读取整个 maps 文件 */
    size_t cap = 64 * 1024;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return -ENOMEM;
    }

    for (;;) {
        if (len == cap) {
            size_t new_cap = cap * 2;
            char *tmp = realloc(buf, new_cap);
            if (!tmp) {
                free(buf);
                close(fd);
                return -ENOMEM;
            }
            buf = tmp;
            cap = new_cap;
        }
        ssize_t n = read(fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return -errno;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    close(fd);

    struct vm_area *head = NULL, *tail = NULL;
    int ret = 0;

    char *p   = buf;
    char *end = buf + len;

    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len;
        if (nl) {
            line_len = (size_t)(nl - p);
        } else {
            line_len = (size_t)(end - p);
        }

        if (line_len == 0) {
            if (!nl)
                break;
            p = nl + 1;
            continue;
        }

        /* 复制为独立的 NUL 终止字符串再解析 */
        char *line = malloc(line_len + 1);
        if (!line) {
            ret = -ENOMEM;
            goto cleanup;
        }
        memcpy(line, p, line_len);
        line[line_len] = '\0';

        uint64_t start = 0, end_addr = 0;
        uint64_t offset = 0, inode = 0;
        uint64_t dev_major = 0, dev_minor = 0;
        char perm_str[5] = {0};
        int consumed = 0;

        /*
         * 注意：%n 前不要加空格，否则会跳过换行。
         * 空格只应出现在必需分隔字段之间。
         */
        int matched = sscanf(line,
            "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64
            " %" SCNx64 ":%" SCNx64 " %" SCNu64 "%n",
            &start, &end_addr, perm_str,
            &offset, &dev_major, &dev_minor,
            &inode, &consumed);

        if (matched != 7) {
            free(line);
            if (!nl)
                break;
            p = nl + 1;
            continue;
        }

        size_t pos = ((size_t)consumed <= line_len) ? (size_t)consumed : line_len;

        while (pos < line_len && (line[pos] == ' ' || line[pos] == '\t'))
            pos++;

        char *pathname = NULL;
        if (pos < line_len) {
            size_t path_len = line_len - pos;
            while (path_len > 0 &&
                   (line[pos + path_len - 1] == ' ' ||
                    line[pos + path_len - 1] == '\t')) {
                path_len--;
            }
            if (path_len > 0) {
                pathname = malloc(path_len + 1);
                if (!pathname) {
                    free(line);
                    ret = -ENOMEM;
                    goto cleanup;
                }
                memcpy(pathname, line + pos, path_len);
                pathname[path_len] = '\0';
            }
        }

        free(line);

        struct vm_area *node = calloc(1, sizeof(struct vm_area));
        if (!node) {
            free(pathname);
            ret = -ENOMEM;
            goto cleanup;
        }

        node->start  = start;
        node->end    = end_addr;
        node->offset = (off_t)offset;
        node->dev    = makedev((unsigned)dev_major, (unsigned)dev_minor);
        node->inode  = (ino_t)inode;
        node->pathname = pathname;

        memcpy(node->perm, perm_str, 4);
        node->perm[4] = '\0';

        node->seg_type  = 0;
        node->seg_index = 0;
        node->module    = NULL;
        node->next      = NULL;

        if (!head) head = tail = node;
        else { tail->next = node; tail = node; }

        if (!nl)
            break;
        p = nl + 1;
    }

    free(buf);
    *vm_area_out = head;
    return 0;

cleanup:
    free(buf);
    free_vm_area(head);
    return ret;
}

void free_vm_area(struct vm_area *head) {
    while (head) {
        struct vm_area *next = head->next;
        free(head->pathname);
        free(head);
        head = next;
    }
}

struct vm_area* vm_area_copy(const struct vm_area *src) {
    if (!src) return NULL;

    struct vm_area *head = NULL, *tail = NULL;

    for (const struct vm_area *cur = src; cur; cur = cur->next) {
        struct vm_area *node = malloc(sizeof(struct vm_area));
        if (!node) {
            while (head) {
                struct vm_area *tmp = head;
                head = head->next;
                free(tmp->pathname);
                free(tmp);
            }
            return NULL;
        }

        *node = *cur;
        node->next = NULL;
        node->module = NULL;

        if (cur->pathname) {
            size_t len = strlen(cur->pathname) + 1;
            node->pathname = malloc(len);
            if (!node->pathname) {
                free(node);
                while (head) {
                    struct vm_area *tmp = head;
                    head = head->next;
                    free(tmp->pathname);
                    free(tmp);
                }
                return NULL;
            }
            memcpy(node->pathname, cur->pathname, len);
        } else {
            node->pathname = NULL;
        }

        if (!head) {
            head = tail = node;
        } else {
            tail->next = node;
            tail = node;
        }
    }

    return head;
}

struct vm_list* vma_copy2_vm(const struct vm_area *src) {
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return NULL;

    struct vm_list *head = NULL, *tail = NULL;
    struct vm_list *current = NULL;

    for (const struct vm_area *vma = src; vma; vma = vma->next) {
        uint64_t start = vma->start;
        uint64_t end   = vma->end;

        for (uint64_t addr = start; addr < end; addr += page_size) {
            if (!current || current->used == VM_LIST_CAPACITY) {
                struct vm_list *node = calloc(1, sizeof(*node));
                if (!node) {
                    while (head) {
                        struct vm_list *tmp = head;
                        head = head->next;
                        free(tmp);
                    }
                    return NULL;
                }
                if (!head) {
                    head = tail = node;
                } else {
                    tail->next = node;
                    tail = node;
                }
                current = node;
            }

            current->addr[current->used++] = addr;
        }
    }

    return head;
}