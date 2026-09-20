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

#ifndef VMA_FILTER_H
#define VMA_FILTER_H

#include "vm_area.h"

#define VMA_FILTER_TYPE_Jh  1 << 0  /* filename="[anon:dalvik-main space (region space)]"*/
#define VMA_FILTER_TYPE_J   1 << 1  /* filename="[anon:dalvik-/" (substr)*/
#define VMA_FILTER_TYPE_Ch  1 << 2  /* filename="[heap]"*/
#define VMA_FILTER_TYPE_Ca  1 << 3  /* filename="[anon:libc_malloc] || [anon:scudo:(substr) || [anon:jemalloc(substr) "*/
#define VMA_FILTER_TYPE_Cd  1 << 4  /* perm=rw-p (open(pathnme)mask=ELF || pathname=".so"(substr)) */
#define VMA_FILTER_TYPE_Cb  1 << 5  /* filename="[anon:.bss] || last_area_type=Cd"*/
#define VMA_FILTER_TYPE_A   1 << 6  /* filename="[anon] || (nil)"*/
#define VMA_FILTER_TYPE_S   1 << 7  /* filename="[stack] "*/
#define VMA_FILTER_TYPE_As  1 << 8  /* filename="[/dev/ashmem(substr)"*/
#define VMA_FILTER_TYPE_V   1 << 9  /* filename="/dev/dri/(substr) || /dev/nvidia(substr) || /dev/kgsl-3d0 || /dev/mali0 || /dev/pvrsrvkm || /dev/ion || "*/
#define VMA_FILTER_TYPE_O   1 << 10 /* Other */ 
#define VMA_FILTER_TYPE_B   1 << 11 /* perm!=r-xp open(pathnme)mask!=ELF pathname="/system/(substr)"*/
#define VMA_FILTER_TYPE_Xa  1 << 12 /* perm=r-xp (open(pathnme)mask=ELF || pathname=".so"(substr)) pathname="/data/app/(substr)"*/
#define VMA_FILTER_TYPE_Xs  1 << 13 /* perm=r-xp (open(pathnme)mask=ELF || pathname=".so"(substr)) pathname="/system(substr)"*/

int vm_area_filter(const struct vm_area *src,
                   struct vm_area **dst,
                   int (*compar)(const struct vm_area *, void* ), void *user_data);

int vma_filter_named(struct vm_area** vm_area, const char* pathname, int is_substr, char perm[4]);

int vma_filter_anon(struct vm_area** vm_area, char perm[4]);

int vma_filter(struct vm_area** vm_area, int area_type, char perm[4]);

#endif  /* VMA_FILTER_H */