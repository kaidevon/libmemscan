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

#ifndef MEMSCAN_CALLBACK_H
#define MEMSCAN_CALLBACK_H

#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

/* process reader callback */
typedef ssize_t (*process_reader_t)(
    pid_t pid,
    const struct iovec* local_iov, unsigned long liovcnt,
    const struct iovec* remote_iov, unsigned long riovcnt,
    void* userdata
);

typedef int (*memscanv_compar_t)(
    const uint8_t *buf,
    size_t len,
    const void **src,
    size_t *size,
    int *align,
    int count,
    uint64_t *mask,
    size_t mask_words,
    void *userdata
);

#endif  /* MEMSCAN_CALLBACK_H */