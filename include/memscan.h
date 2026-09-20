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

#ifndef MEMSCAN_H
#define MEMSCAN_H

#include "memscan/callback.h"
#include "memscan/vm_area.h"
#include <sys/types.h>
#include <sys/uio.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <pthread.h>

#define CHUNK_READ_SIZE         0x100000

#define MEMSCAN_CANCEL   1
#define MEMSCAN_PAUSE    1

#define MEMSCAN_FINISH      0
#define MEMSCAN_FAILED      -1
#define MEMSCAN_CANCELLED   -2

/* memscan performance counters */
struct ms_perf {
    atomic_uint_least64_t start_ns;
    atomic_uint_least64_t end_ns;
    atomic_ullong bytes;
    atomic_ullong cb_count;
    atomic_ullong found;
    int thread_count;
};

/* memscan result storage */
struct ms_result {
    struct vm_list *head;
    struct vm_list *tail;
    struct ms_perf* perf;
    pthread_mutex_t lock;
};

/* memscan progress control */
struct ms_progress {
    _Atomic uint64_t tot_len;
    _Atomic uint64_t current_pos;
    _Atomic uint64_t total_found;
    _Atomic int      cancel;
    _Atomic int      pause;
    int              event_fd;
    pthread_mutex_t mtx;
    pthread_cond_t  cond;
};

/**
 * memscanv - multi-threaded memory scan for multiple byte patterns
 * @pid:             PID of the target process
 * @vm_area:         linked list of virtual memory areas to be scanned
 * @src:             array of pointers to byte patterns
 * @size:            array of pattern lengths (bytes)
 * @align:           array of alignment requirements (power of 2)
 * @count:           number of patterns
 * @progress:        progress control object, may be NULL
 * @result:          address of a result-set pointer; matching addresses are appended
 * @process_reader:  remote memory read callback function
 * @compar:          optional comparison callback for custom matching (may be NULL)
 * @userdata:        user-defined data passed to the comparison callback
 * @jobs:            number of parallel threads
 *
 * This function scans the given memory areas for any of the specified patterns.
 * If a comparison callback is provided, it is used for custom matching;
 * otherwise, an optimized multi-value integer scan is used when all patterns
 * are 4 or 8 bytes with the same alignment, falling back to a generic search
 * for each pattern individually.
 *
 * Return values:
 *   MEMSCAN_FINISH    ( 0) - success
 *   MEMSCAN_FAILED    (-1) - fatal error
 *   MEMSCAN_CANCELLED (-2) - cancelled by user
 */
int memscanv(pid_t pid, struct vm_area* vm_area,
             const void** src, size_t* size, int* align, int count,
             struct ms_progress* progress,
             struct ms_result** result,
             process_reader_t process_reader,
             memscanv_compar_t compar,
             void *userdata,
             int jobs);

/**
 * memscan - multi-threaded memory scan for a single byte pattern
 * @pid:             PID of the target process
 * @vm_area:         linked list of virtual memory areas to be scanned
 * @src:             target byte string to search for
 * @size:            length of the target byte string in bytes
 * @align:           alignment requirement, must be a power of 2
 * @progress:        progress control object, may be NULL
 * @result:          address of a result-set pointer
 * @process_reader:  remote memory read callback function
 * @jobs:            number of parallel threads
 *
 * This is a convenience wrapper around memscanv for a single pattern.
 *
 * Return values:
 *   MEMSCAN_FINISH    ( 0) - success
 *   MEMSCAN_FAILED    (-1) - fatal error
 *   MEMSCAN_CANCELLED (-2) - cancelled by user
 */
int memscan(pid_t pid, struct vm_area* vm_area,
            const void* src, size_t size, int align,
            struct ms_progress* progress,
            struct ms_result** result,
            process_reader_t process_reader,
            int jobs);

void free_ms_result(struct ms_result** result);

struct ms_progress* create_ms_progress(void);
void free_ms_progress(struct ms_progress* progress);

void ms_progress_pause(struct ms_progress* p);
void ms_progress_resume(struct ms_progress* p);
void ms_progress_cancel(struct ms_progress* p);

#endif /* MEMSCAN_H */