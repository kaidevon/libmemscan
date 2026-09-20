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

#ifndef ADDR_LIST_FILTER_H
#define ADDR_LIST_FILTER_H

#include "memscan.h"
#include "memscan/callback.h"
#include "memscan/vm_area.h"
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>

#define ADDR_LIST_FILTER_EQ   0
#define ADDR_LIST_FILTER_NE   1
#define ADDR_LIST_FILTER_LT   2
#define ADDR_LIST_FILTER_LE   3
#define ADDR_LIST_FILTER_GT   4
#define ADDR_LIST_FILTER_GE   5
#define ADDR_LIST_FILTER_FEQ  6
#define ADDR_LIST_FILTER_FNE  7
#define ADDR_LIST_FILTER_FLT  8
#define ADDR_LIST_FILTER_FLE  9
#define ADDR_LIST_FILTER_FGT  10
#define ADDR_LIST_FILTER_FGE  11
#define ADDR_LIST_FILTER_IEQ_M9 12
#define ADDR_LIST_FILTER_IEQ_M8 13
#define ADDR_LIST_FILTER_IEQ_M7 14
#define ADDR_LIST_FILTER_IEQ_M6 15
#define ADDR_LIST_FILTER_IEQ_M5 16
#define ADDR_LIST_FILTER_IEQ_M4 17
#define ADDR_LIST_FILTER_IEQ_M3 18
#define ADDR_LIST_FILTER_IEQ_M2 19
#define ADDR_LIST_FILTER_IEQ_M1 20
#define ADDR_LIST_FILTER_IEQ_0  21
#define ADDR_LIST_FILTER_IEQ_1  22
#define ADDR_LIST_FILTER_IEQ_2  23
#define ADDR_LIST_FILTER_IEQ_3  24
#define ADDR_LIST_FILTER_IEQ_4  25
#define ADDR_LIST_FILTER_IEQ_5  26
#define ADDR_LIST_FILTER_IEQ_6  27
#define ADDR_LIST_FILTER_IEQ_7  28
#define ADDR_LIST_FILTER_IEQ_8  29
#define ADDR_LIST_FILTER_IEQ_9  30
#define ADDR_LIST_FILTER_INE_M9 31
#define ADDR_LIST_FILTER_INE_M8 32
#define ADDR_LIST_FILTER_INE_M7 33
#define ADDR_LIST_FILTER_INE_M6 34
#define ADDR_LIST_FILTER_INE_M5 35
#define ADDR_LIST_FILTER_INE_M4 36
#define ADDR_LIST_FILTER_INE_M3 37
#define ADDR_LIST_FILTER_INE_M2 38
#define ADDR_LIST_FILTER_INE_M1 39
#define ADDR_LIST_FILTER_INE_0  40
#define ADDR_LIST_FILTER_INE_1  41
#define ADDR_LIST_FILTER_INE_2  42
#define ADDR_LIST_FILTER_INE_3  43
#define ADDR_LIST_FILTER_INE_4  44
#define ADDR_LIST_FILTER_INE_5  45
#define ADDR_LIST_FILTER_INE_6  46
#define ADDR_LIST_FILTER_INE_7  47
#define ADDR_LIST_FILTER_INE_8  48
#define ADDR_LIST_FILTER_INE_9  49
#define ADDR_LIST_FILTER_FEQ_M9 50
#define ADDR_LIST_FILTER_FEQ_M8 51
#define ADDR_LIST_FILTER_FEQ_M7 52
#define ADDR_LIST_FILTER_FEQ_M6 53
#define ADDR_LIST_FILTER_FEQ_M5 54
#define ADDR_LIST_FILTER_FEQ_M4 55
#define ADDR_LIST_FILTER_FEQ_M3 56
#define ADDR_LIST_FILTER_FEQ_M2 57
#define ADDR_LIST_FILTER_FEQ_M1 58
#define ADDR_LIST_FILTER_FEQ_0  59
#define ADDR_LIST_FILTER_FEQ_1  60
#define ADDR_LIST_FILTER_FEQ_2  61
#define ADDR_LIST_FILTER_FEQ_3  62
#define ADDR_LIST_FILTER_FEQ_4  63
#define ADDR_LIST_FILTER_FEQ_5  64
#define ADDR_LIST_FILTER_FEQ_6  65
#define ADDR_LIST_FILTER_FEQ_7  66
#define ADDR_LIST_FILTER_FEQ_8  67
#define ADDR_LIST_FILTER_FEQ_9  68
#define ADDR_LIST_FILTER_FNE_M9 69
#define ADDR_LIST_FILTER_FNE_M8 70
#define ADDR_LIST_FILTER_FNE_M7 71
#define ADDR_LIST_FILTER_FNE_M6 72
#define ADDR_LIST_FILTER_FNE_M5 73
#define ADDR_LIST_FILTER_FNE_M4 74
#define ADDR_LIST_FILTER_FNE_M3 75
#define ADDR_LIST_FILTER_FNE_M2 76
#define ADDR_LIST_FILTER_FNE_M1 77
#define ADDR_LIST_FILTER_FNE_0  78
#define ADDR_LIST_FILTER_FNE_1  79
#define ADDR_LIST_FILTER_FNE_2  80
#define ADDR_LIST_FILTER_FNE_3  81
#define ADDR_LIST_FILTER_FNE_4  82
#define ADDR_LIST_FILTER_FNE_5  83
#define ADDR_LIST_FILTER_FNE_6  84
#define ADDR_LIST_FILTER_FNE_7  85
#define ADDR_LIST_FILTER_FNE_8  86
#define ADDR_LIST_FILTER_FNE_9  87

#define ADDR_LIST_SNAPSHOT_FILTER_CHG    100
#define ADDR_LIST_SNAPSHOT_FILTER_UNCH   101
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG   102
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH  103
#define ADDR_LIST_SNAPSHOT_FILTER_INC    104
#define ADDR_LIST_SNAPSHOT_FILTER_DEC    105
#define ADDR_LIST_SNAPSHOT_FILTER_INC_BY 106
#define ADDR_LIST_SNAPSHOT_FILTER_DEC_BY 107
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M9 108
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M8 109
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M7 110
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M6 111
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M5 112
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M4 113
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M3 114
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M2 115
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_M1 116
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_0  117
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_1  118
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_2  119
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_3  120
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_4  121
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_5  122
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_6  123
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_7  124
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_8  125
#define ADDR_LIST_SNAPSHOT_FILTER_ICHG_9  126
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M9 127
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M8 128
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M7 129
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M6 130
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M5 131
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M4 132
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M3 133
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M2 134
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_M1 135
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_0  136
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_1  137
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_2  138
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_3  139
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_4  140
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_5  141
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_6  142
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_7  143
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_8  144
#define ADDR_LIST_SNAPSHOT_FILTER_IUNCH_9  145
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M9 146
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M8 147
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M7 148
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M6 149
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M5 150
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M4 151
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M3 152
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M2 153
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_M1 154
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_0  155
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_1  156
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_2  157
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_3  158
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_4  159
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_5  160
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_6  161
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_7  162
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_8  163
#define ADDR_LIST_SNAPSHOT_FILTER_FCHG_9  164
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M9 165
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M8 166
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M7 167
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M6 168
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M5 169
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M4 170
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M3 171
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M2 172
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_M1 173
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_0  174
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_1  175
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_2  176
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_3  177
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_4  178
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_5  179
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_6  180
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_7  181
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_8  182
#define ADDR_LIST_SNAPSHOT_FILTER_FUNCH_9  183

/* address list */
struct addr_list {
    uint64_t *addrs;
    size_t    count;
};

/* address list snapshot*/
struct addr_list_snapshot {
    uint64_t *addrs;
    uint8_t  *values;
    size_t    count;
    size_t    value_size;
};

int addrlist_filter(pid_t pid, 
                     const struct addr_list* addrlist, 
                     int filter_type,
                     const void* src, 
                     size_t size,
                     struct ms_progress* progress,
                     struct ms_result** result,
                     process_reader_t process_reader,
                     int jobs);

int addrlist_snapshot_filter(pid_t pid,
                     const struct addr_list* addrlist,
                     int filter_type,
                     struct addr_list_snapshot* snapshot,
                     uint64_t delta,
                     struct ms_progress* progress,
                     struct ms_result** result,
                     process_reader_t process_reader,
                     int jobs);

struct addr_list* vmlist2_addrlist(struct vm_list* vmlist);

struct addr_list_snapshot* addrlist_snapshot(pid_t pid, 
                     struct addr_list* addrlist, 
                     size_t value_size,
                     process_reader_t reader);

#endif  /*  ADDR_LIST_FILTER_H */