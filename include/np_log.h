//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_LOG_INNER_H_
#define _NP_LOG_INNER_H_

#include "stdio.h"

#include "neuropil_log.h"

#include "np_types.h"

/*
    0000 0
    000i 1
    00i0 2
    00ii 3
    0i00 4
    0i0i 5
    0ii0 6
    0iii 7
    i000 8
    i00i 9
    i0i0 A
    i0ii B
    ii00 C
    ii0i D
    iii0 E
    iiii F
*/

typedef enum np_log_e log_type;

NP_API_EXPORT
bool _np_log_init(np_state_t *context, const char *filename, uint32_t level);

NP_API_EXPORT
void _np_log_destroy(np_state_t *context);

NP_API_INTERN
void _np_log_rotation(np_state_t *context);

NP_API_EXPORT
void np_log_setlevel(np_state_t *context, uint32_t level);

NP_API_INTERN
void _np_log_fflush(np_state_t *context, bool force);

NP_API_EXPORT
void np_log_message(np_state_t   *context,
                    enum np_log_e level,
                    const char   *srcFile,
                    const char   *funcName,
                    uint16_t      lineno,
                    void         *uuid,
                    const char   *msg,
                    ...) __attribute__((__format__(__printf__, 7, 8)));

#ifndef log_msg
#define log_msg(level, uuid, msg, ...)                                         \
  np_log_message(context,                                                      \
                 level,                                                        \
                 __FILE__,                                                     \
                 FUNC,                                                         \
                 __LINE__,                                                     \
                 uuid,                                                         \
                 msg,                                                          \
                 ##__VA_ARGS__)
#endif

#ifndef log_info
#define log_info(level, uuid, msg, ...)                                        \
  log_msg(level | LOG_INFO, uuid, msg, ##__VA_ARGS__)
#endif

#ifndef log_warn
#define log_warn(level, uuid, msg, ...)                                        \
  log_msg(level | LOG_WARNING, uuid, msg, ##__VA_ARGS__)
#endif

#ifndef log_error
#define log_error(uuid, msg, ...) log_msg(LOG_ERROR, uuid, msg, ##__VA_ARGS__)
#endif

#ifdef DEBUG
#ifndef log_debug
#define log_debug(level, uuid, msg, ...)                                       \
  log_msg(level | LOG_DEBUG, uuid, msg, ##__VA_ARGS__)
#endif
#else
#define log_debug(level, uuid, msg, ...)
#endif

#ifdef TRACE
#ifndef log_trace
#define log_trace(level, uuid, msg, ...)                                       \
  log_msg(level | LOG_TRACE, uuid, msg, ##__VA_ARGS__)
#endif
#else
#define log_trace_msg(level, uuid, msg, ...)
#define log_trace(level, uuid, msg, ...)
#endif

#endif /* _NP_LOG_INNER_H_ */
