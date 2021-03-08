//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_LOG_INNER_H_
#define _NP_LOG_INNER_H_

#include "stdio.h"

#include "np_types.h"
#include "neuropil_log.h"

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
bool _np_log_init (np_state_t* context, const char* filename, uint32_t level);

NP_API_EXPORT
void _np_log_destroy(np_state_t* context);

NP_API_INTERN
void _np_log_rotate(np_state_t* context, bool force);

NP_API_EXPORT
void np_log_setlevel(np_state_t* context, uint32_t level);

NP_API_INTERN
void _np_log_fflush(np_state_t* context, bool force);

NP_API_EXPORT
void np_log_message(np_state_t* context, enum np_log_e level,
                    const char* srcFile, const char* funcName,
                    uint16_t lineno, const char* msg, ...)
     //TODO: add context? __attribute__((__format__ (__printf__, 5,6) ))
;

#ifndef log_msg
    #define log_msg(level, msg, ...) \
         np_log_message(context, level, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
#endif

#ifndef log_info
        #define log_info(level, msg, ...) \
                 np_log_message(context, level | LOG_INFO, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
#endif
#ifndef log_warn
        #define log_warn(level, msg, ...) \
                 np_log_message(context, level | LOG_WARN, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
#endif
#ifndef log_error
        #define log_error(msg, ...) \
                 np_log_message(context, LOG_ERROR, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
#endif

#ifndef log_debug_msg
    #ifdef DEBUG
        #define log_debug_msg(level, msg, ...) \
                 np_log_message(context, level | LOG_DEBUG, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
        #define log_debug(level, msg, ...) \
                 np_log_message(context, level | LOG_DEBUG, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
    #else
        #define log_debug_msg(level, msg, ...)
        #define log_debug(level, msg, ...)
    #endif
#endif

#ifndef log_trace_msg
    #ifdef TRACE
        #define log_trace_msg(level, msg, ...) \
                 np_log_message(context, LOG_TRACE| level, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
    #else
        #define log_trace_msg(level, msg, ...)
    #endif
#endif


#endif /* _NP_LOG_INNER_H_ */
