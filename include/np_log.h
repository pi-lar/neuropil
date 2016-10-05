//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_LOG_H_
#define _NP_LOG_H_

#include "stdio.h"

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

enum
{
	LOG_NONE       = 0x0000, /* log nothing        */
	LOG_NOMOD      = 0x0000, /*           */

	LOG_ERROR      = 0x0001, /* error messages     */
    LOG_WARN       = 0x0002, /* warning messages   */
    LOG_INFO       = 0x0004, /* info messages      */
    LOG_DEBUG      = 0x0008, /* debugging messages */
    LOG_TRACE      = 0x0010, /* tracing messages   */

	LOG_KEY        = 0x0100, /* debugging messages for key subsystem */
    LOG_NETWORK    = 0x0200, /* debugging messages for network layer */
    LOG_ROUTING    = 0x0400, /* debugging the routing table          */
    LOG_MESSAGE    = 0x0800, /* debugging the message subsystem      */
    LOG_SECURE     = 0x1000, /* debugging the security module        */
    LOG_HTTP       = 0x2000, /* debugging the message subsystem      */
    LOG_AAATOKEN   = 0x4000, /* debugging the message subsystem      */
    LOG_GLOBAL     = 0x8000, /* debugging the global system          */

	LOG_MODUL_MASK = 0xFF00, /* debugging the global system          */
	LOG_NOMOD_MASK = 0x7F00, /* debugging the global system          */

} NP_ENUM NP_API_EXPORT;

#define LOG_LEVEL_MASK 0x00FF /*  */

NP_API_EXPORT
void np_log_init (const char* filename, uint16_t level);

NP_API_EXPORT
void np_log_setlevel(uint16_t level);

NP_API_EXPORT
void np_log_destroy ();

NP_API_INTERN
void _np_log_fflush();

NP_API_EXPORT
void np_log_message(uint16_t level,
					 const char* srcFile, const char* funcName,
					 uint16_t lineno, const char* msg, ...)
	 __attribute__((__format__ (__printf__, 5,6) ));

#define log_msg(level, msg, ...) \
	 np_log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)

#endif /* _NP_LOG_H_ */
