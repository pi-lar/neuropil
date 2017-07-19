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

typedef enum np_log_e log_type;

enum np_log_e
{
	LOG_NONE  		    = 0x000000, /* log nothing        */
	LOG_NOMOD		    = 0x000000, /*                    */

	LOG_ERROR     		= 0x000001, /* error messages     */
    LOG_WARN       		= 0x000002, /* warning messages   */
    LOG_INFO       		= 0x000004, /* info messages      */
    LOG_DEBUG      		= 0x000008, /* debugging messages */
    LOG_TRACE      		= 0x000010, /* tracing messages   */

	LOG_SERIALIZATION	= 0x000100, /* debugging the serialization methods    */
	LOG_MUTEX      		= 0x000200, /* debugging messages for mutex subsystem */
	LOG_KEY        		= 0x000400, /* debugging messages for key subsystem   */
	LOG_NETWORK    		= 0x000800, /* debugging messages for network layer   */
    LOG_ROUTING    		= 0x001000, /* debugging the routing table            */
    LOG_MESSAGE    		= 0x002000, /* debugging the message subsystem        */
    LOG_SECURE     		= 0x004000, /* debugging the security module          */
    LOG_HTTP       		= 0x008000, /* debugging the http subsystem           */
	LOG_AAATOKEN   		= 0x010000, /* debugging the aaatoken subsystem       */
	LOG_MEMORY 			= 0x020000, /* debugging the memory subsystem      	  */
	LOG_SYSINFO			= 0x040000, /* debugging the Sysinfo subsystem     	  */

	LOG_GLOBAL     		= 0x800000, /* debugging the global system            */

} NP_ENUM NP_API_EXPORT;

#define LOG_NOMOD_MASK 	  0x8000FF /* filter the module mask */
#define LOG_MODUL_MASK    0x0FFF00 /* filter the module mask */
#define LOG_LEVEL_MASK    0x0000FF /* filter the log level */


NP_API_EXPORT
void np_log_init (const char* filename, uint32_t level);

NP_API_EXPORT
void np_log_setlevel(uint32_t level);

NP_API_EXPORT
void np_log_destroy ();

NP_API_INTERN
void _np_log_fflush();

NP_API_EXPORT
void np_log_message(uint32_t level,
					const char* srcFile, const char* funcName,
					uint16_t lineno, const char* msg, ...)
	 __attribute__((__format__ (__printf__, 5,6) ));

#ifndef log_msg
	#define log_msg(level, msg, ...) \
		 np_log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)
#endif

#ifdef DEBUG
	#ifndef log_debug_msg
		#define log_debug_msg(level, msg, ...) \
		 np_log_message(level & LOG_DEBUG, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)
	#endif
#else
	#ifndef log_debug_msg
		#define log_debug_msg(level, msg, ...)
	#endif
#endif

#endif /* _NP_LOG_H_ */
