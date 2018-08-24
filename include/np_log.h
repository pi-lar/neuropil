//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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
	LOG_NONE  		    = 0x00000000, /* log nothing								 */
	LOG_NOMOD		    = 0x00000000, /*											 */
							
	LOG_ERROR     		= 0x00000001, /* error messages							 */
	LOG_WARN       		= 0x00000002, /* warning messages						 */
	LOG_INFO       		= 0x00000004, /* info messages							 */
	LOG_DEBUG      		= 0x00000008, /* debugging messages						 */
	LOG_TRACE           = 0x00000010, /* tracing messages						 */
	LOG_VERBOSE         = 0x00000020, /* verbose messages						 */
							
	LOG_SERIALIZATION	= 0x00000100, /* debugging the serialization methods		*/
	LOG_MUTEX      		= 0x00000200, /* debugging messages for mutex subsystem	*/
	LOG_KEY        		= 0x00000400, /* debugging messages for key subsystem	*/
	LOG_NETWORK    		= 0x00000800, /* debugging messages for network layer	*/
	LOG_ROUTING    		= 0x00001000, /* debugging the routing table				*/
	LOG_MESSAGE    		= 0x00002000, /* debugging the message subsystem			*/
	LOG_SECURE     		= 0x00004000, /* debugging the security module			*/
	LOG_HTTP       		= 0x00008000, /* debugging the http subsystem			*/
	LOG_AAATOKEN   		= 0x00010000, /* debugging the aaatoken subsystem		*/
	LOG_MEMORY 			= 0x00020000, /* debugging the memory subsystem			*/
	LOG_SYSINFO			= 0x00040000, /* debugging the Sysinfo subsystem     	*/
	LOG_TREE			= 0x00080000, /* debugging the Tree subsystem     		*/
	LOG_THREADS			= 0x00100000, /* debugging the Threads subsystem     	*/
	LOG_MSGPROPERTY		= 0x00200000, /* debugging the Messageproperties     	*/
	LOG_JOBS			= 0x00400000, /* debugging the Jobqueue subsystem     	*/
	LOG_EVENT			= 0x00800000, /* debugging the undefined					*/
	LOG_MISC            = 0x01000000, /* debugging the undefined					*/
	LOG_HANDSHAKE       = 0x02000000, /* debugging the undefined					*/

	LOG_GLOBAL     		= 0x80000000, /* debugging the global system				*/
							
} NP_ENUM NP_API_EXPORT;	
							
#define LOG_MODUL_MASK    0xFFFFFF00 /* filter the module mask */
#define LOG_LEVEL_MASK    0x000000FF /* filter the log level */


NP_API_EXPORT
void _np_log_init (np_state_t* context, const char* filename, uint32_t level);

NP_API_EXPORT
void np_log_setlevel(np_state_t* context, uint32_t level);

NP_API_EXPORT
void np_log_destroy (np_state_t* context);

NP_API_INTERN
void _np_log_fflush(np_state_t* context, bool force);

#ifndef SWIG
NP_API_EXPORT
void np_log_message(np_state_t* context, uint32_t level,
					const char* srcFile, const char* funcName,
					uint16_t lineno, const char* msg, ...)
	 //TODO: add context? __attribute__((__format__ (__printf__, 5,6) ))
	;
#endif

#ifndef log_msg
	#define log_msg(level, msg, ...) \
		 np_log_message(context, level, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)
#endif

#ifndef log_debug_msg
	#ifdef DEBUG	
		#define log_debug_msg(level, msg, ...) \
				 np_log_message(context, level | LOG_DEBUG, __FILE__, FUNC, __LINE__, msg, ##__VA_ARGS__)	
	#else
		#define log_debug_msg(level, msg, ...)
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


#endif /* _NP_LOG_H_ */
