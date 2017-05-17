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
	LOG_NONE  		    = 0x00000, /* log nothing        */
	LOG_NOMOD		    = 0x00000, /*                    */

	LOG_ERROR     		= 0x00001, /* error messages     */
    LOG_WARN       		= 0x00002, /* warning messages   */
    LOG_INFO       		= 0x00004, /* info messages      */
    LOG_DEBUG      		= 0x00008, /* debugging messages */
    LOG_TRACE      		= 0x00010, /* tracing messages   */

	LOG_LEVEL_MASK      = 0x000FF, /* filter the log level */

	LOG_SERIALIZATION	= 0x00100, /* debugging the serialization methods    */
	LOG_MUTEX      		= 0x00200, /* debugging messages for mutex subsystem */
	LOG_KEY        		= 0x00400, /* debugging messages for key subsystem   */
	LOG_NETWORK    		= 0x00800, /* debugging messages for network layer   */
    LOG_ROUTING    		= 0x01000, /* debugging the routing table            */
    LOG_MESSAGE    		= 0x02000, /* debugging the message subsystem        */
    LOG_SECURE     		= 0x04000, /* debugging the security module          */
    LOG_HTTP       		= 0x08000, /* debugging the http subsystem           */
	LOG_AAATOKEN   		= 0x10000, /* debugging the aaatoken subsystem       */

	LOG_GLOBAL     		= 0x80000, /* debugging the global system            */
	LOG_MODUL_MASK 		= 0x7FF00, /* filter the module mask                 */
	LOG_NOMOD_MASK 		= 0x7FF00, /* filter the module mask                 */

} NP_ENUM NP_API_EXPORT;


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
