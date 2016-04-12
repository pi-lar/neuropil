/** copyright 2015 pi-lar GmbH
 **/
#ifndef _NP_LOG_H_
#define _NP_LOG_H_

#include "stdio.h"

#include "np_container.h"

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
	LOG_NONE  = 0x0000,			/* log nothing        */

	LOG_ERROR = 0x0001,			/* error messages     */
    LOG_WARN  = 0x0002,			/* warning messages   */
    LOG_INFO  = 0x0004,			/* info messages      */
    LOG_DEBUG = 0x0008,			/* debugging messages */
    LOG_TRACE = 0x0010,			/* tracing messages   */

	LOG_LEVEL_MASK = 0x00FF,			/*  */

	LOG_NOMOD    = 0x0000,	/*           */
	LOG_KEY      = 0x0100,	/* debugging messages for key subsystem */
    LOG_NETWORK  = 0x0200,	/* debugging messages for network layer */
    LOG_ROUTING  = 0x0400,	/* debugging the routing table          */
    LOG_MESSAGE  = 0x0800,	/* debugging the message subsystem      */
    LOG_SECURE   = 0x1000,	/* debugging the security module        */
    LOG_HTTP     = 0x2000,	/* debugging the message subsystem      */
    LOG_AAATOKEN = 0x4000,	/* debugging the message subsystem      */
    LOG_GLOBAL   = 0x8000,	/* debugging the global system          */

	LOG_MODUL_MASK = 0xFF00,	/* debugging the global system          */
	LOG_NOMOD_MASK = 0x7F00,	/* debugging the global system          */
};

void log_message(uint16_t level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...);

#define log_msg(level, msg, ...) log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)

// #define log_msg(level, msg, ...) \
// { \
// if ( (level & logger->level) > LOG_NONE) { \
// log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__) \
// }

void log_init (const char* filename, uint16_t level);
void log_destroy ();
// LOG* log_get ();
void log_fflush();


#endif /* _NP_LOG_H_ */
