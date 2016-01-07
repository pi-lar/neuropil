/** copyright 2015 pi-lar GmbH
 **/
#ifndef _NP_LOG_H_
#define _NP_LOG_H_

#include "stdio.h"

#include "np_container.h"

typedef struct np_log_t {
	char filename[256];
	FILE *fp;
	uint8_t level;
	np_sll_t(char, logentries_l);
    pthread_mutex_t lock;
} LOG;

LOG* logger;

enum
{
	LOG_NONE=0,				/* log nothing */
    LOG_ERROR=1,			/* error messages (stderr) */
    LOG_WARN=2,				/* warning messages (none) */
    LOG_INFO=4,			/* error messages (stderr) */
    LOG_TRACE=8,			/* tracing messages (none) */
    LOG_DEBUG=16,			/* debugging messages (none) */
    LOG_KEYDEBUG=32,		/* debugging messages for key subsystem (none) */
    LOG_NETWORKDEBUG=64,	/* debugging messages for network layer (none) */
    LOG_ROUTING=128,		/* debugging the routing table (none) */
    LOG_SECUREDEBUG=256,	/* for security module (none) */
    LOG_DATA=512,			/* for measurement and analysis (none) */
    LOG_COUNT=1024			/* count of log message types */
};

// #define log_msg(level, msg)      fprintf(stdout, "%s:%s:%d ## %d ## %d # %s\n",      __FILE__, __func__, __LINE__, level, getpid(), msg)
// size_t fwrite(const void *ptr, size_t size_of_elements, size_t number_of_elements, FILE *a_file);
// #define log_msg(level, msg, ...)
//  		fprintf(logger.fp, "%s:%s:%d ## %d ## %d # " msg "\n", __FILE__, __func__, __LINE__, level, getpid(), ##__VA_ARGS__)


void log_message(uint8_t level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...);

#define log_msg(level, msg, ...) log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)

// #define log_msg(level, msg, ...) \
// { \
// if ( (level & logger->level) > LOG_NONE) { \
// log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__) \
// }

void log_init (const char* filename, uint8_t level);
void log_destroy ();
LOG* log_get ();
void log_fflush();


#endif /* _NP_LOG_H_ */
