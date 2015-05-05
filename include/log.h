/*
** $Id: log.h,v 1.14 2006/06/16 07:55:37 ravenben Exp $
**
** Matthew Allen
** description: 
*/

/* define this to be 0 for no logging, 1 for logging */
#define LOGS 0

#ifndef _CHIMERA_LOG_H_
#define _CHIMERA_LOG_H_

typedef struct np_log_t {
	char filename[256];
	FILE *fp;
	int level;
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
    LOG_ROUTING=128,			/* debugging the routing table (none) */
    LOG_SECUREDEBUG=256,	/* for security module (none) */
    LOG_DATA=512,			/* for measurement and analysis (none) */
    LOG_COUNT=1024			/* count of log message types */
};

// #define log_msg(level, msg)      fprintf(stdout, "%s:%s:%d ## %d ## %d # %s\n",      __FILE__, __func__, __LINE__, level, getpid(), msg)
// size_t fwrite(const void *ptr, size_t size_of_elements, size_t number_of_elements, FILE *a_file);
// #define log_msg(level, msg, ...)
//  		fprintf(logger.fp, "%s:%s:%d ## %d ## %d # " msg "\n", __FILE__, __func__, __LINE__, level, getpid(), ##__VA_ARGS__)


void log_message(int level, const char* srcFile, const char* funcName, int lineno, const char* msg, ...);

#define log_msg(level, msg, ...) log_message(level, __FILE__, __func__, __LINE__, msg, ##__VA_ARGS__)

void log_init (const char* filename, int level);
void log_destroy ();
LOG* log_get ();

// void log_msg(int level, char* msg, ...);
// void log_msg(int type, char *format, ...);
// void *log_init ();
// void log_message (void *logs, int type, char *format, ...);
void log_direct (void *logs, int type, FILE * fp);

#endif /* _CHIMERA_LOG_H_ */
