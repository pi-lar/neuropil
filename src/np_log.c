/*
 */
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"

#include "np_list.h"

#include <sys/time.h>
#include <time.h>

NP_SLL_GENERATE_PROTOTYPES(char);
NP_SLL_GENERATE_IMPLEMENTATION(char);

typedef struct np_log_s
{
	char filename[256];
	int fp;
	// FILE *fp;
	uint16_t level;
	np_sll_t(char, logentries_l);
	ev_io watcher;
} np_log_t;

typedef struct log_str_t { const char* text; int log_code; } log_str_t;
// TODO: ugly, but works. clean it up
log_str_t __level_str[] = {
		{NULL   , 0x0000 },
		{"ERROR", 0x0001 },         /* error messages     */
		{"WARN_", 0x0002 },			/* warning messages   */
		{NULL   , 0x0003 },			/* none messages      */
		{"INFO_", 0x0004 },			/* info messages      */
		{NULL   , 0x0005 },			/* none messages      */
		{NULL   , 0x0006 },			/* none messages      */
		{NULL   , 0x0007 },			/* none messages      */
		{"DEBUG", 0x0008 },			/* debugging messages */
		{NULL   , 0x0009 },			/* none messages      */
		{NULL   , 0x000a },			/* none messages      */
		{NULL   , 0x000b },			/* none messages      */
		{NULL   , 0x000c },			/* none messages      */
		{NULL   , 0x000d },			/* none messages      */
		{NULL   , 0x000e },			/* none messages      */
		{NULL   , 0x000f },			/* none messages      */
		{"TRACE", 0x0010 }			/* tracing messages   */
};

static np_log_t* logger;
static pthread_mutex_t __log_mutex = PTHREAD_MUTEX_INITIALIZER;

void np_log_message(uint16_t level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...)
{
	if ( (level & LOG_NOMOD_MASK ) > 0)
		if ( (level & logger->level & LOG_MODUL_MASK) == 0 )
			return;

	if ( (level & logger->level & LOG_LEVEL_MASK) > LOG_NONE)
	{
  	    char* new_log_entry = malloc(sizeof(char)*1124);
  	    int wb = 0;
		struct timeval tval;
		struct tm local_time;
		gettimeofday(&tval, (struct timezone*)0);
		int32_t millis = tval.tv_usec;
		localtime_r(&tval.tv_sec, &local_time);

		wb  = strftime(new_log_entry, 80, "%Y-%m-%d %H:%M:%S", &local_time);
		wb += snprintf(new_log_entry+wb, 1124-wb,
	    				   ".%06d %-15lu %15.15s:%-5hd %-25.25s _%5s_ ",
	    				   millis, (unsigned long) pthread_self(),
						   srcFile, lineno, funcName,
						   __level_str[level & LOG_LEVEL_MASK].text);
		va_list ap;
		va_start (ap, msg);
		wb += vsnprintf (new_log_entry+wb, 1124-wb, msg, ap);
		va_end(ap);
		snprintf(new_log_entry+wb, 1124-wb, "\n");

//		pthread_mutex_lock(&__log_mutex);
//	    sll_append(char, logger->logentries_l, new_log_entry);
//		pthread_mutex_unlock(&__log_mutex);

		pthread_mutex_lock(&__log_mutex);
		write(logger->fp, new_log_entry, strlen(new_log_entry));
		// fprintf(logger->fp, "%s\n", new_log_entry);
		// fflush(logger->fp);
		pthread_mutex_unlock(&__log_mutex);
		free (new_log_entry);
	}
	else
	{
		// printf("not logging to file(%p): %d & %d = %d\n", logger, level, logger->level, level & logger->level);
	}
}

void _log_evflush(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_io *event, int revents)
{
	if (revents & EV_WRITE)
	{
		_np_log_fflush();
	}
}

void _np_log_fflush()
{
	char* entry = NULL;
	do
	{
		pthread_mutex_lock(&__log_mutex);
		entry = sll_head(char, logger->logentries_l);
		pthread_mutex_unlock(&__log_mutex);

		if (NULL != entry)
		{
			write(logger->fp, entry, strlen(entry));
			free(entry);
		}

	} while(NULL != entry);
}

void np_log_setlevel(uint16_t level)
{
    logger->level = level;
}

void np_log_init(const char* filename, uint16_t level)
{
	logger = (np_log_t *) malloc(sizeof(np_log_t));

    snprintf (logger->filename, 255, "%s", filename);
	// logger->fp = fopen(logger->filename, "a"); // "a"
	logger->fp = open(logger->filename, O_WRONLY | O_APPEND | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP); // "a"
    logger->level = level;

    sll_init(char, logger->logentries_l);
    char* new_log_entry = malloc(sizeof(char)*256);
    snprintf(new_log_entry, 255, "initialized log system %p: %s / %x", logger, logger->filename, logger->level);
    np_log_message(LOG_DEBUG, __FILE__, __func__, __LINE__, "%s", new_log_entry);

    // fprintf(logger->fp, "initialized log system %p: %s (%p) %d\n", logger, logger->filename, logger->fp, logger->level);
    // sll_append(char, logger->logentries_l, new_log_entry);
    // fflush(logger->fp);

    // _np_suspend_event_loop();
    EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_init(&logger->watcher, _log_evflush, logger->fp, EV_WRITE);
	ev_io_start(EV_A_ &logger->watcher);
	// _np_resume_event_loop();
}

void np_log_destroy()
{
	logger->level=LOG_NONE;

    EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_stop(EV_A_ &logger->watcher);

	_np_log_fflush();

	close(logger->fp);
	free(logger);
}

