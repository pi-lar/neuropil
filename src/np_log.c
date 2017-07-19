//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"

#include "np_list.h"
#include "np_memory.h"

#include <sys/time.h>
#include <time.h>

NP_SLL_GENERATE_PROTOTYPES(char);
NP_SLL_GENERATE_IMPLEMENTATION(char);

typedef struct np_log_s
{
	char filename[256];
	int fp;
	// FILE *fp;
	uint32_t level;
	np_sll_t(char, logentries_l);
	ev_io watcher;
} np_log_t;

typedef struct log_str_t { const char* text; int log_code; } log_str_t;
// TODO: ugly, but works. clean it up
log_str_t __level_str[] = {
		{NULL   , 0x00000 },
		{"ERROR", 0x00001 },            /* error messages     */
		{"WARN_", 0x00002 },			/* warning messages   */
		{NULL   , 0x00003 },			/* none messages      */
		{"INFO_", 0x00004 },			/* info messages      */
		{NULL   , 0x00005 },			/* none messages      */
		{NULL   , 0x00006 },			/* none messages      */
		{NULL   , 0x00007 },			/* none messages      */
		{"DEBUG", 0x00008 },			/* debugging messages */
		{NULL   , 0x00009 },			/* none messages      */
		{NULL   , 0x0000a },			/* none messages      */
		{NULL   , 0x0000b },			/* none messages      */
		{NULL   , 0x0000c },			/* none messages      */
		{NULL   , 0x0000d },			/* none messages      */
		{NULL   , 0x0000e },			/* none messages      */
		{NULL   , 0x0000f },			/* none messages      */
		{"TRACE", 0x00010 }			    /* trace messages   */
};

static np_log_t* logger = NULL;
static pthread_mutex_t __log_mutex = PTHREAD_MUTEX_INITIALIZER;


void np_log_message(uint32_t level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...)
{
	if(logger == NULL){
		return;
	}
	// filter if a module log entry is wanted
	if ( LOG_NONE < (level & LOG_MODUL_MASK) )
		// if a module log entry is wanted, is it in the configured log mask ?
		if ( LOG_NONE == (level & LOG_MODUL_MASK & logger->level) )
			// not found, nothing to do
			return;

	// next check if the log level (debug, error, ...) is set
	if ( (level & LOG_LEVEL_MASK & logger->level) > LOG_NONE)
	{
  	    char* new_log_entry = malloc(sizeof(char)*1124);
		CHECK_MALLOC(new_log_entry);

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

#ifdef CONSOLE_LOG && CONSOLE_LOG == 1
		fprintf(stdout, new_log_entry);
		fprintf(stdout, "/n");
#endif
		 pthread_mutex_lock(&__log_mutex);
		 sll_append(char, logger->logentries_l, new_log_entry);
		 //write(logger->fp, new_log_entry, strlen(new_log_entry));
		 //fflush(NULL);
		 // fsync(logger->fp);
		 pthread_mutex_unlock(&__log_mutex);

		 // instant writeout
		 _np_log_fflush();
	}
	else
	{
		// printf("not logging to file(%p): %d & %d = %d\n", logger, level, logger->level, level & logger->level);
	}
}

void _np_log_evflush(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_io *event, int revents)
{
    log_msg(LOG_TRACE, "start: void _np_log_evflush(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_io *event, int revents){");
	if ((revents &  EV_WRITE) == EV_WRITE && (revents &  EV_ERROR) != EV_ERROR)
	{
		_np_log_fflush();
	}
}

void _np_log_fflush()
{
    log_msg(LOG_TRACE, "start: void _np_log_fflush(){");
	char* entry = NULL;

	if(0 == pthread_mutex_trylock(&__log_mutex)) {
		entry = sll_head(char, logger->logentries_l);
		pthread_mutex_unlock(&__log_mutex);
	}

	if (NULL != entry)
	{
		if( 0 >= write(logger->fp, entry, strlen(entry))){
			 pthread_mutex_lock(&__log_mutex);
			 sll_append(char, logger->logentries_l, entry);
			 pthread_mutex_unlock(&__log_mutex);

		} else	{
			free(entry);
		}
	}
}

void np_log_setlevel(uint32_t level)
{
    log_msg(LOG_TRACE, "start: void np_log_setlevel(uint32_t level){");
    logger->level = level;
}

void np_log_init(const char* filename, uint32_t level)
{
    log_msg(LOG_TRACE, "start: void np_log_init(const char* filename, uint32_t level){");
    np_log_t* logsys = (np_log_t *) malloc(sizeof(np_log_t));
	CHECK_MALLOC(logsys);


    snprintf (logsys->filename, 255, "%s", filename);
    logsys->fp = open(logsys->filename, O_WRONLY | O_APPEND | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP);
	if(logsys->fp < 0) {
		fprintf(stderr,"Could not create logfile at %s. Error: %s (%d)",logsys->filename, strerror(errno), errno);
		fflush(NULL);
		exit(EXIT_FAILURE);
	}
	logsys->level = level;

    sll_init(char, logsys->logentries_l);
    char* new_log_entry = malloc(sizeof(char)*256);
	CHECK_MALLOC(new_log_entry);

    snprintf(new_log_entry, 255, "initialized log system %p: %s / %x", logsys, logsys->filename, logsys->level);
    np_log_message(LOG_DEBUG, __FILE__, __func__, __LINE__, "%s", new_log_entry);

    // fprintf(logger->fp, "initialized log system %p: %s (%p) %d\n", logger, logger->filename, logger->fp, logger->level);
    // sll_append(char, logger->logentries_l, new_log_entry);
    // fflush(logger->fp);

   //  _np_suspend_event_loop();
    EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_init(&logsys->watcher, _np_log_evflush, logsys->fp, EV_WRITE);

	ev_io_start(EV_A_ &logsys->watcher);
//	_np_resume_event_loop();

	// make available to system
	logger = logsys;
}
void np_log_destroy()
{
    log_msg(LOG_TRACE, "start: void np_log_destroy(){");
	logger->level=LOG_NONE;

    EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_io_stop(EV_A_ &logger->watcher);

	_np_log_fflush();

	close(logger->fp);
	free(logger);
	pthread_mutex_destroy(&__log_mutex);

}

