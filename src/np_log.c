//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <time.h>
#include <inttypes.h>

#include "event/ev.h"
#include "pthread.h"

#include "np_log.h"

#include "np_list.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_event.h"
//#include "np_types.h"
#include "np_settings.h"

typedef struct np_log_s
{
	char filename_ext[16];
	char original_filename[256];
	char filename[256];
	int fp;
	// FILE *fp;
	uint32_t level;
	np_sll_t(char_ptr, logentries_l);
	ev_io watcher;
	uint32_t log_size;
	uint32_t log_count;
	np_bool log_rotate;

} np_log_t;

typedef struct log_str_t { const char* text; int log_code; } log_str_t;
// TODO: ugly, but works. clean it up
log_str_t __level_str[] = {
		{NULL   , 0x00000 },
		{"ERROR", LOG_ERROR },					/* error messages				*/
		{"WARN", LOG_WARN	},					/* warning messages				*/
		{NULL   , 0x00003	},					/* none messages				*/
		{"INFO", 0x00004	},					/* info messages				*/
		{NULL   , 0x00005	},					/* none messages				*/
		{NULL   , 0x00006	},					/* none messages				*/
		{NULL   , 0x00007	},					/* none messages				*/
		{"DEBUG", LOG_DEBUG },					/* debugging messages			*/
		{"ERROR_D", LOG_ERROR | LOG_DEBUG },	/* debugging error messages		*/
		{"WARN_D",  LOG_WARN  | LOG_DEBUG },	/* debugging warning messages	*/
		{NULL   , 0x0000b	},					/* none messages				*/
		{"INFO_D",  LOG_INFO  | LOG_DEBUG },	/* debugging info messages		*/
		{NULL   , 0x0000d	},					/* none messages				*/
		{NULL   , 0x0000e	},					/* none messages				*/
		{NULL   , 0x0000f	},					/* none messages				*/
		{"TRACE", LOG_TRACE },					/* trace messages				*/


};

static np_log_t* __logger = NULL;
static pthread_mutex_t __log_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutexattr_t __log_mutex_attr;


void _np_log_evflush(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_io *event, int revents)
{
	log_trace_msg(LOG_TRACE, "start: void _np_log_evflush(NP_UNUSED struct ev_loop *loop, NP_UNUSED ev_io *event, int revents){");
	if ((revents &  EV_WRITE) == EV_WRITE && (revents &  EV_ERROR) != EV_ERROR)
	{
		_np_log_fflush(FALSE);
	}
}

void log_rotation()
{
	pthread_mutex_lock(&__log_mutex);
	if(__logger->log_size >= LOG_ROTATE_AFTER_BYTES)
	{
		__logger->log_size = 0;

		__logger->log_count++;
		int log_id = (__logger->log_count % LOG_ROTATE_COUNT) ;
		if(log_id == 0) {
			log_id = LOG_ROTATE_COUNT;
		}

		// Closing old file
		char* old_filename = strdup(__logger->filename);
		if(__logger->log_count > 1) {
			if(close(__logger->fp) != 0) {
				fprintf(stderr,"Could not close old logfile %s. Error: %s (%d)", old_filename, strerror(errno), errno);
				fflush(NULL);
			}
		}

		// set up new filename
		if(__logger->log_rotate){
			snprintf (__logger->filename, 255, "%s_%d%s", __logger->original_filename, log_id, __logger->filename_ext );
		} else {
			snprintf (__logger->filename, 255, "%s%s", __logger->original_filename, __logger->filename_ext );
		}
		// creation of new file
		if(__logger->log_rotate) {
			// unlink a possibly already existing file
			unlink(__logger->filename);
		}
		// open the new log file
		__logger->fp = open(__logger->filename, O_WRONLY | O_APPEND | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP);
		// check
		if(__logger->fp < 0) {
			fprintf(stderr,"Could not create logfile at %s. Error: %s (%d)",__logger->filename, strerror(errno), errno);
			fprintf(stderr, "Log will no longer continue");
			fflush(NULL);
			// discontinue new log msgs
		    free(__logger);
		    __logger = NULL;
		}
		else
		{
			// _np_suspend_event_loop_io();
			EV_P = _np_event_get_loop_io();
			ev_io_stop(EV_A_ &__logger->watcher);
			ev_io_init(&__logger->watcher, _np_log_evflush, __logger->fp, EV_WRITE);
			ev_io_start(EV_A_ &__logger->watcher);
			// _np_resume_event_loop_io();
		}

		if (__logger->log_count > LOG_ROTATE_COUNT) {
			char rollover_text[128];
			sprintf(rollover_text, "Continuing log from file %s. This is the %"PRIu32" iteration of this file.\n", old_filename, __logger->log_count / LOG_ROTATE_COUNT);
			write(__logger->fp, rollover_text, strlen(rollover_text));
		}
		// cleanup
		free(old_filename);
	}
	pthread_mutex_unlock(&__log_mutex);
}

void np_log_message(uint32_t level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...)
{
	if (__logger == NULL) {
		return;
	}
	// include msg if log level is included into selected levels
	// and if the msg has acategory and is included into selected categories
	// or if no category is provided for msg or the log level contains the LOG_GLOBAL flag
	if ((level & LOG_LEVEL_MASK & __logger->level) > LOG_NONE &&
		(
			(level & LOG_MODUL_MASK & __logger->level) > LOG_NONE ||
			(__logger->level & LOG_MODUL_MASK & LOG_GLOBAL) == LOG_GLOBAL ||
			(level & LOG_MODUL_MASK) == LOG_NONE
		)
	)
	{
		struct timeval tval;
		struct tm local_time;
		gettimeofday(&tval, (struct timezone*)0);
		int32_t millis = tval.tv_usec;
		localtime_r(&tval.tv_sec, &local_time);

		char* prefix = malloc(sizeof(char)*LOG_ROW_SIZE);
		CHECK_MALLOC(prefix);

		strftime(prefix, 80, "%Y-%m-%d %H:%M:%S", &local_time);
		int new_log_entry_length = strlen(prefix);
		snprintf(prefix + new_log_entry_length, LOG_ROW_SIZE - new_log_entry_length,
			".%06d %-15lu %15.15s:%-5hd %-25.25s _%5s_ ",
			millis, (unsigned long)pthread_self(),
			srcFile, lineno, funcName,
			__level_str[level & LOG_LEVEL_MASK].text);

		static const char* suffix = "\n";

		char* log_msg;
		va_list ap;
		va_start(ap, msg);
		vasprintf(&log_msg, msg, ap);
		va_end(ap);

		char* new_log_entry;
		asprintf(&new_log_entry, "%s %s%s", prefix, log_msg, suffix);
		free(prefix);
		free(log_msg);


#if defined(CONSOLE_LOG) && CONSOLE_LOG == 1
		fprintf(stdout, new_log_entry);
		fprintf(stdout, "/n");
#endif

		if (0 == pthread_mutex_lock(&__log_mutex))
		{
			sll_append(char_ptr, __logger->logentries_l, new_log_entry);
			pthread_mutex_unlock(&__log_mutex);
		}

		// instant writeout
		if ((level & LOG_ERROR) == LOG_ERROR) {
			_np_log_fflush(TRUE);
		}
#ifdef DEBUG
		else {
			_np_log_fflush(FALSE);
		}
#endif // DEBUG
	}
}

void _np_log_fflush(np_bool force)
{
	//log_trace_msg(LOG_TRACE, "start: void _np_log_fflush(){");
	char* entry = NULL;
	int lock_result = 0;
	if (__logger == NULL) {
		return;
	}

	/*
		-1 = evaluate the status on first lock
		 0 = log till no entries are available anymore
		 1 = discontinue the flush
	*/
	int flush_status= -1;
	uint32_t i = 0;
	do
	{
		if (force) {
			lock_result = pthread_mutex_lock(&__log_mutex);
		}
		else {
			lock_result = pthread_mutex_trylock(&__log_mutex);
		}

		if (0 == lock_result) {
			if (flush_status < 1 ) {
				// check force flag or amount of messages in list
				if (flush_status < 0) {
					flush_status = (force == TRUE || sll_size(__logger->logentries_l) > 10) ? 0 : 1;
				}
				// if status is zero, get the topmost entry
				if(flush_status == 0){
					entry = sll_head(char_ptr, __logger->logentries_l);
				}
			}
			pthread_mutex_unlock(&__log_mutex);
		}

		if (NULL != entry)
		{
			pthread_mutex_lock(&__log_mutex);

			// write log entry to log file
			uint32_t bytes_witten = 0;
			while(bytes_witten  != strlen(entry))
			{
				int current_bytes_witten = write(__logger->fp, entry + bytes_witten, strlen(entry) - bytes_witten);
				// if we write was not successful we reschedule the entry
				// and break free from this iteration
				if(current_bytes_witten < 0)
				{
					 sll_append(char_ptr, __logger->logentries_l, entry);
					 break;
				} else {
					bytes_witten += current_bytes_witten;
				}
			}

			if( bytes_witten == strlen(entry))
			{
				free(entry);
				entry = NULL;
			}
			__logger->log_size += bytes_witten;

			if(__logger->log_rotate == TRUE)
				log_rotation();

			pthread_mutex_unlock(&__log_mutex);
		}
		else {
			// no more log entries
			flush_status = 1;
		}
		i++;
	} while (flush_status == 0 && i <= MISC_LOG_FLUSH_MAX_ITEMS);
}

void np_log_setlevel(uint32_t level)
{
	log_trace_msg(LOG_TRACE, "start: void np_log_setlevel(uint32_t level){");
	__logger->level = level;
}

void np_log_init(const char* filename, uint32_t level)
{
	pthread_mutexattr_init(&__log_mutex_attr);
	pthread_mutexattr_settype(&__log_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&__log_mutex, &__log_mutex_attr);

	__logger = (np_log_t *) calloc(1, sizeof(np_log_t));
	CHECK_MALLOC(__logger);

	// init logsystem
	__logger->level = level;
	__logger->log_count = 0;
	__logger->log_size = UINT32_MAX; // for initial log_rotation start
	__logger->log_rotate = LOG_ROTATE_ENABLE;

	// detect filename_ext from filename (. symbol)
	char* parsed_filename = filename;
	int len_f = strlen(parsed_filename);
	for(int i= len_f; i >= 0;i--) {
		if(strncmp((parsed_filename + i) ,".",1) == 0)
		{
			// found extension
			snprintf (__logger->filename_ext, len_f-i+1, "%s",parsed_filename+i);
			parsed_filename = strndup(parsed_filename, i);
			break;
		}
	}

	if(strncmp(__logger->filename_ext, "", 1) == 0)
	{
		snprintf (__logger->filename_ext, 15, ".log");
	}

	snprintf (__logger->original_filename, 255, "%s", parsed_filename );
	snprintf (__logger->filename, 255, "%s%s", parsed_filename,__logger->filename_ext );
	free(parsed_filename);

	sll_init(char_ptr, __logger->logentries_l);
	log_rotation();

	log_debug_msg(LOG_DEBUG, "initialized log system %p: %s / %x", __logger, __logger->filename, __logger->level);
}

void np_log_destroy()
{
	log_trace_msg(LOG_TRACE, "start: void np_log_destroy(){");
	__logger->level=LOG_NONE;

	EV_P = _np_event_get_loop_io();
	ev_io_stop(EV_A_ &__logger->watcher);

	_np_log_fflush(TRUE);

	close(__logger->fp);
	free(__logger);
	__logger = NULL;

	pthread_mutex_destroy(&__log_mutex);
}
