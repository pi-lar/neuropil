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

#include "np_event.h"
#include "np_jobqueue.h"
#include "np_legacy.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_settings.h"
#include "np_util.h"


typedef struct np_log_s
{
    char filename_ext[16];
    char original_filename[256];
    char filename[256];
    int fp;
    // FILE *fp;
    uint32_t level;
    np_sll_t(char_ptr, logentries_l);
    ev_periodic watcher;
    uint32_t log_size;
    uint32_t log_count;
    bool log_rotate;

} np_log_t;

typedef struct log_str_t { const char* text; int log_code; } log_str_t;


np_module_struct(log) {
    np_state_t* context;
    np_log_t*   __logger;
    pthread_mutex_t     __log_mutex;
    pthread_mutexattr_t __log_mutex_attr;
};

void _np_log_evflush(struct ev_loop* loop, NP_UNUSED ev_periodic* ev, int event_type) {
    if ( FLAG_CMP(event_type, EV_WRITE) ) {
            _np_log_fflush((np_context*) ev_userdata(loop), false);
    }
}

void log_rotation(np_state_t* context)
{
    pthread_mutex_lock(&np_module(log)->__log_mutex);

    np_module(log)->__logger->log_size = 0;
    np_module(log)->__logger->log_count += 1;

    int log_id = (np_module(log)->__logger->log_count % LOG_ROTATE_COUNT) ;
    if(log_id == 0) {
        log_id = LOG_ROTATE_COUNT;
    }

    char* old_filename = strdup(np_module(log)->__logger->filename);

    // create new filename
    if(np_module(log)->__logger->log_rotate){
         snprintf (np_module(log)->__logger->filename, 255, "%s_%d%s", np_module(log)->__logger->original_filename, log_id, np_module(log)->__logger->filename_ext );
    } else {
         snprintf (np_module(log)->__logger->filename, 255, "%s%s", np_module(log)->__logger->original_filename, np_module(log)->__logger->filename_ext );
    }

    // Closing old file
    if(np_module(log)->__logger->log_count > 1) {
        log_msg(LOG_INFO, "Continuing log in file %s now.", np_module(log)->__logger->filename);
        _np_log_fflush(context, true);
        if(close(np_module(log)->__logger->fp) != 0) {
            fprintf(stderr,"Could not close old logfile %s. Error: %s (%d)", old_filename, strerror(errno), errno);
            fflush(NULL);
        }
    }

    // setting up new file
    if(np_module(log)->__logger->log_rotate){
        unlink(np_module(log)->__logger->filename);
    }
    np_module(log)->__logger->fp = open(np_module(log)->__logger->filename, O_WRONLY | O_APPEND | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP);

    if(np_module(log)->__logger->fp < 0) {
        fprintf(stderr,"Could not create logfile at %s. Error: %s (%d)", np_module(log)->__logger->filename, strerror(errno), errno);
        fprintf(stderr, "Log will no longer continue");
        fflush(NULL);
        // discontinue new log msgs
        free(np_module(log)->__logger);
        np_module(log)->__logger = NULL;
    }

    if (np_module(log)->__logger->log_count > LOG_ROTATE_COUNT) {
        log_msg(LOG_INFO, "Continuing log from file %s. This is the %"PRIu32" iteration of this file.", old_filename, np_module(log)->__logger->log_count / LOG_ROTATE_COUNT);
    }

    _np_log_fflush(context, true);
    free(old_filename);
    pthread_mutex_unlock(&np_module(log)->__log_mutex);	
}

void _np_log_rotate(np_state_t* context, bool force)
{
    if(np_module(log)->__logger->log_size >= LOG_ROTATE_AFTER_BYTES || force == true) {
        log_rotation(context);
    }
}
/*
    buffer may be at least 12 char wide
*/
char * get_level_str(enum np_log_e level, char * buffer) {
    
    char ret[12] = { 0 };

    if (FLAG_CMP(level, LOG_ERROR)) {
        sprintf(ret, "ERROR");
    }
    else if (FLAG_CMP(level, LOG_WARN)) {
        sprintf(ret, "WARNING");
    }
    else if (FLAG_CMP(level, LOG_INFO)) {
        sprintf(ret, "INFO");
    }
    else if (FLAG_CMP(level, LOG_TRACE)) {
        sprintf(ret, "TRACE");
    }

    // mark debug entry 
    if (FLAG_CMP(level, LOG_DEBUG)) {
        if (ret[0] == 0) {
            sprintf(ret, "DEBUG");
        }
        else {
            sprintf(ret, "%s_D", ret);
        }
    }
    // mark verbose entry
    /*if (FLAG_CMP(level, LOG_VERBOSE)) {		
        sprintf(ret, "%s_V", ret);
    }
    */
    snprintf(buffer, 12, "%-11s", ret);

    return buffer;
}

void np_log_message(np_state_t* context, enum np_log_e level, const char* srcFile, const char* funcName, uint16_t lineno, const char* msg, ...)
{
    if (np_module(log)->__logger == NULL) {
        return;
    }
    // include msg if log level is included into selected levels
    // and if the msg has a category and is included into selected categories
    // or if no category is provided for msg or the log level contains the LOG_GLOBAL flag
    if ((level & LOG_LEVEL_MASK & np_module(log)->__logger->level) > LOG_NONE &&
        (
            (level & LOG_MODUL_MASK & np_module(log)->__logger->level) > LOG_NONE ||
            (np_module(log)->__logger->level & LOG_MODUL_MASK & LOG_GLOBAL) == LOG_GLOBAL ||
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
        char tmp_buffer[20];
        strftime(prefix, 80, "%Y-%m-%d %H:%M:%S", &local_time);
        int new_log_entry_length = strlen(prefix);
        snprintf(prefix + new_log_entry_length, LOG_ROW_SIZE - new_log_entry_length,
            ".%06d %-15lu %15.15s:%-5hd %-25.25s %5s ",
            millis, (unsigned long)pthread_self(),
            srcFile, lineno, funcName,
            get_level_str(level & LOG_LEVEL_MASK, tmp_buffer));

        static const char* suffix = "\n";

        char* log_msg=NULL;
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

        if (0 == pthread_mutex_lock(&np_module(log)->__log_mutex))
        {
            sll_append(char_ptr, np_module(log)->__logger->logentries_l, new_log_entry);
            pthread_mutex_unlock(&np_module(log)->__log_mutex);
        }

        // instant writeout
        if ((level & LOG_ERROR) == LOG_ERROR) {
            _np_log_fflush(context, true);
        }
#ifdef DEBUG
        else {
            _np_log_fflush(context, true);
        }
#endif // DEBUG
        
    }
}

void _np_log_fflush(np_state_t* context, bool force)
{
    //log_trace_msg(LOG_TRACE, "start: void _np_log_fflush(){");
    char* entry = NULL;
    int lock_result = 0;
    if (np_module(log)->__logger == NULL) {
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
            lock_result = pthread_mutex_lock(&np_module(log)->__log_mutex);
        }
        else {
            lock_result = pthread_mutex_trylock(&np_module(log)->__log_mutex);
        }

        if (0 == lock_result) {
            if (flush_status < 1 ) {
                if (flush_status < 0) {
                    flush_status = (force == true || sll_size(np_module(log)->__logger->logentries_l) > 100) ? 0 : 1;
                }
                if(flush_status == 0) {
                    entry = sll_head(char_ptr, np_module(log)->__logger->logentries_l);
                    if (NULL != entry) {
                        np_module(log)->__logger->log_size += strlen(entry);
                    }
                }				
            }
            pthread_mutex_unlock(&np_module(log)->__log_mutex);
        }

        if (NULL != entry)
        {
            uint32_t bytes_witten = 0;

            while(bytes_witten  != strlen(entry))
            {
                int current_bytes_witten = write(np_module(log)->__logger->fp, entry + bytes_witten, strlen(entry) - bytes_witten);
                // if we write was not successful we reschedule the entry
                // and break free from this iteration
                if(current_bytes_witten < 0)
                {
                     pthread_mutex_lock(&np_module(log)->__log_mutex);
                     sll_append(char_ptr, np_module(log)->__logger->logentries_l, entry);
                     pthread_mutex_unlock(&np_module(log)->__log_mutex);
                     break;
                }
                bytes_witten += current_bytes_witten;
            }	

            if(np_module(log)->__logger->log_rotate == true)
                _np_log_rotate(context, false);

            if(bytes_witten  == strlen(entry))
            {
                free(entry);
                entry = NULL;
            }
        }
        else {
            flush_status = 1;
        }
        i++;
    } while (flush_status == 0 && i <= MISC_LOG_FLUSH_MAX_ITEMS);
}

void np_log_setlevel(np_state_t* context, uint32_t level)
{
    log_trace_msg(LOG_TRACE, "start: void np_log_setlevel(uint32_t level){");
    np_module(log)->__logger->level = level;
}


void _np_log_init(np_state_t* context, const char* filename, uint32_t level)
{
    if (!np_module_initiated(log)) {        
        np_module_malloc(log);		 
        pthread_mutex_init(&_module->__log_mutex, NULL);

        pthread_mutexattr_init(&_module->__log_mutex_attr);
        pthread_mutexattr_settype(&_module->__log_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
        pthread_mutex_init(&_module->__log_mutex, &_module->__log_mutex_attr);

        np_log_t* __logger = (np_log_t *)calloc(1, sizeof(np_log_t));
        CHECK_MALLOC(__logger);

        // init logsystem
        __logger->level = level;
        __logger->log_count = 0;
        __logger->log_size = UINT32_MAX; // for initial log_rotation start
        __logger->log_rotate = LOG_ROTATE_ENABLE;

        // detect filename_ext from filename (. symbol)
        char* parsed_filename = filename;
        int len_f = strlen(parsed_filename);
        for (int i = len_f; i >= 0; i--) {
            if (strncmp((parsed_filename + i), ".", 1) == 0)
            {
                // found extension
                snprintf(__logger->filename_ext, len_f - i + 1, "%s", parsed_filename + i);
                parsed_filename = strndup(parsed_filename, i);
                break;
            }
        }

        if (strncmp(__logger->filename_ext, "", 1) == 0)
        {
            snprintf(__logger->filename_ext, 15, ".log");
        }

        snprintf(__logger->original_filename, 255, "%s", parsed_filename);
        snprintf(__logger->filename, 255, "%s%s", parsed_filename, __logger->filename_ext);
        free(parsed_filename);

        sll_init(char_ptr, __logger->logentries_l);        
        _module->__logger = __logger;
        log_rotation(context);
        log_debug_msg(LOG_DEBUG, "initialized log system %p: %s / %x", __logger, __logger->filename, __logger->level);
    }
}

void np_log_destroy(np_state_t* context)
{
    log_trace_msg(LOG_TRACE, "start: void np_log_destroy(){");
    np_module(log)->__logger->level=LOG_NONE;

    EV_P = _np_event_get_loop_io(context);
    ev_periodic_stop(EV_A_ &np_module(log)->__logger->watcher);

    _np_log_fflush(context, true);

    close(np_module(log)->__logger->fp);
    free(np_module(log)->__logger);
    np_module(log)->__logger = NULL;
    pthread_mutex_destroy(&np_module(log)->__log_mutex);
}

