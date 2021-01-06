//
// neuropil is copyright 2016-2021 by pi-lar GmbH
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
#include "util/np_list.h"
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
    uint32_t log_size;
    uint32_t log_count;
    bool log_rotate;

    ev_io watcher;

} np_log_t;

typedef struct log_str_t { const char* text; int log_code; } log_str_t;

np_module_struct(log) 
{
    np_state_t*   context;
    np_log_t*     __logger;
    np_spinlock_t __log_lock;
};

void _np_log_evflush(struct ev_loop* loop, NP_UNUSED ev_io* ev, int event_type) {
    if ( FLAG_CMP(event_type, EV_WRITE) ) {
        _np_log_fflush((np_context*) ev_userdata(loop), false);
    }
}

void __np_log_close_file(np_log_t* logger){
    if(close(logger->fp) != 0) {
        fprintf(stderr,"Could not close old logfile. Error: %s (%d)", strerror(errno), errno);
        fflush(NULL);
    }
}

void log_rotation(np_state_t* context, bool first_init)
{
    np_log_t* logger = np_module(log)->__logger;

    logger->log_size = 0;
    logger->log_count += 1;

    EV_P = _np_event_get_loop_file(context);
    _np_event_suspend_loop_file(context);
    ev_io_stop(EV_A_ &logger->watcher);

    // Closing old file
    if(!first_init) {
        log_msg(LOG_INFO, "Continuing log in file %s now.", logger->filename);
        _np_log_fflush(context, true);
        __np_log_close_file(logger);
    }

    char* old_filename = strdup(logger->filename);
    np_spinlock_lock(&np_module(log)->__log_lock);
    {
        int log_id = (logger->log_count % LOG_ROTATE_COUNT) ;
        if(log_id == 0) {
            log_id = LOG_ROTATE_COUNT;
        }

        // create new filename
        if(logger->log_rotate) {
            snprintf (logger->filename, 255, "%s_%d%s", logger->original_filename, log_id, logger->filename_ext );
        } else {
            snprintf (logger->filename, 255, "%s%s", logger->original_filename, logger->filename_ext );
        }
        // setting up new file
        if(logger->log_rotate)
        {   // remove old file if it is already present
            unlink(logger->filename);
        }
        logger->fp = open(logger->filename, O_WRONLY | O_APPEND | O_CREAT, S_IREAD | S_IWRITE | S_IRGRP);
    }
    np_spinlock_unlock(&np_module(log)->__log_lock);

    if(logger->fp < 0) {
        fprintf(stderr,"Could not create logfile at %s. Error: %s (%d)", logger->filename, strerror(errno), errno);
        fprintf(stderr, "Log will no longer continue");
        fflush(NULL);
        // discontinue new log msgs
        free(logger);
        logger = NULL;
    } else {
        ev_io_init(&logger->watcher, _np_log_evflush, logger->fp, EV_WRITE);
        ev_io_start(EV_A_ &logger->watcher);
        _np_event_resume_loop_file(context);
        _np_event_reconfigure_loop_file(context);
    }

    if (!first_init) {
        log_msg(LOG_INFO, "Continuing log from file %s. This is the %"PRIu32" iteration of this file.", old_filename, logger->log_count / LOG_ROTATE_COUNT);
    }
    free(old_filename);
}

void _np_log_rotate(np_state_t* context, bool force)
{
    if(np_module(log)->__logger->log_size >= LOG_ROTATE_AFTER_BYTES || force == true) {
        log_rotation(context, false);
    }
}
/*
    buffer may be at least 12 char wide
*/
char * get_level_str(enum np_log_e level, char * buffer) {
    
    char ret[12] = { 0 };

    if (FLAG_CMP(level, LOG_ERROR)) {
        snprintf(ret, 12, "ERROR");
    }
    else if (FLAG_CMP(level, LOG_WARN)) {
        snprintf(ret, 12, "WARNING");
    }
    else if (FLAG_CMP(level, LOG_INFO)) {
        snprintf(ret, 12, "INFO");
    }
    else if (FLAG_CMP(level, LOG_TRACE)) {
        snprintf(ret, 12, "TRACE");
    }

    // mark debug entry 
    if (FLAG_CMP(level, LOG_DEBUG)) {
        if (ret[0] == 0) {
            snprintf(ret, 12, "DEBUG");
        }
        else {
            snprintf(ret, 12, "%s_D", ret);
        }
    }
    // mark verbose entry
    /*if (FLAG_CMP(level, LOG_VERBOSE)) {		
        snprintf(ret, "%s_V", ret);
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

        np_spinlock_lock(&np_module(log)->__log_lock);
        {
            sll_append(char_ptr, np_module(log)->__logger->logentries_l, new_log_entry);
        }
        np_spinlock_unlock(&np_module(log)->__log_lock);

        // instant writeout
        if ((level & LOG_ERROR) == LOG_ERROR) {
            _np_log_fflush(context, true);
        }
#ifdef DEBUG
        else {
            _np_log_fflush(context, true);
        }
#else // DEBUG
        else if (sll_size(np_module(log)->__logger->logentries_l) > MISC_LOG_FLUSH_AFTER_X_ITEMS) {
            _np_event_invoke_file(context);        
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
        np_spinlock_lock(&np_module(log)->__log_lock);
        {
            if (flush_status < 1 ) {

                if (flush_status < 0) {
                    flush_status = (force == true || sll_size(np_module(log)->__logger->logentries_l) > MISC_LOG_FLUSH_AFTER_X_ITEMS) ? 0 : 1;
                }

                if(flush_status == 0) {
                    entry = sll_head(char_ptr, np_module(log)->__logger->logentries_l);
                    if (NULL != entry) {
                        np_module(log)->__logger->log_size += strlen(entry);
                    }
                }
            }
        }
        np_spinlock_unlock(&np_module(log)->__log_lock);

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
                    np_spinlock_lock(&np_module(log)->__log_lock);
                    sll_append(char_ptr, np_module(log)->__logger->logentries_l, entry);
                    np_spinlock_unlock(&np_module(log)->__log_lock);
                    break;
                }
                bytes_witten += current_bytes_witten;
            }

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

    if(np_module(log)->__logger->log_rotate == true)
        _np_log_rotate(context, false);

}

void np_log_setlevel(np_state_t* context, uint32_t level)
{
    log_trace_msg(LOG_TRACE, "start: void np_log_setlevel(uint32_t level){");
    np_module(log)->__logger->level = level;
}

bool _np_log_init(np_state_t* context, const char* filename, uint32_t level)
{
    if (!np_module_initiated(log))
    {
        np_module_malloc(log);
        TSP_INIT(np_module(log)->__log);
        np_spinlock_init(&np_module(log)->__log_lock, PTHREAD_PROCESS_PRIVATE);

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
        log_rotation(context, true);
        log_debug_msg(LOG_DEBUG, "initialized log system %p: %s / %x", __logger, __logger->filename, __logger->level);
    }
    return true;
}

void _np_log_destroy(np_state_t* context)
{
    if (np_module_initiated(log)) {
        np_module_var(log);

        _np_log_fflush(context, true);

        __np_log_close_file(np_module(log)->__logger);
        TSP_DESTROY(np_module(log)->__log);
        np_spinlock_destroy(&np_module(log)->__log_lock);
        sll_iterator(char_ptr) logentries_l_item = sll_first(_module->__logger->logentries_l);
        while(logentries_l_item != NULL){
            free(logentries_l_item->val);
            sll_next(logentries_l_item);
        }

        sll_free(char_ptr, _module->__logger->logentries_l);
        free(_module->__logger);

        np_module_free(log);
    }
} 

