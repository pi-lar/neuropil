//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_log.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "event/ev.h"
#include "pthread.h"

#include "neuropil_log.h"

#include "util/np_event.h"
#include "util/np_list.h"

#include "np_evloop.h"
#include "np_jobqueue.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "np_settings.h"
#include "np_time.h"
#include "np_util.h"

typedef struct np_log_entry *np_log_entry_ptr;
NP_SLL_GENERATE_PROTOTYPES(np_log_entry_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_log_entry_ptr);
typedef struct np_log_s {
  char original_filename[PATH_MAX + 1];
  char filename[PATH_MAX + 1];
  char filename_ext[16];

  int fp;

  // FILE *fp;
  uint32_t level;
  np_sll_t(np_log_entry_ptr, logentries_l);
  uint32_t log_size;
  uint32_t log_count;
  bool     log_rotate;

  ev_io watcher;

} np_log_t;

typedef struct log_str_t {
  const char *text;
  int         log_code;
} log_str_t;

np_module_struct(log) {
  np_state_t   *context;
  np_log_t     *__logger;
  np_spinlock_t __log_lock;
  bool          __init;
};

void _np_log_to_str(char         *buffer,
                    size_t        buffer_size,
                    enum np_log_e to_convert) {
  size_t _buffer_size     = buffer_size - 1;
  size_t _buffer_size_new = 0;
  if (FLAG_CMP(to_convert, LOG_ERROR))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "ERROR ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_WARNING))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "WARNING ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_INFO))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "INFO ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_DEBUG))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "DEBUG ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_TRACE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "TRACE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);

  if (FLAG_CMP(to_convert, LOG_KEY))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "KEY ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_HTTP))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "HTTP ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_TREE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "TREE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_JOBS))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "JOBS ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_MISC))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "MISC ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_MUTEX))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "MUTEX ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_EVENT))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "EVENT ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_MEMORY))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "MEMORY ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_SECURE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "SECURE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_NETWORK))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "NETWORK ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_ROUTING))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "ROUTING ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_MESSAGE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "MESSAGE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_SYSINFO))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "SYSINFO ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_THREADS))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "THREADS ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_AAATOKEN))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "AAATOKEN ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_KEYCACHE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "KEYCACHE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_HANDSHAKE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "HANDSHAKE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_PHEROMONE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "PHEROMONE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_EXPERIMENT))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "EXPERIMENT ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_MSGPROPERTY))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "MSGPROPERTY ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
  if (FLAG_CMP(to_convert, LOG_SERIALIZATION))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "SERIALIZATION ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);

  if (FLAG_CMP(to_convert, LOG_VERBOSE))
    _buffer_size_new += strnlen(strncpy(buffer + _buffer_size_new,
                                        "VERBOSE ",
                                        _buffer_size - _buffer_size_new),
                                _buffer_size);
}

void _np_log_evflush(struct ev_loop  *loop,
                     NP_UNUSED ev_io *ev,
                     int              event_type) {
  if (FLAG_CMP(event_type, EV_WRITE)) {
    _np_log_fflush((np_context *)ev_userdata(loop), false);
  }
}

void __np_log_close_file(np_log_t *logger) {
  if (close(logger->fp) != 0) {
    fprintf(stderr,
            "Could not close old logfile. Error: %s (%d)",
            strerror(errno),
            errno);
    fflush(NULL);
  }
}

void log_rotation(np_state_t *context) {
  bool first_init        = !np_module(log)->__init;
  np_module(log)->__init = true;

  np_log_t *logger = np_module(log)->__logger;

  logger->log_size = 0;
  logger->log_count += 1;

  EV_P = _np_event_get_loop_file(context);
  _np_event_suspend_loop_file(context);
  ev_io_stop(EV_A_ & logger->watcher);

  // Closing old file
  if (!first_init) {
    // log_msg(LOG_INFO, "Continuing log in file %s now.", logger->filename);
    _np_log_fflush(context, true);
    __np_log_close_file(logger);
  }

  char old_filename[PATH_MAX + 1] = {0};
  strncpy(old_filename, logger->filename, PATH_MAX);

  np_spinlock_lock(&np_module(log)->__log_lock);
  {
    int log_id = (logger->log_count % LOG_ROTATE_COUNT);
    if (log_id == 0) {
      log_id = LOG_ROTATE_COUNT;
    }

    // create new filename
    if (logger->log_rotate) {
      snprintf(logger->filename,
               PATH_MAX,
               "%s_%d%s",
               logger->original_filename,
               log_id,
               logger->filename_ext);
    } else {
      snprintf(logger->filename,
               PATH_MAX,
               "%s%s",
               logger->original_filename,
               logger->filename_ext);
    }
    // setting up new file
    if (logger->log_rotate) { // remove old file if it is already present
      unlink(logger->filename);
    }
    logger->fp = open(logger->filename,
                      O_WRONLY | O_APPEND | O_CREAT,
                      S_IREAD | S_IWRITE | S_IRGRP);
  }
  np_spinlock_unlock(&np_module(log)->__log_lock);

  if (logger->fp < 0) {
    fprintf(stderr,
            "Could not create logfile at %s. Error: %s (%d)",
            logger->filename,
            strerror(errno),
            errno);
    fprintf(stderr, "Log will no longer continue");
    fflush(NULL);
    // discontinue new log msgs
    free(logger);
    logger = NULL;
  } else {
    ev_io_init(&logger->watcher, _np_log_evflush, logger->fp, EV_WRITE);
    ev_io_start(EV_A_ & logger->watcher);
    _np_event_resume_loop_file(context);
    _np_event_reconfigure_loop_file(context);
  }

  if (!first_init) {
    log_msg(LOG_INFO,
            "Continuing log from file %s. This is the %" PRIu32
            " iteration of this file.",
            old_filename,
            logger->log_count / LOG_ROTATE_COUNT);
  }
}

void _np_log_rotate(np_state_t *context, bool force) {
  size_t log_size;
  np_spinlock_lock(&np_module(log)->__log_lock);
  { log_size = np_module(log)->__logger->log_size; }
  np_spinlock_unlock(&np_module(log)->__log_lock);
  if (log_size >= LOG_ROTATE_AFTER_BYTES || force == true) {
    log_rotation(context);
  }
}

void np_log_message(np_state_t   *context,
                    enum np_log_e level,
                    const char   *srcFile,
                    const char   *funcName,
                    uint16_t      lineno,
                    const char   *msg,
                    ...) {
  if (!np_module_initiated(log) || np_module(log)->__logger == NULL) {
#ifdef CONSOLE_BACKUP_LOG
    va_list ap;
    va_start(ap, msg);
    vfprintf(stderr, msg, ap);
    fprintf(stderr, "\n");
    va_end(ap);
#endif
    return;
  }
  // include msg if log level is included into selected levels
  // and if the msg has a category and is included into selected categories
  // or if no category is provided for msg or the log level contains the
  // LOG_GLOBAL flag
  if (((level & LOG_LEVEL_MASK & np_module(log)->__logger->level) > LOG_NONE &&
       ((level & LOG_VERBOSE) <=
        (LOG_VERBOSE & np_module(log)->__logger->level)) &&
       ((level & LOG_MODUL_MASK & np_module(log)->__logger->level) > LOG_NONE ||
        (np_module(log)->__logger->level & LOG_MODUL_MASK & LOG_GLOBAL) ==
            LOG_GLOBAL ||
        (level & LOG_MODUL_MASK) == LOG_NONE)) ||
      FLAG_CMP(level, LOG_ERROR) || FLAG_CMP(level, LOG_WARNING)) {
    np_log_entry_ptr new_log_entry = malloc(sizeof(struct np_log_entry));
    _np_log_to_str(new_log_entry->level, 20, level & LOG_LEVEL_MASK);
    new_log_entry->timestamp = _np_time_force_now_nsec();

    va_list ap;
    va_start(ap, msg);
    new_log_entry->string_length = vasprintf(&new_log_entry->string, msg, ap);
    va_end(ap);
    assert(new_log_entry->string_length > 0);

#ifndef CONSOLE_LOG
    if (context->settings->log_write_fn == NULL) {
#endif
      struct timeval tval;
      struct tm      local_time;
      gettimeofday(&tval, (struct timezone *)0);
      int32_t millis = tval.tv_usec;
      localtime_r(&tval.tv_sec, &local_time);

      char prefix[500] = {0};
      strftime(prefix, 80, "%Y-%m-%d %H:%M:%S", &local_time);

      int new_log_entry_length = strlen(prefix);
      sprintf(prefix + new_log_entry_length,
              ".%06d "  /*millisec*/
              "%-15lu " /*thread id*/
              //"%15.15s:%-5hd %-25.25s " /* file desc*/
              "%8s " /*Level*/,
              millis,                        // millisec
              (unsigned long)pthread_self(), // thread id
              // srcFile, lineno, funcName, // file desc
              new_log_entry->level);

      _np_log_to_str(prefix + strlen(prefix),
                     500 - strlen(prefix),
                     level & LOG_MODUL_MASK);

      char *buf;
      new_log_entry->string_length =
          asprintf(&buf, "%s %s\n", prefix, new_log_entry->string);
      free(new_log_entry->string);
      new_log_entry->string = buf;
#ifndef CONSOLE_LOG
    }
#endif

#if defined(CONSOLE_LOG) && CONSOLE_LOG == 1
    fprintf(stdout, new_log_entry->string);
#else
    size_t log_size = 0;
    np_spinlock_lock(&np_module(log)->__log_lock);
    {
      sll_append(np_log_entry_ptr,
                 np_module(log)->__logger->logentries_l,
                 new_log_entry);
      log_size = sll_size(np_module(log)->__logger->logentries_l);
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
#else  // DEBUG
    else if (log_size > MISC_LOG_FLUSH_AFTER_X_ITEMS) {
      _np_event_invoke_file(context);
    }
#endif // DEBUG

#endif // CONSOLE_LOG
  }
}
void __np_log_write(np_state_t *context, np_log_entry_ptr entry) {
  uint32_t bytes_witten = 0;
  bool     retry        = false;
  while (bytes_witten < entry->string_length) {
    int current_bytes_witten = 0;

    if (context->settings->log_write_fn != NULL) {
      current_bytes_witten += entry->string_length;
      context->settings->log_write_fn(context, *entry);
    } else {
      current_bytes_witten = write(np_module(log)->__logger->fp,
                                   entry->string + bytes_witten,
                                   entry->string_length - bytes_witten);
    }
    // if we write was not successful we reschedule the entry
    // and break free from this iteration
    if (current_bytes_witten < 0) {
      np_spinlock_lock(&np_module(log)->__log_lock);
      sll_prepend(np_log_entry_ptr,
                  np_module(log)->__logger->logentries_l,
                  entry);
      np_spinlock_unlock(&np_module(log)->__log_lock);
      retry = true;
      break;
    }
    bytes_witten += current_bytes_witten;
  }
  if (!retry) {
    free(entry->string);
    free(entry);
  }
}
void _np_log_fflush(np_state_t *context, bool force) {
  // log_trace_msg(LOG_TRACE, "start: void _np_log_fflush(){");
  np_log_entry_ptr entry       = NULL;
  int              lock_result = 0;
  if (!np_module_initiated(log) || np_module(log)->__logger == NULL ||
      (np_module(log)->__logger->fp <= 0 &&
       context->settings->log_write_fn == NULL)) {
    return;
  }
  /*
      -1 = evaluate the status on first lock
       0 = log till no entries are available anymore
       1 = discontinue the flush
  */
  int      flush_status = -1;
  uint32_t i            = 0;
  do {
    np_spinlock_lock(&np_module(log)->__log_lock);
    {
      if (flush_status < 1) {

        if (flush_status < 0) {
          flush_status = (force == true ||
                          sll_size(np_module(log)->__logger->logentries_l) >
                              MISC_LOG_FLUSH_AFTER_X_ITEMS)
                             ? 0
                             : 1;
        }

        if (flush_status == 0) {
          entry = sll_head(np_log_entry_ptr,
                           np_module(log)->__logger->logentries_l);
          if (NULL != entry) {
            np_module(log)->__logger->log_size += entry->string_length;
          }
        }
      }
    }
    np_spinlock_unlock(&np_module(log)->__log_lock);

    if (NULL != entry) {
      __np_log_write(context, entry);
    } else {
      flush_status = 1;
    }
    i++;
  } while (flush_status == 0 && i <= MISC_LOG_FLUSH_MAX_ITEMS);

  if (np_module(log)->__logger->log_rotate == true)
    _np_log_rotate(context, false);
}

void np_log_setlevel(np_state_t *context, uint32_t level) {
  log_trace_msg(LOG_TRACE, "start: void np_log_setlevel(uint32_t level){");
  np_module(log)->__logger->level = level;
}

bool _np_log_init(np_state_t *context, const char *filename, uint32_t level) {
  if (!np_module_initiated(log)) {
    np_module_malloc(log);
    TSP_INIT(np_module(log)->__log);

    np_log_t *__logger = (np_log_t *)calloc(1, sizeof(np_log_t));
    CHECK_MALLOC(__logger);
    _module->__init = false;

    // init logsystem
    __logger->level     = level;
    __logger->log_count = 0;
    __logger->log_size  = UINT32_MAX; // for initial log_rotation start
    __logger->log_rotate =
        LOG_ROTATE_ENABLE && context->settings->log_write_fn == NULL;

    // detect filename_ext from filename (. symbol)
    char *suffix = strrchr(filename, '.');
    if (suffix != NULL) { // found extension
      snprintf(__logger->filename_ext, 15, "%s", suffix);
    } else {
      snprintf(__logger->filename_ext, 15, ".log");
    }

    char new_filename[PATH_MAX + 1] = {0};
    snprintf(new_filename, suffix + 1 - filename, "%s", filename);
    realpath(new_filename, __logger->original_filename);
    realpath(new_filename, __logger->filename);

    sll_init(np_log_entry_ptr, __logger->logentries_l);
    _module->__logger = __logger;
    log_rotation(context);
    log_debug_msg(LOG_MISC,
                  "initialized log system %p: %s / %x",
                  __logger,
                  __logger->filename,
                  __logger->level);
  }
  return true;
}

void _np_log_destroy(np_state_t *context) {
  if (np_module_initiated(log)) {
    np_module_var(log);
    _np_log_fflush(context, true);
    np_module_init_null(log);

    __np_log_close_file(_module->__logger);
    TSP_DESTROY(_module->__log);
    sll_iterator(np_log_entry_ptr) logentries_l_item =
        sll_first(_module->__logger->logentries_l);
    while (logentries_l_item != NULL) {
      free(logentries_l_item->val->string);
      free(logentries_l_item->val);
      sll_next(logentries_l_item);
    }

    sll_free(np_log_entry_ptr, _module->__logger->logentries_l);
    free(_module->__logger);

    np_module_free(log);
  }
}
