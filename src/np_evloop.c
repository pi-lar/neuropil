//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_evloop.h"

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "event/ev.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_tree.h"

#include "np_constants.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_messagepart.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

#define __NP_EVENT_EVLOOP_STRUCTS(LOOPNAME)                                    \
  struct ev_loop *__loop_##LOOPNAME;                                           \
  ev_idle         __idle_##LOOPNAME;                                           \
  ev_async        __async_##LOOPNAME;                                          \
  size_t          __trigger_count_##LOOPNAME;

#define __NP_EVENT_EVLOOP_DEINIT(LOOPNAME)                                     \
  ev_loop_destroy(_module->__loop_##LOOPNAME);

#define __NP_EVENT_EVLOOP_INIT(LOOPNAME)                                       \
  np_module(events)->__loop_##LOOPNAME =                                       \
      ev_loop_new(EVFLAG_AUTO | EVFLAG_FORKCHECK);                             \
  if (np_module(events)->__loop_##LOOPNAME == false) {                         \
    ABORT("ERROR: cannot init " #LOOPNAME " event loop");                      \
  }                                                                            \
  ev_async_init(&np_module(events)->__async_##LOOPNAME, async_cb);             \
  ev_async_start(np_module(events)->__loop_##LOOPNAME,                         \
                 &np_module(events)->__async_##LOOPNAME);                      \
  ev_set_userdata(np_module(events)->__loop_##LOOPNAME, context);              \
  ev_verify(np_module(events)->__loop_##LOOPNAME);                             \
  ev_set_loop_release_cb(np_module(events)->__loop_##LOOPNAME,                 \
                         _l_release_##LOOPNAME,                                \
                         _l_acquire_##LOOPNAME);

// ev_check check_watcher;
// ev_check_init (&check_watcher, callback)

//     ev_idle_init (&np_module(events)->__idle_##LOOPNAME, _np_events_idle_##LOOPNAME);                                    \
//     ev_idle_start (np_module(events)->__loop_##LOOPNAME, &np_module(events)->__idle_##LOOPNAME);                         \

//    if (strncmp("out", #LOOPNAME, 3)) {
//        ev_set_io_collect_interval(np_module(events)->__loop_##LOOPNAME,
//        NP_EVENT_IO_CHECK_PERIOD_SEC);
//        ev_set_timeout_collect_interval(np_module(events)->__loop_##LOOPNAME,
//        NP_EVENT_IO_CHECK_PERIOD_SEC);
//    }

#define __NP_EVENT_LOOP_FNs(LOOPNAME)                                          \
  static void _np_events_idle_##LOOPNAME(NP_UNUSED struct ev_loop *loop,       \
                                         NP_UNUSED ev_idle        *w,          \
                                         NP_UNUSED int             revents) {              \
    np_state_t *context = ev_userdata(EV_A);                                   \
    if (np_get_status(context) != np_running) {                                \
      ev_break(EV_A_ EVBREAK_ALL);                                             \
    } else {                                                                   \
      ev_sleep(NP_PI / 500);                                                   \
    }                                                                          \
  }                                                                            \
  void _l_acquire_##LOOPNAME(EV_P) {                                           \
    np_state_t *context = ev_userdata(EV_A);                                   \
    _np_threads_lock_module(context, np_event_##LOOPNAME##_t_lock, FUNC);      \
  }                                                                            \
  void _l_release_##LOOPNAME(EV_P) {                                           \
    np_state_t *context = ev_userdata(EV_A);                                   \
    _np_threads_unlock_module(context, np_event_##LOOPNAME##_t_lock);          \
    if (np_get_status(context) >= np_shutdown) {                               \
      ev_break(EV_A_ EVBREAK_ALL);                                             \
    }                                                                          \
  }                                                                            \
  void _l_invoke_##LOOPNAME(EV_P) {                                            \
    np_state_t *context = ev_userdata(EV_A);                                   \
    while (ev_pending_count(EV_A)) {                                           \
      ev_invoke_pending(np_module(events)->__loop_##LOOPNAME);                 \
    }                                                                          \
    if (np_get_status(context) >= np_shutdown) {                               \
      ev_break(EV_A_ EVBREAK_ALL);                                             \
    }                                                                          \
  }                                                                            \
  bool _np_events_read_##LOOPNAME(np_state_t               *context,           \
                                  NP_UNUSED np_util_event_t event) {           \
    EV_P         = _np_event_get_loop_##LOOPNAME(context);                     \
    size_t count = 1;                                                          \
    _LOCK_MODULE(np_event_##LOOPNAME##_t) {                                    \
      ev_run(EV_A_(EVRUN_ONCE | EVRUN_NOWAIT));                                \
    }                                                                          \
    return true;                                                               \
  }                                                                            \
  void _np_event_##LOOPNAME##_run(np_state_t            *context,              \
                                  NP_UNUSED np_thread_t *thread_ptr) {         \
    EV_P = _np_event_get_loop_##LOOPNAME(context);                             \
    _LOCK_MODULE(np_event_##LOOPNAME##_t) { ev_run(EV_A_(0)); }                \
  }                                                                            \
  void _np_event_##LOOPNAME##_run_triggered(np_state_t  *context,              \
                                            np_thread_t *thread) {             \
    EV_P = _np_event_get_loop_##LOOPNAME(context);                             \
    ev_set_invoke_pending_cb(np_module(events)->__loop_##LOOPNAME,             \
                             _l_invoke_##LOOPNAME);                            \
    _LOCK_MODULE(np_event_##LOOPNAME##_t) {                                    \
      ev_run(EV_A_(EVRUN_NOWAIT | EVRUN_ONCE));                                \
      if (np_module(events)->__trigger_count_##LOOPNAME == 0) {                \
        _np_threads_module_condition_timedwait(context,                        \
                                               np_event_##LOOPNAME##_t_lock,   \
                                               NP_EVENT_IO_CHECK_PERIOD_SEC);  \
      } else {                                                                 \
        size_t count = np_module(events)->__trigger_count_##LOOPNAME;          \
        np_module(events)->__trigger_count_##LOOPNAME =                        \
            (count > 0) ? count - 1 : count;                                   \
      }                                                                        \
      log_debug(LOG_THREADS,                                                   \
                NULL,                                                          \
                "thread %" PRIsizet " type %" PRIu32 " stopping ...",          \
                thread->id,                                                    \
                thread->thread_type);                                          \
    }                                                                          \
  }                                                                            \
  void _np_event_suspend_loop_##LOOPNAME(np_state_t *context) {                \
    _np_threads_lock_module(context, np_event_##LOOPNAME##_t_lock, FUNC);      \
  }                                                                            \
  void _np_event_resume_loop_##LOOPNAME(np_state_t *context) {                 \
    _np_threads_unlock_module(context, np_event_##LOOPNAME##_t_lock);          \
  }                                                                            \
  void _np_event_reconfigure_loop_##LOOPNAME(np_state_t *context) {            \
    ev_async_send(_np_event_get_loop_##LOOPNAME(context),                      \
                  &np_module(events)->__async_##LOOPNAME);                     \
  }                                                                            \
  struct ev_loop *_np_event_get_loop_##LOOPNAME(np_state_t *context) {         \
    return (np_module(events)->__loop_##LOOPNAME);                             \
  }                                                                            \
  void _np_event_invoke_##LOOPNAME(np_state_t *context) {                      \
    if (0 == _np_threads_trylock_module(context,                               \
                                        np_event_##LOOPNAME##_t_lock,          \
                                        "ev_out")) {                           \
      np_module(events)->__trigger_count_##LOOPNAME++;                         \
      _np_threads_module_condition_signal(context,                             \
                                          np_event_##LOOPNAME##_t_lock);       \
      _np_threads_unlock_module(context, np_event_##LOOPNAME##_t_lock);        \
    }                                                                          \
  }

np_module_struct(events) {
  np_state_t *context;

  __NP_EVENT_EVLOOP_STRUCTS(in);
  __NP_EVENT_EVLOOP_STRUCTS(out);
  __NP_EVENT_EVLOOP_STRUCTS(http);
  __NP_EVENT_EVLOOP_STRUCTS(file);
};

__NP_EVENT_LOOP_FNs(in);
__NP_EVENT_LOOP_FNs(out);
__NP_EVENT_LOOP_FNs(http);
__NP_EVENT_LOOP_FNs(file);

void async_cb(EV_P_ NP_UNUSED ev_async *w, NP_UNUSED int revents) {
  /* just used for the side effects */
}

bool _np_event_init(np_state_t *context) {
  bool ret = false;
  if (!np_module_initiated(events)) {
    np_module_malloc(events);
    __NP_EVENT_EVLOOP_INIT(in);
    __NP_EVENT_EVLOOP_INIT(out);
    __NP_EVENT_EVLOOP_INIT(http);
    __NP_EVENT_EVLOOP_INIT(file);
    ret = true;
  }
  return ret;
}

void _np_event_destroy(np_state_t *context) {
  if (np_module_initiated(events)) {
    np_module_var(events);
    __NP_EVENT_EVLOOP_DEINIT(in);
    __NP_EVENT_EVLOOP_DEINIT(out);
    __NP_EVENT_EVLOOP_DEINIT(http);
    __NP_EVENT_EVLOOP_DEINIT(file);
    np_module_free(events);
  }
}
