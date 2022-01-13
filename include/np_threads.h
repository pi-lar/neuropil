//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef NP_THREADS_H_
#define NP_THREADS_H_

#include <stdlib.h>
#include <pthread.h>

#ifdef __APPLE__
    #include <os/lock.h>
#endif

#if defined(_WIN32) || defined(WIN32) 
    #include <time.h>
#else
    #include <sys/time.h>
#endif

#include "np_memory.h"

#include "util/np_list.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"

#include "np_jobqueue.h"

#ifdef __cplusplus
extern "C" {
#endif

_NP_GENERATE_MEMORY_PROTOTYPES(np_thread_t)

typedef struct np_thread_stats_s np_thread_stats_t;

enum np_module_lock_e {
    /*00*/np_memory_t_lock = 0,
    /*01*/np_event_in_t_lock,
    /*02*/np_event_out_t_lock,
    /*03*/np_event_http_t_lock,
    /*04*/np_event_file_t_lock,
    /*05*/np_keycache_t_lock,
    /*06*/np_message_part_cache_t_lock,
    /*07*/np_routeglobal_t_lock,
    /*07*/np_pheromones_t_lock,
    /*08*/np_logsys_t_lock,
    /*09*/np_sysinfo_t_lock,
    /*10*/np_jobqueue_t_lock,
    /*11*/np_node_renewal_t_lock,
    /*12*/np_statistics_t_lock,
    /*14*/np_threads_t_lock,
    /*15*/np_utilstatistics_t_lock,
    /*16*/np_aaatoken_t_lock,
    /*17*/np_state_message_tokens_t_lock,
    PREDEFINED_DUMMY_START,	// The following dummy entries are reserved for future mutexes for the neuropil library
} NP_ENUM NP_API_INTERN;

typedef enum np_module_lock_e np_module_lock_type;

/** platform mutex/condition wrapper structures are defined here **/
/** condition                                                    **/
struct np_cond_s {
    pthread_cond_t     cond;
    pthread_condattr_t cond_attr;
};
typedef struct np_cond_s np_cond_t;

/** mutex                                                        **/
struct np_mutex_s {
    char desc[64];
    pthread_mutex_t lock;
    pthread_mutexattr_t lock_attr;
    np_cond_t  condition;
};


enum np_thread_type_e {
    np_thread_type_other = 0,
    np_thread_type_main,
    np_thread_type_worker,
    np_thread_type_eventloop,
    np_thread_type_manager,
    np_thread_type_managed,
} NP_ENUM;

static const char* np_thread_type_str[] =  {
    "other",
    "main",
    "worker",
    "evloop",
    "coord",
    "managed",
};

/** thread														**/
struct np_thread_s
{
    uint8_t idx;
    size_t id;
    pthread_t thread_id;

    /**
    this thread can only handle jobs up to the max_job_priority
    */
    double max_job_priority;
    /**
    this thread can only handle jobs down to the min_job_priority
    */
    double min_job_priority;

    bool _busy;
    enum np_thread_type_e thread_type;
    np_threads_worker_run run_fn;

    np_mutex_t job_lock;
    volatile np_job_t job;
    volatile bool has_job;

#ifdef NP_THREADS_CHECK_THREADING
    np_mutex_t locklists_lock;
    np_sll_t(char_ptr, want_lock);
    np_sll_t(char_ptr, has_lock);
#endif

#ifdef NP_STATISTICS_THREADS
    np_thread_stats_t *stats;
#endif

} NP_API_INTERN;


NP_API_INTERN
bool _np_threads_init(np_state_t* context);
NP_API_INTERN
void _np_threads_destroy(np_state_t* context);
NP_API_INTERN
void np_threads_shutdown_workers(np_state_t* context);

NP_API_INTERN
int _np_threads_lock_module(np_state_t* context, np_module_lock_type module_id, const char* where);
NP_API_INTERN
int _np_threads_unlock_module(np_state_t* context, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_unlock_modules(np_state_t* context, np_module_lock_type module_id_a, np_module_lock_type module_id_b);

NP_API_INTERN
int _np_threads_module_condition_broadcast(NP_UNUSED np_state_t* context, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_module_condition_signal(NP_UNUSED np_state_t* context, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_module_condition_timedwait(NP_UNUSED np_state_t* context, np_module_lock_type module_id, double sec);
NP_API_INTERN
int _np_threads_module_condition_wait(NP_UNUSED np_state_t* context, np_module_lock_type module_id);

NP_API_EXPORT
int _np_threads_mutex_init(np_state_t*context, np_mutex_t* mutex, const char* desc);
NP_API_EXPORT
int _np_threads_mutex_lock(NP_UNUSED np_state_t*context, np_mutex_t* mutex, const char* where);
NP_API_INTERN
int _np_threads_mutex_trylock(NP_UNUSED np_state_t*context, np_mutex_t* mutex, const char* where);
NP_API_EXPORT
int _np_threads_mutex_unlock(NP_UNUSED np_state_t*context, np_mutex_t* mutex);
NP_API_INTERN
void _np_threads_mutex_destroy(NP_UNUSED np_state_t*context, np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_mutex_condition_timedwait(NP_UNUSED np_state_t*context, np_mutex_t* mutex, struct timespec* waittime);
NP_API_INTERN
int _np_threads_mutex_condition_wait(NP_UNUSED np_state_t*context, np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_mutex_timedlock(NP_UNUSED np_state_t*context, np_mutex_t * mutex, const double delay);
NP_API_INTERN
int _np_threads_mutex_condition_signal(NP_UNUSED np_state_t* context, np_mutex_t* mutex);

NP_API_INTERN
void _np_threads_condition_init(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_init_shared(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
int _np_threads_condition_wait(NP_UNUSED np_state_t* context, np_cond_t* condition, np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_condition_signal(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
int _np_threads_condition_broadcast(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_destroy(NP_UNUSED np_state_t* context, np_cond_t* condition);

NP_API_INTERN
np_thread_t * __np_createThread(NP_UNUSED np_state_t* context, uint8_t number,np_threads_worker_run fn, bool auto_run, enum np_thread_type_e type);

NP_API_INTERN
np_thread_t*_np_threads_get_self(NP_UNUSED np_state_t* context);
NP_API_INTERN
void _np_threads_set_self(np_thread_t * myThread);

NP_API_INTERN
void np_threads_start_workers(NP_UNUSED np_state_t* context, uint8_t pool_size);

NP_API_INTERN
char* np_threads_print(np_state_t * context, bool asOneLine);

#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)

#define __NP_THREADS_GET_MUTEX_DEFAULT_WAIT(NAME, ELAPSED_TIME)												\
struct timespec NAME##_ts={0};																				\
struct timeval NAME##_tv;																					\
struct timespec* NAME=&NAME##_ts;																			\
                                                                                                            \
gettimeofday(&NAME##_tv, NULL);																				\
NAME##_ts.tv_sec = NAME##_tv.tv_sec + MUTEX_WAIT_MAX_SEC - ELAPSED_TIME;


#define __LOCK_ACCESS_W_PREFIX(prefix, obj, lock_type)																						           \
    np_mutex_t* TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__)) = obj;																		           \
    for(uint8_t TOKENPASTE2(prefix,__LINE__)=0; 																							           \
        (TOKENPASTE2(prefix,__LINE__) < 1) && 0 == _np_threads_mutex_##lock_type##lock(context, TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__)),FUNC); \
        _np_threads_mutex_unlock(context, TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__))), TOKENPASTE2(prefix,__LINE__)++							   \
        )
#define _LOCK_ACCESS(obj) __LOCK_ACCESS_W_PREFIX(TOKENPASTE2(default_prefix_, __COUNTER__), obj,)
#define _TRYLOCK_ACCESS(obj) __LOCK_ACCESS_W_PREFIX(TOKENPASTE2(default_try_prefix_, __COUNTER__), obj,try)
// protect access to restricted area in the rest of your code like this
/*
struct obj {
    np_mutex_t lock;
} obj_t;

obj_t object;

_LOCK_ACCESS(&object->lock)
{
    ... call_a_function_of_locked_module() ...;
}
*/

#define _LOCK_MODULE(TYPE) for(uint8_t _LOCK_MODULE_i##__LINE__=0; (_LOCK_MODULE_i##__LINE__ < 1) && 0 == _np_threads_lock_module(context, TYPE##_lock,FUNC); _np_threads_unlock_module(context, TYPE##_lock), _LOCK_MODULE_i##__LINE__++)
// protect access to a module in the rest of your code like this
/*
_LOCK_MODULE(np_keycache_t)
{
    ... call_a_function_of_locked_module() ...;
}
*/
// print the complete object list and statistics

NP_API_PROTEC
char* np_threads_print_locks(NP_UNUSED np_state_t* context, bool asOneLine, bool force);

/*
    TSP = ThreadSafeProperty using spinlocks
*/
#ifdef __APPLE__
    #define np_spinlock_t          os_unfair_lock
    #define np_spinlock_init(x,y)  (*x = OS_UNFAIR_LOCK_INIT)
    #define np_spinlock_destroy(x) 
    #define np_spinlock_lock(x)    os_unfair_lock_lock(x)
    #define np_spinlock_trylock(x) (true == os_unfair_lock_trylock(x))
    #define np_spinlock_unlock(x)  os_unfair_lock_unlock(x)
#else
    #define np_spinlock_t          pthread_spinlock_t
    #define np_spinlock_init(x, y) pthread_spin_init(x, y)
    #define np_spinlock_destroy(x) pthread_spin_destroy(x)
    #define np_spinlock_lock(x)    pthread_spin_lock(x)
    #define np_spinlock_trylock(x) (0 == pthread_spin_trylock(x))
    #define np_spinlock_unlock(x)  pthread_spin_unlock(x)
#endif 


#define TSP(TYPE, NAME)                                                         \
    TYPE NAME;                                                                  \
    np_spinlock_t NAME##_lock;                                                  \

#define TSP_INITD(NAME, DEFAULT_VALUE)                                          \
    TSP_INIT(NAME);                                                             \
    TSP_SET(NAME, DEFAULT_VALUE);                                               

#define TSP_INIT(NAME)                                                          \
    np_spinlock_init(&NAME##_lock, PTHREAD_PROCESS_PRIVATE);                    

#define TSP_DESTROY(NAME)                                                       \
    np_spinlock_destroy(&NAME##_lock);                                          

#define TSP_GET(TYPE, NAME, RESULT)                                             \
    TYPE RESULT=0;                                                              \
    np_spinlock_lock(&NAME##_lock);                                             \
    RESULT = NAME;                                                              \
    np_spinlock_unlock(&NAME##_lock);                                           

#define TSP_SET(NAME, VALUE)                                                    \
    np_spinlock_lock(&NAME##_lock);                                             \
    NAME = VALUE;                                                               \
    np_spinlock_unlock(&NAME##_lock);                                           

#define TSP_SCOPE(NAME)                                                         \
    for(uint8_t _LOCK_i##__LINE__=0; np_spinlock_lock(&NAME##_lock), _LOCK_i##__LINE__ < 1; np_spinlock_unlock(&NAME##_lock), _LOCK_i##__LINE__++)


void np_threads_busyness(np_state_t* context, np_thread_t* self, bool is_busy);
#ifdef NP_STATISTICS_THREADS
    void np_threads_busyness_statistics(np_state_t* context, np_thread_t* self, double *perc_1, double *perc_5, double *perc_15);
    void np_threads_busyness_stat(np_state_t* context, np_thread_t* self) ;
#else
    #define np_threads_busyness_statistics(context,self,perc_1, perc_5, perc_15)
    #define np_threads_busyness_stat(context,self)
#endif


#ifdef __cplusplus
}
#endif

#endif // _NP_THREADS_H_
