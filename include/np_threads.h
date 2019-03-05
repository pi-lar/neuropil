//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#include <stdlib.h>
#include <pthread.h>
#if defined(_WIN32) || defined(WIN32) 
#include <time.h>
#else
#include <sys/time.h>
#endif

#include "np_memory.h"

#include "np_list.h"
#include "np_log.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"

#include "np_jobqueue.h"

#ifdef __cplusplus
extern "C" {
#endif

// first try to decorate functions, usable ?
#define _WRAP(return_type, func_name, arg_1, arg_2) \
return_type func_name(arg_1 a_1, arg_2 a_2) {		\
    return wrapped_##func_name(a_1, a_2);			\
}													\
return_type wrapped_##func_name(arg_1, arg_2);


_NP_GENERATE_MEMORY_PROTOTYPES(np_thread_t);
typedef struct np_thread_stats_s np_thread_stats_t;


typedef enum np_module_lock_e np_module_lock_type;

enum np_module_lock_e {
    /*00*/np_memory_t_lock = 0,
    /*01*/np_aaatoken_t_lock,
    /*02*/np_event_t_lock,
    /*03*/np_keycache_t_lock,
    /*04*/np_message_part_cache_t_lock,
    /*05*/np_msgproperty_t_lock,
    /*06*/np_network_t_lock,
    /*07*/np_routeglobal_t_lock,
    /*08*/np_sysinfo_t_lock,
    /*09*/np_logsys_t_lock,
    /*10*/np_jobqueue_t_lock,
    /*11*/np_node_renewal_t_lock,
    /*12*/np_statistics_t_lock,
    /*13*/np_handshake_t_lock,
    /*14*/np_threads_t_lock,
    /*15*/np_utilstatistics_t_lock,
    /*16*/np_state_message_tokens_t_lock,
    PREDEFINED_DUMMY_START,	// The following dummy entries are reserved for future mutexes for the neuropil library
    PREDEFINED_DUMMY_1,
    PREDEFINED_DUMMY_2,
    PREDEFINED_DUMMY_3,
    PREDEFINED_DUMMY_4,
    PREDEFINED_DUMMY_5,
    PREDEFINED_DUMMY_6,
    PREDEFINED_DUMMY_7,
    PREDEFINED_DUMMY_8,
} NP_ENUM NP_API_INTERN;

static char* np_module_lock_str[PREDEFINED_DUMMY_START] = {
    "np_memory_t_lock",
    "np_aaatoken_t_lock",
    "np_event_t_lock",
    "np_keycache_t_lock",
    "np_message_part_cache_t_lock",
    "np_msgproperty_t_lock",
    "np_network_t_lock",
    "np_routeglobal_t_lock",
    "np_sysinfo_t_lock",
    "np_logsys_t_lock",
    "np_jobqueue_t_lock",
    "np_node_renewal_t_lock",
    "np_statistics_t_lock",
    "np_handshake_t_lock",
    "np_threads_t_lock",
    "np_utilstatistics_t_lock",
    "np_state_message_tokens_t_lock"
};

/** platform mutex/condition wrapper structures are defined here **/
/** condition                                                    **/
struct np_cond_s {
    pthread_cond_t     cond;
    pthread_condattr_t cond_attr;
};
typedef struct np_cond_s np_cond_t;

/** mutex                                                        **/
struct np_mutex_s {
    char* desc;
    pthread_mutex_t lock;
    pthread_mutexattr_t lock_attr;
    np_cond_t  condition;
};


enum np_thread_type_e {
    np_thread_type_other = 0,
    np_thread_type_main,
    np_thread_type_worker,
    np_thread_type_manager,
    np_thread_type_managed,
}NP_ENUM;

static const char* np_thread_type_str[] =  {
    "other",
    "main",
    "worker",
    "manager",
    "managed",
};

/** thread														**/
struct np_thread_s
{  
    np_threads_worker_run run_fn;
    uint8_t idx;

    size_t id;
    /**
    this thread can only handle jobs up to the max_job_priority
    */
    double max_job_priority;
    /**
    this thread can only handle jobs down to the min_job_priority
    */
    double min_job_priority;

    np_mutex_t job_lock;
    np_job_t job;
    bool _busy;
    enum np_thread_type_e thread_type;

    enum np_status status;

    pthread_t thread_id;

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
int _np_threads_unlock_modules(np_state_t* context, np_module_lock_type module_id_a,np_module_lock_type module_id_b);
NP_API_INTERN
int _np_threads_module_condition_broadcast(NP_UNUSED np_state_t* context, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_module_condition_signal(NP_UNUSED np_state_t* context, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_module_condition_timedwait(NP_UNUSED np_state_t* context, np_cond_t* condition, np_module_lock_type module_id, double sec);
NP_API_INTERN
int _np_threads_module_condition_wait(NP_UNUSED np_state_t* context, np_cond_t* condition, np_module_lock_type module_id);


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
void _np_threads_condition_init(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_init_shared(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
int _np_threads_condition_wait(NP_UNUSED np_state_t* context, np_cond_t* condition, np_mutex_t* mutex);

NP_API_INTERN
int _np_threads_condition_signal(NP_UNUSED np_state_t* context, np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_destroy(NP_UNUSED np_state_t* context, np_cond_t* condition);

NP_API_INTERN
int _np_threads_condition_broadcast(NP_UNUSED np_state_t* context, np_cond_t* condition);
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


#define __LOCK_ACCESS_W_PREFIX(prefix, obj, lock_type)																						\
    np_mutex_t* TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__)) = obj;																		\
    for(uint8_t TOKENPASTE2(prefix,__LINE__)=0; 																										\
        (TOKENPASTE2(prefix,__LINE__) < 1) && 0 == _np_threads_mutex_##lock_type##lock(context, TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__)),FUNC);		\
        _np_threads_mutex_unlock(context, TOKENPASTE2(prefix,TOKENPASTE2(lock, __LINE__))), TOKENPASTE2(prefix,__LINE__)++										\
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
    TSP = ThreadSafeProperty
*/
#define TSP(TYPE, NAME)								\
    TYPE NAME;										\
    np_mutex_t NAME##_mutex;

#define TSP_INITD(NAME, DEFAULT_VALUE)						 \
    _np_threads_mutex_init(context, &NAME##_mutex, #NAME);			 \
    TSP_SET(NAME, DEFAULT_VALUE)

#define TSP_INIT(NAME)										 \
    _np_threads_mutex_init(context, &NAME##_mutex, #NAME);

#define TSP_DESTROY(NAME)							\
    _np_threads_mutex_destroy(context, &NAME##_mutex);

#define TSP_GET(TYPE, NAME, RESULT)					\
    TYPE RESULT=0;									\
    _LOCK_ACCESS(&NAME##_mutex){					\
        RESULT = NAME;								\
    }
#define TSP_SET(NAME, VALUE)						\
    _LOCK_ACCESS(&NAME##_mutex){					\
        NAME = VALUE;								\
    }
#define TSP_SCOPE(NAME)								\
    _LOCK_ACCESS(&NAME##_mutex)
#define TSP_TRYSCOPE(NAME)								\
    _TRYLOCK_ACCESS(&NAME##_mutex)

 
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
