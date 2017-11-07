//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#include <stdlib.h>
#include <pthread.h>
#include <sys/time.h>

#include "np_memory.h"
#include "np_list.h"
#include "np_log.h"
#include "np_types.h"
#include "np_constants.h"
#include "np_settings.h"

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

/** platform mutex/condition wrapper structures are defined here **/
/** mutex                                                        **/
struct np_mutex_s {
	char* desc;
	pthread_mutex_t lock;
	pthread_mutexattr_t lock_attr;
};

/** condition                                                    **/
struct np_cond_s {
	pthread_cond_t     cond;
	pthread_condattr_t cond_attr;
};
typedef struct np_cond_s np_cond_t;
/** thread														**/
struct np_thread_s
{
	np_obj_t* obj;

	unsigned long id;
	/**
	this thread can only handle jobs up to the max_job_priority
	*/
	double max_job_priority;
	/**
	this thread can only handle jobs down to the min_job_priority
	*/
	double min_job_priority;
#ifdef CHECK_THREADING
	np_mutex_t locklists_lock;
	np_sll_t(char_ptr, want_lock);
	np_sll_t(char_ptr, has_lock);
#endif
} NP_API_INTERN;



NP_API_INTERN
np_bool _np_threads_init();

NP_API_INTERN
int _np_threads_lock_module(np_module_lock_type module_id, char* where);
NP_API_INTERN
int _np_threads_unlock_module(np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_lock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b, char* where);
NP_API_INTERN
int _np_threads_unlock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b);

NP_API_INTERN
int _np_threads_mutex_init(np_mutex_t* mutex,char* desc);
NP_API_INTERN
int _np_threads_mutex_lock(np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_mutex_unlock(np_mutex_t* mutex);
NP_API_INTERN
void _np_threads_mutex_destroy(np_mutex_t* mutex);

NP_API_INTERN
void _np_threads_condition_init(np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_init_shared(np_cond_t* condition);
NP_API_INTERN
int _np_threads_condition_wait(np_cond_t* condition, np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_condition_signal(np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_destroy(np_cond_t* condition);
NP_API_INTERN
int _np_threads_module_condition_timedwait(np_cond_t* condition, np_module_lock_type module_id, struct timespec* waittime);
NP_API_INTERN
int _np_threads_condition_broadcast(np_cond_t* condition);
NP_API_INTERN
np_thread_t*_np_threads_get_self();

#define TOKENPASTE(x, y) x ## y
#define TOKENPASTE2(x, y) TOKENPASTE(x, y)

#define __NP_THREADS_GET_MUTEX_DEFAULT_WAIT(NAME, ELAPSED_TIME)												\
struct timespec NAME##_ts={0};																				\
struct timeval NAME##_tv;																					\
struct timespec* NAME=&NAME##_ts;																			\
																											\
gettimeofday(&NAME##_tv, NULL);																				\
NAME##_ts.tv_sec = NAME##_tv.tv_sec + min(MUTEX_WAIT_MAX_SEC - ELAPSED_TIME, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC);													


#define _LOCK_ACCESS(obj) np_mutex_t* TOKENPASTE2(lock, __LINE__) = obj; for(uint8_t _LOCK_ACCESS##__LINE__=0; (_LOCK_ACCESS##__LINE__ < 1) && !_np_threads_mutex_lock(TOKENPASTE2(lock, __LINE__)); _np_threads_mutex_unlock(TOKENPASTE2(lock, __LINE__)), _LOCK_ACCESS##__LINE__++)
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

#define _LOCK_MODULE(TYPE) for(uint8_t _LOCK_MODULE_i##__LINE__=0; (_LOCK_MODULE_i##__LINE__ < 1) && 0 == _np_threads_lock_module(TYPE##_lock,__func__); _np_threads_unlock_module(TYPE##_lock), _LOCK_MODULE_i##__LINE__++)
#define _LOCK_MODULES(TYPE_A,TYPE_B) for(uint8_t _LOCK_MODULES_i##__LINE__=0; (_LOCK_MODULES_i##__LINE__ < 1) && 0 == _np_threads_lock_modules(TYPE_A##_lock,TYPE_B##_lock,__func__); _np_threads_unlock_modules(TYPE_A##_lock,TYPE_B##_lock), _LOCK_MODULES_i##__LINE__++)
// protect access to a module in the rest of your code like this
/*
_LOCK_MODULE(np_keycache_t)
{
	... call_a_function_of_locked_module() ...;
}
*/
// print the complete object list and statistics
NP_API_INTERN
char* np_threads_printpool(np_bool asOneLine);


#ifdef __cplusplus
}
#endif

#endif // _NP_THREADS_H_
