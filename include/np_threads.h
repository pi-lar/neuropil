//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#include <stdlib.h>
#include <pthread.h>

#include "np_threads.h"

#include "np_list.h"
#include "np_log.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif


// first try to decorate functions, usable ?
#define _WRAP(return_type, func_name, arg_1, arg_2) \
return_type func_name(arg_1 a_1, arg_2 a_2) {		\
	return wrapped_##func_name(a_1, a_2);			\
}													\
return_type wrapped_##func_name(arg_1, arg_2);



typedef enum np_module_lock_e np_module_lock_type;

enum np_module_lock_e {
	np_memory_t_lock = 0,
	np_aaatoken_t_lock,
	np_keycache_t_lock,
	np_messagesgpart_cache_t_lock,
	np_msgproperty_t_lock,
	np_network_t_lock,
	np_routeglobal_t_lock,
	np_sysinfo_t_lock,
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
    pthread_mutex_t lock;
    pthread_mutexattr_t lock_attr;
};
typedef struct np_mutex_s np_mutex_t;
/** condition                                                    **/
struct np_cond_s {
	pthread_cond_t     cond;
	pthread_condattr_t cond_attr;
};
typedef struct np_cond_s np_cond_t;


NP_API_INTERN
np_bool _np_threads_init();

NP_API_INTERN
int _np_threads_lock_module(np_module_lock_type module_id);
NP_API_INTERN
int _np_threads_unlock_module(np_module_lock_type module_id);

NP_API_INTERN
int _np_threads_mutex_init(np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_mutex_lock(np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_mutex_unlock(np_mutex_t* mutex);
NP_API_INTERN
void _np_threads_mutex_destroy(np_mutex_t* mutex);

NP_API_INTERN
void _np_threads_condition_init(np_cond_t* condition);
NP_API_INTERN
int _np_threads_condition_wait(np_cond_t* condition, np_mutex_t* mutex);
NP_API_INTERN
int _np_threads_condition_signal(np_cond_t* condition);
NP_API_INTERN
void _np_threads_condition_destroy(np_cond_t* condition);

#define _LOCK_ACCESS(obj) for(uint8_t i=0; (i < 1) && !_np_threads_mutex_lock(obj); _np_threads_mutex_unlock(obj), i++)
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

#define _LOCK_MODULE(TYPE) for(uint8_t i=0; (i < 1) && 0 == _np_threads_lock_module(TYPE##_lock); _np_threads_unlock_module(TYPE##_lock), i++)
// protect access to a module in the rest of your code like this
/*
_LOCK_MODULE(np_keycache_t)
{
    ... call_a_function_of_locked_module() ...;
}
*/


#ifdef __cplusplus
}
#endif

#endif // _NP_THREADS_H_
