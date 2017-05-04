//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

// put this into the header file of a module
#define _NP_ENABLE_MODULE_LOCK(TYPE) \
	int _##TYPE##_lock(); \
	int _##TYPE##_unlock();

// and add the implementation into the source file
#define _NP_MODULE_LOCK_IMPL(TYPE) 									\
	int  _##TYPE##_lock()   {										\
/*		log_msg(LOG_DEBUG,"wait lock for "#TYPE);   			*/	\
		int ret =  pthread_mutex_lock(get_mutex(mutex_##TYPE));	   	\
/*		log_msg(LOG_DEBUG,"res %d lock for "#TYPE,ret);			*/	\
		return ret;	    											\
	} 																\
	int _##TYPE##_unlock() {               		            	\
/*		log_msg(LOG_DEBUG,"unlock for "#TYPE);   				*/	\
		int ret = pthread_mutex_unlock(get_mutex(mutex_##TYPE));   	\
/*		log_msg(LOG_DEBUG,"res %d unlock for "#TYPE,ret);   	*/	\
		return ret;	    											\
	}


#define _LOCK_MODULE(TYPE) for(uint8_t i=0; (i < 1) && 0 == _##TYPE##_lock(); _##TYPE##_unlock(), i++)
// protect access to a module in the rest of your code like this
/*
_LOCK_MODULE(np_keycache_t)
{
    ... call_a_function_of_locked_module() ...;
}
*/

// LOCK_CACHE
#define LOCK_CACHE(cache) for(uint8_t i=0; (i < 1) && !pthread_mutex_lock(&cache->lock); pthread_mutex_unlock(&cache->lock), i++)
// used like this
/*
LOCK_CACHE(lock_var) {
    var++;
}
*/

// first try to decorate functions, usable ?
#define _WRAP(return_type, func_name, arg_1, arg_2) \
return_type func_name(arg_1 a_1, arg_2 a_2) {		\
	return wrapped_##func_name(a_1, a_2);			\
}													\
return_type wrapped_##func_name(arg_1, arg_2);

typedef enum lock_e {
	mutex_np_memory_t = 0,
	mutex_np_keycache_t,
	mutex_msgpart_cache,
	mutex_np_msgproperty_t,
	mutex_np_network_t,
	mutex_np_routeglobal_t,
	mutex_np_sysinfo,
 	PREDEFINED_DUMMY_START,	// The following dummy entries are reserved for future mutexes for the neuropil library
	PREDEFINED_DUMMY_1,
	PREDEFINED_DUMMY_2,
	PREDEFINED_DUMMY_3,
	PREDEFINED_DUMMY_4,
	PREDEFINED_DUMMY_5,
	PREDEFINED_DUMMY_6,
	PREDEFINED_DUMMY_7,
	PREDEFINED_DUMMY_8,
	PREDEFINED_DUMMY_9,
	PREDEFINED_DUMMY_10,
	PREDEFINED_DUMMY_11,
	PREDEFINED_DUMMY_12,
	PREDEFINED_DUMMY_13,
	PREDEFINED_DUMMY_14,
	PREDEFINED_DUMMY_15,
	PREDEFINED_DUMMY_16,
	PREDEFINED_DUMMY_17,
	PREDEFINED_DUMMY_18,
	PREDEFINED_DUMMY_19,
	PREDEFINED_DUMMY_20,
	PREDEFINED_DUMMY_21,
	PREDEFINED_DUMMY_22,
	PREDEFINED_DUMMY_23,
	PREDEFINED_DUMMY_24,
	PREDEFINED_DUMMY_25,
	PREDEFINED_DUMMY_26,
	PREDEFINED_DUMMY_27,
	PREDEFINED_DUMMY_28,
	PREDEFINED_DUMMY_29,
	PREDEFINED_DUMMY_30,
	PREDEFINED_DUMMY_31,
	PREDEFINED_DUMMY_32,
	PREDEFINED_DUMMY_33,
	PREDEFINED_DUMMY_34,
	PREDEFINED_DUMMY_35,
	PREDEFINED_DUMMY_36,
	PREDEFINED_DUMMY_37,
	PREDEFINED_DUMMY_38,
	PREDEFINED_DUMMY_39,
	PREDEFINED_DUMMY_40,
	PREDEFINED_DUMMY_41,
	PREDEFINED_DUMMY_42,
	PREDEFINED_DUMMY_43,
	PREDEFINED_DUMMY_44,
	PREDEFINED_DUMMY_45,
	PREDEFINED_DUMMY_46,
	PREDEFINED_DUMMY_47,
	PREDEFINED_DUMMY_48,
	PREDEFINED_DUMMY_49,
} lock_e;

NP_API_INTERN
np_bool _np_threads_init();
NP_API_INTERN
pthread_mutex_t* get_mutex(int mutex_id);
NP_API_INTERN
np_bool create_mutex(int mutex_id);

#ifdef __cplusplus
}
#endif

#endif // _NP_THREADS_H_
