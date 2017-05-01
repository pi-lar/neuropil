//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#ifdef __cplusplus
extern "C" {
#endif

// put this into the header file of a module
#define _NP_ENABLE_MODULE_LOCK(TYPE) \
	int _##TYPE##_lock(); \
	void _##TYPE##_unlock();

// and add the implementation into the source file
#define _NP_MODULE_LOCK_IMPL(TYPE) 						\
	int  _##TYPE##_lock()   {							\
		return pthread_mutex_lock(&__lock_mutex);	    \
	} 													\
	void _##TYPE##_unlock() {                           \
		pthread_mutex_unlock(&__lock_mutex);            \
	}                                                   \


#define _LOCK_MODULE(TYPE) for(uint8_t i=0; (i < 1) && !_##TYPE##_lock(); _##TYPE##_unlock(), i++)
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
return_type func_name(arg_1 a_1, arg_2 a_2) {\
	return wrapped_##func_name(a_1, a_2);\
}\
return_type wrapped_##func_name(arg_1, arg_2)


#ifdef __cplusplus
}
#endif

#endif // _NP_THREADS_H_
