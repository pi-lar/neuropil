/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

#ifdef __cplusplus
extern "C" {
#endif

// LOCK_CACHE
#define LOCK_CACHE(cache) for(uint8_t i=0; (i < 1) && !pthread_mutex_lock(&cache->lock); pthread_mutex_unlock(&cache->lock), i++)
// used like this
/*
LOCK_CACHE(lk_var) {
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
