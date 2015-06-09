#ifndef _NP_THREADS_H_
#define _NP_THREADS_H_

// LOCK_CACHE
// used like this
/*
LOCK_CACHE(lk_var) {
    var++;
}
*/
#define LOCK_CACHE(cache) for(int i=0; (i < 1) && !pthread_mutex_lock(&cache->lock); pthread_mutex_unlock(&cache->lock), i++)

#endif // _NP_THREADS_H_
