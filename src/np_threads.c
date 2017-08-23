/*
 * np_threads.c
 *
 *  Created on: 02.05.2017
 *      Author: sklampt
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>

#include "np_threads.h"
#include "event/ev.h"
#include "pthread.h"

#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_log.h"
#include "np_settings.h"

#ifndef MUTEX_WAIT_SEC
const ev_tstamp MUTEX_WAIT_SEC = 0.005;
#endif

static pthread_once_t __np_thread_init_once = PTHREAD_ONCE_INIT;

/** predefined module mutex array **/
np_mutex_t __mutexes[PREDEFINED_DUMMY_START-1];
np_bool _np_threads_initiated = FALSE;

np_bool __np_threads_create_module_mutex(np_module_lock_type module_id)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: np_bool __np_threads_create_module_mutex(np_module_lock_type module_id){");
	pthread_mutexattr_init(&__mutexes[module_id].lock_attr);
	pthread_mutexattr_settype(&__mutexes[module_id].lock_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&__mutexes[module_id].lock, &__mutexes[module_id].lock_attr);

//#ifdef DEBUG
//	__mutexes[module_id].wantlock = strdup(__func__);
//	__mutexes[module_id].lastlock = strdup(__func__);
//#endif

	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "created module mutex %d", module_id);

	return TRUE;
}

void _np_threads_init()
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: np_bool _np_threads_init(){");
	if(FALSE == _np_threads_initiated ){
		_np_threads_initiated = TRUE;
		for(int i = 0; i < PREDEFINED_DUMMY_START; i++){
			np_bool ret = __np_threads_create_module_mutex(i);
			if(FALSE == ret) {
				log_msg(LOG_ERROR,"could not init threading mutex: %d.", i);
				abort();
			}
		}
	}
}

int _np_threads_lock_module(np_module_lock_type module_id, const char* where ) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d.", module_id);

	pthread_once(&__np_thread_init_once, _np_threads_init);

	int ret =  1;
#ifdef DEBUG
	double start = ev_time();
#endif
	while(ret != 0){
#ifdef DEBUG
		double diff = ev_time() - start;
			if(diff > (MUTEX_WAIT_SEC*1000)){
				log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %d (%f sec)", pthread_self(), module_id, diff);
//#ifdef DEBUG
//				for (int i = 0; i < PREDEFINED_DUMMY_START; i++) {
//					log_msg(LOG_ERROR, "mutex %d last lock was at %s", i, __mutexes[i].lastlock);
//					log_msg(LOG_ERROR, "mutex %d last want lock was at %s", i, __mutexes[i].wantlock);
//				}
//#endif
				abort();
			}
			if(diff > (MUTEX_WAIT_SEC*10)){
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id, diff);
			}
#endif

		ret = pthread_mutex_trylock(&__mutexes[module_id].lock);
		if(ret == EBUSY){
//			#ifdef DEBUG
//						free(__mutexes[module_id].wantlock);
//						asprintf(&__mutexes[module_id].wantlock, "%s(%d@%f)", where, pthread_self(), ev_time());
//			#endif
			ev_sleep(MUTEX_WAIT_SEC);
		}else if(ret != 0) {
			log_msg(LOG_ERROR,"error at acquiring mutex for module %d. Error: %s (%d)", module_id, strerror(ret), ret);
		}
		else {
//#ifdef DEBUG
//			free(__mutexes[module_id].lastlock);
//			asprintf(&__mutexes[module_id].lastlock, "%s(%d@%f)", where, pthread_self(),ev_time());
//#endif
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locked module mutex %d.", module_id);
	return ret;
}

int _np_threads_lock_modules(np_module_lock_type module_id_a, np_module_lock_type module_id_b, const char* where)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");

	pthread_once(&__np_thread_init_once, _np_threads_init);

	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locking module mutex %d and mutex %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

	while(ret != 0){
		ret = pthread_mutex_trylock(lock_a);
		if (ret == 0) {
			ret = pthread_mutex_trylock(lock_b);
			if(ret != 0){
//#ifdef DEBUG
//				free(__mutexes[module_id_b].wantlock);
//				asprintf(&__mutexes[module_id_b].wantlock, "%s(%d@%f)", where, pthread_self(),ev_time());
//#endif
				pthread_mutex_unlock(lock_a);
				ev_sleep(MUTEX_WAIT_SEC);
				ret = ret  -100;
			}
		}else{
//#ifdef DEBUG
//			free(__mutexes[module_id_a].wantlock);
//			asprintf(&__mutexes[module_id_a].wantlock, "%s(%d@%f)", where, pthread_self(),ev_time());
//#endif
			ev_sleep(MUTEX_WAIT_SEC);
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "got module mutexes %d and %d.", module_id_a,module_id_b);
	if (ret == 0) {
//#ifdef DEBUG
//		free(__mutexes[module_id_a].lastlock);
//		asprintf(&__mutexes[module_id_a].lastlock, "%s(%d@%f)", where, pthread_self(), ev_time());
//		free(__mutexes[module_id_b].lastlock);
//		asprintf(&__mutexes[module_id_b].lastlock, "%s(%d@%f)", where, pthread_self(), ev_time());
//#endif

	}
	return ret;
}

int _np_threads_unlock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");

	pthread_once(&__np_thread_init_once, _np_threads_init);

	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d and %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

//#ifdef DEBUG
//	free(__mutexes[module_id_a].lastlock);
//	__mutexes[module_id_a].lastlock = strdup("");
//	free(__mutexes[module_id_b].lastlock);
//	__mutexes[module_id_b].lastlock = strdup("");
//#endif

	ret = pthread_mutex_unlock(lock_b);
	ret = pthread_mutex_unlock(lock_a);
	return ret;
}

int _np_threads_unlock_module(np_module_lock_type module_id) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_unlock_module(np_module_lock_type module_id) {");

	pthread_once(&__np_thread_init_once, _np_threads_init);

	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Unlocking module mutex %d.", module_id);
//#ifdef DEBUG
//	free(__mutexes[module_id].lastlock);
//	__mutexes[module_id].lastlock = strdup("");
//#endif

	return pthread_mutex_unlock(&__mutexes[module_id].lock);
}

/** pthread mutex platform wrapper functions following this line **/
int _np_threads_mutex_init(np_mutex_t* mutex)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_init(np_mutex_t* mutex){");
	pthread_mutexattr_init(&mutex->lock_attr);
	pthread_mutexattr_settype(&mutex->lock_attr, PTHREAD_MUTEX_RECURSIVE);
	return pthread_mutex_init(&mutex->lock, &mutex->lock_attr);
}

int _np_threads_mutex_lock(np_mutex_t* mutex) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");
	int ret =  1;
	while(ret != 0) {
		ret = pthread_mutex_trylock(&mutex->lock);
		if(ret == EBUSY){
			ev_sleep(MUTEX_WAIT_SEC);
		}else if(ret != 0) {
			log_msg(LOG_ERROR, "error at acquiring mutex. Error: %s (%d)", strerror(ret), ret);
		}
	}
	return ret;
}

int _np_threads_mutex_unlock(np_mutex_t* mutex)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_unlock(np_mutex_t* mutex){");
	return pthread_mutex_unlock(&mutex->lock);
}
void _np_threads_mutex_destroy(np_mutex_t* mutex)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_mutex_destroy(np_mutex_t* mutex){");
	pthread_mutex_destroy (&mutex->lock);
}
/** pthread condition platform wrapper functions following this line **/
void _np_threads_condition_init(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_init(np_cond_t* condition){");
	pthread_cond_init (&condition->cond, &condition->cond_attr);
}
void _np_threads_condition_init_shared(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_init_shared(np_cond_t* condition){");
	pthread_cond_init (&condition->cond, &condition->cond_attr);
	pthread_condattr_setpshared(&condition->cond_attr, PTHREAD_PROCESS_PRIVATE);
}
void _np_threads_condition_destroy(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_destroy(np_cond_t* condition){");
	pthread_condattr_destroy(&condition->cond_attr);
	pthread_cond_destroy (&condition->cond);
}
int _np_threads_condition_wait(np_cond_t* condition, np_mutex_t* mutex)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_wait(np_cond_t* condition, np_mutex_t* mutex){");
	return pthread_cond_wait(&condition->cond, &mutex->lock);
}
int _np_threads_module_condition_timedwait(np_cond_t* condition, np_module_lock_type module_id, struct timespec* waittime)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_timedwait(np_cond_t* condition, np_module_lock_type module_id, struct timespec* waittime){");
	return pthread_cond_timedwait(&condition->cond, &__mutexes[module_id].lock, waittime);
}
int _np_threads_module_condition_broadcast(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_broadcast(np_cond_t* condition)");
	return pthread_cond_broadcast(&condition->cond);
}

int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id){");
	return pthread_cond_wait(&condition->cond, &__mutexes[module_id].lock);
}
int _np_threads_condition_signal(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_signal(np_cond_t* condition){");
	return pthread_cond_signal(&condition->cond);
}

