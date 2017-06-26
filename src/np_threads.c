/*
 * np_threads.c
 *
 *  Created on: 02.05.2017
 *      Author: sklampt
 */
#include <stdlib.h>
#include <pthread.h>

#include "np_threads.h"

#include "np_types.h"
#include "np_list.h"
#include "np_log.h"


/** predefined module mutex array **/
np_mutex_t __mutexes[PREDEFINED_DUMMY_START-1];
np_bool _np_threads_initiated = FALSE;

np_bool __np_threads_create_module_mutex(np_module_lock_type module_id)
{
    log_msg(LOG_TRACE | LOG_MUTEX, "start: np_bool __np_threads_create_module_mutex(np_module_lock_type module_id){");
	pthread_mutexattr_init(&__mutexes[module_id].lock_attr);
	pthread_mutexattr_settype(&__mutexes[module_id].lock_attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&__mutexes[module_id].lock, &__mutexes[module_id].lock_attr);

	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "created module mutex %d", module_id);

	return TRUE;
}

np_bool _np_threads_init()
{
    log_msg(LOG_TRACE | LOG_MUTEX, "start: np_bool _np_threads_init(){");
	np_bool ret = TRUE;
	if(FALSE == _np_threads_initiated ){
		_np_threads_initiated = TRUE;
		for(int i = 0; i < PREDEFINED_DUMMY_START; i++){
			ret = __np_threads_create_module_mutex(i);
			if(FALSE == ret) {
				log_msg(LOG_ERROR,"Cannot initialize mutex %d.", i);
				break;
			}
		}
	}
	return ret;
}

int _np_threads_lock_module(np_module_lock_type module_id) {
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d.", module_id);
	return pthread_mutex_lock(&__mutexes[module_id].lock);
}

int _np_threads_lock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b) {
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	int ret = -1;
    log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d and %d.", module_id_a,module_id_b);

    pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
    pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

	while(ret != 0){
		ret = pthread_mutex_trylock(lock_a);
		if(ret == 0){
			ret = pthread_mutex_trylock(lock_b);
			if(ret != 0){
				pthread_mutex_unlock(lock_a);
				ev_sleep(0.010); // wait 10ms
			}
		}
	}
	return ret;
}

int _np_threads_unlock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b) {
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	int ret = -1;
    log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d and %d.", module_id_a,module_id_b);

    pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
    pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

	while(ret != 0){
		ret = pthread_mutex_trylock(lock_b);
		if(ret == 0){
			ret = pthread_mutex_trylock(lock_a);
			if(ret != 0){
				pthread_mutex_unlock(lock_b);
				ev_sleep(0.010); // wait 10ms
			}
		}
	}
	return ret;
}



int _np_threads_unlock_module(np_module_lock_type module_id) {
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_unlock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Unlocking module mutex %d.", module_id);
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
int _np_threads_mutex_lock(np_mutex_t* mutex)
{
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");
	return pthread_mutex_lock(&mutex->lock);
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
int _np_threads_condition_signal(np_cond_t* condition)
{
    log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_signal(np_cond_t* condition){");
	return pthread_cond_signal(&condition->cond);
}

