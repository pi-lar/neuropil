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
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>

#include <unistd.h>
#include <float.h>

#include "np_threads.h"

#include "event/ev.h"
#include "pthread.h"

#include "dtime.h"
#include "neuropil.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_log.h"
#include "np_settings.h"
#include "np_constants.h"


#include "np_jobqueue.h"
#include "np_glia.h"
#include "np_event.h"

/** predefined module mutex array **/
np_mutex_t __mutexes[PREDEFINED_DUMMY_START-1];
np_bool    __np_threads_mutexes_initiated = FALSE;
np_bool    __np_threads_threads_initiated = FALSE;

static pthread_once_t __thread_init_once = PTHREAD_ONCE_INIT;

void __np_threads_create_module_mutex()
{
	for(int module_id = 0; module_id < PREDEFINED_DUMMY_START; module_id++) {
		pthread_mutexattr_init(&__mutexes[module_id].lock_attr);
		pthread_mutexattr_settype(&__mutexes[module_id].lock_attr, PTHREAD_MUTEX_RECURSIVE);
		pthread_mutex_init(&__mutexes[module_id].lock, &__mutexes[module_id].lock_attr);

		log_debug_msg(LOG_MUTEX | LOG_DEBUG, "created module mutex %d", module_id);
	}
	__np_threads_mutexes_initiated = TRUE;
}

np_bool _np_threads_init()
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: np_bool _np_threads_init(){");
	pthread_once(&__thread_init_once, __np_threads_create_module_mutex);
	return (__np_threads_mutexes_initiated);
}

int _np_threads_lock_module(np_module_lock_type module_id, const char * where ) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d.", module_id);
	if(FALSE == __np_threads_mutexes_initiated ){
		pthread_once(&__thread_init_once, __np_threads_create_module_mutex);
	}
	int ret =  1;

#ifndef NP_THREADS_CHECK_THREADING 
	ret = pthread_mutex_lock(&__mutexes[module_id].lock);
#else
	double start = np_time_now();

	char * tmp = NULL;

	np_thread_t* self_thread = _np_threads_get_self();
	if (self_thread != NULL)
	{
		asprintf(&tmp, "%d@%s", module_id, where);
		CHECK_MALLOC(tmp);

		_LOCK_ACCESS(&(self_thread->locklists_lock)) {
			sll_prepend(char_ptr, self_thread->want_lock, tmp);
		}
	}
	double diff = 0;
	while(ret != 0){
		diff = np_time_now() - start;
			if(diff >MUTEX_WAIT_MAX_SEC) {				
				log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id, diff);
				log_msg(LOG_ERROR, np_threads_printpool(FALSE));
				abort();
			}
			if(diff >  MUTEX_WAIT_SOFT_SEC){
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id, diff);
			}
		ret = _np_threads_mutex_timedlock(&__mutexes[module_id], min(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));

		if(ret == ETIMEDOUT) {			
			//continue;
		}else if(ret != 0) {
			log_msg(LOG_ERROR,"error at acquiring mutex for module %d. Error: %s (%d)", module_id, strerror(ret), ret);
		}
		else { // ret == 0
			if (self_thread != NULL)
			{
				_LOCK_ACCESS(&(self_thread->locklists_lock))
				{
					sll_prepend(char_ptr, self_thread->has_lock, tmp);
					_sll_char_remove(self_thread->want_lock, tmp, strlen(tmp));
				}
			}
		}
	}
#endif

	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locked module mutex %d.", module_id);
	return ret;
}

int _np_threads_mutex_timedlock(np_mutex_t * mutex, const double timeout)
{
	int ret = -1;
#if NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK
	{
		struct timeval tv_sleep = dtotv(np_time_now() + timeout);
		struct timespec waittime = { .tv_sec = tv_sleep.tv_sec,.tv_nsec = tv_sleep.tv_usec * 1000 };

		ret = pthread_mutex_timedlock(&mutex->lock, &waittime);
	}
#else
	{
		double start = np_time_now();
		do
		{
			ret = pthread_mutex_trylock(&mutex->lock);
			if (ret == EBUSY)
			{
				struct timespec ts;
				ts.tv_sec = 0;
				ts.tv_nsec= 20/*ms*/ * 1000000; // to nanoseconds
				
				int status = -1;
				while (status == -1)
					status = nanosleep(&ts, &ts);
			}
			else
				break;
		} while (ret != 0 && (np_time_now() - start) <= timeout);
	}
#endif
	return ret;
}

int _np_threads_lock_modules(np_module_lock_type module_id_a, np_module_lock_type module_id_b, const char* where)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	if(FALSE == __np_threads_mutexes_initiated ){
		pthread_once(&__thread_init_once, __np_threads_create_module_mutex);
	}
	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locking module mutex %d and mutex %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

#ifndef NP_THREADS_CHECK_THREADING
	ret = pthread_mutex_lock(lock_a);
	if (ret == 0) {
		ret = pthread_mutex_lock(lock_b);
	}
#else
	char * tmp_a = NULL;
	asprintf(&tmp_a, "%d@%s", module_id_a, where);
	CHECK_MALLOC(tmp_a);
	char * tmp_b = NULL;
	asprintf(&tmp_b, "%d@%s", module_id_b, where);
	CHECK_MALLOC(tmp_b);
	np_thread_t* self_thread = _np_threads_get_self();

	if (self_thread != NULL)
	{
		_LOCK_ACCESS(&(self_thread ->locklists_lock)) {

			sll_prepend(char_ptr, self_thread->want_lock, tmp_a);
			sll_prepend(char_ptr, self_thread->want_lock, tmp_b);
		}
	}

	double start = np_time_now();
	double diff = 0;
	while(ret != 0) {		
		ret = _np_threads_mutex_timedlock(&__mutexes[module_id_a], min(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));
		diff = np_time_now() - start;
		if (ret == 0) {
			ret = _np_threads_mutex_timedlock(&__mutexes[module_id_b], min(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));
			diff = np_time_now() - start;

			if(ret != 0) {
				if (diff > MUTEX_WAIT_MAX_SEC) {					
					log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id_b, diff);
					log_msg(LOG_ERROR, np_threads_printpool(FALSE));
					abort();
				}
				if (diff >  MUTEX_WAIT_SOFT_SEC) {
					log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id_b, diff);
				}
				ret = pthread_mutex_unlock(lock_a);
				ret = ret -100;
			}
		}else{
			if (diff > MUTEX_WAIT_MAX_SEC) {				
				log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id_a, diff);
				log_msg(LOG_ERROR, np_threads_printpool(FALSE));
				abort();
			}
			if (diff >  MUTEX_WAIT_SOFT_SEC) {
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id_a, diff);
			}
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "got module mutexes %d and %d.", module_id_a,module_id_b);
	if (ret == 0) {
		np_thread_t* self_thread = _np_threads_get_self();
		if (self_thread != NULL)	{
			_LOCK_ACCESS(&(self_thread->locklists_lock))
			{
				sll_prepend(char_ptr, self_thread->has_lock, tmp_a);
				sll_prepend(char_ptr, self_thread->has_lock, tmp_b);
				_sll_char_remove(self_thread->want_lock, tmp_a, strlen(tmp_a));
				_sll_char_remove(self_thread->want_lock, tmp_b, strlen(tmp_b));
				
			}
		}
	}
#endif
	return ret;
}

int _np_threads_unlock_modules(np_module_lock_type module_id_a,np_module_lock_type module_id_b) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	if(FALSE == __np_threads_mutexes_initiated ){
		pthread_once(&__thread_init_once, __np_threads_create_module_mutex);
	}
	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d and %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

	ret = pthread_mutex_unlock(lock_b);
#ifdef NP_THREADS_CHECK_THREADING
	char * tmp = NULL;
	char * rm = NULL;
	np_thread_t* self_thread = _np_threads_get_self();

	if(ret == 0){		
		asprintf(&tmp, "%d@", module_id_b);
		_LOCK_ACCESS(&(self_thread ->locklists_lock) ){
			rm = _sll_char_remove(self_thread->has_lock, tmp, strlen(tmp));
			free(rm);
		}
		free(tmp);
	}
#endif

	ret = pthread_mutex_unlock(lock_a);
#ifdef NP_THREADS_CHECK_THREADING
	if (ret == 0 && self_thread != NULL) {
		asprintf(&tmp, "%d@", module_id_a);
		_LOCK_ACCESS(&(self_thread ->locklists_lock)) {
			rm = _sll_char_remove(self_thread->has_lock, tmp, strlen(tmp));
			free(rm);
		}
		free(tmp);
	}
#endif

	return ret;
}

int _np_threads_unlock_module(np_module_lock_type module_id) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_unlock_module(np_module_lock_type module_id) {");
	if(FALSE == __np_threads_mutexes_initiated ){
		pthread_once(&__thread_init_once, __np_threads_create_module_mutex);
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Unlocking module mutex %d.", module_id);
	int ret = pthread_mutex_unlock(&__mutexes[module_id].lock);
#ifdef NP_THREADS_CHECK_THREADING
	char * tmp = NULL;
	np_thread_t* self_thread = _np_threads_get_self();

	if (ret == 0 && self_thread  != NULL)
	{		
		asprintf(&tmp, "%d@", module_id);
		_LOCK_ACCESS(&(self_thread ->locklists_lock)) {
			char * rm = _sll_char_remove(self_thread->has_lock, tmp, strlen(tmp));
			free(rm);
		}
		free(tmp);
	}
#endif

	return ret;
}

/** pthread mutex platform wrapper functions following this line **/
int _np_threads_mutex_init(np_mutex_t* mutex, const char* desc)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_init(np_mutex_t* mutex){");
	int ret = 0;
	mutex->desc = strdup(desc);
	pthread_mutexattr_init(&mutex->lock_attr);
	pthread_mutexattr_settype(&mutex->lock_attr, PTHREAD_MUTEX_RECURSIVE);

	_np_threads_condition_init(&mutex->condition);

	ret = pthread_mutex_init(&mutex->lock, &mutex->lock_attr);
	if (ret != 0)
	{
		log_msg(LOG_ERROR, "pthread_mutex_init: %s (%d)",
			strerror(ret), ret);
	}
	return ret;
}

int _np_threads_mutex_lock(np_mutex_t* mutex) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");
	int ret =  1;
#ifdef DEBUG
	double diff = 0;
	double start = np_time_now();
#endif
	while(ret != 0) {
		// TODO: review lock warn system
		// ret = _np_threads_mutex_timedlock(mutex, min(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));
		ret = pthread_mutex_lock(&mutex->lock);

#ifdef DEBUG
		diff = np_time_now() - start;
		if (diff > MUTEX_WAIT_MAX_SEC) {
			log_msg(LOG_ERROR, "Thread %d waits too long for mutex %p / %s (%f sec)", _np_threads_get_self()->id, mutex, mutex->desc, diff);
			abort();
		}
		if (diff > MUTEX_WAIT_SOFT_SEC) {
			log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for mutex %p (%f sec)", mutex, diff);
		}
#endif

		if(ret != ETIMEDOUT && ret != 0) {
			log_msg(LOG_ERROR, "error at acquiring mutex. Error: %s (%d)", strerror(ret), ret);
			abort();
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
	free(mutex->desc);
	_np_threads_condition_destroy(&mutex->condition);
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

int _np_threads_mutex_condition_timedwait(np_mutex_t* mutex, struct timespec* waittime)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_timedwait(np_cond_t* condition, np_module_lock_type module_id, struct timespec* waittime){");
	return pthread_cond_timedwait(&mutex->condition.cond, &mutex->lock, waittime);
}

int _np_threads_condition_broadcast(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_broadcast(np_cond_t* condition)");
	return pthread_cond_broadcast(&condition->cond);
}

int _np_threads_module_condition_broadcast(np_module_lock_type module_id)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_broadcast(np_cond_t* condition)");
	return pthread_cond_broadcast(&__mutexes[module_id].condition.cond);
}

int _np_threads_module_condition_signal(np_module_lock_type module_id)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_broadcast(np_cond_t* condition)");
	return pthread_cond_signal(&__mutexes[module_id].condition.cond);
}

int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id){");
	return pthread_cond_wait(&condition->cond, &__mutexes[module_id].lock);
}


int _np_threads_mutex_condition_wait(np_mutex_t* mutex)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_module_condition_wait(np_cond_t* condition, np_module_lock_type module_id){");
	return pthread_cond_wait(&mutex->condition.cond, &mutex->lock);
}

int _np_threads_condition_signal(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_signal(np_cond_t* condition){");
	return pthread_cond_signal(&condition->cond);
}

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_thread_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_thread_ptr);


np_thread_t*_np_threads_get_self()
{
	np_thread_t* ret = NULL;

	if (_np_state() != NULL)
	{
		unsigned long id_to_find = (unsigned long)pthread_self();

		sll_iterator(np_thread_ptr) iter_threads = sll_first(_np_state()->threads);
		while (iter_threads != NULL)
		{
			if (iter_threads->val->id == id_to_find) {
				ret = iter_threads->val;
				break;
			}
			sll_next(iter_threads);
		}

		if (ret == NULL) {
			id_to_find = (unsigned long)getpid();

			iter_threads = sll_first(_np_state()->threads);
			while (iter_threads != NULL)
			{
				if (iter_threads->val->id == id_to_find) {
					ret = iter_threads->val;
					break;
				}
				sll_next(iter_threads);
			}
		}
	}
	return ret;
}
void _np_thread_t_del(void* obj)
{
	log_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_del(void* nw){");
	np_thread_t* thread = (np_thread_t*)obj;

#ifdef NP_THREADS_CHECK_THREADING

	_LOCK_ACCESS(&thread->locklists_lock){
		sll_iterator(char_ptr) iter_has_lock = sll_first(thread->has_lock);
		while (iter_has_lock != NULL)
		{
			free(iter_has_lock->val);
			sll_next(iter_has_lock);
		}
		sll_free(char_ptr, thread->has_lock);

		sll_iterator(char_ptr) iter_want_lock = sll_first(thread->want_lock);
		while (iter_want_lock != NULL)
		{
			free(iter_want_lock->val);
			sll_next(iter_want_lock);
		}

		sll_free(char_ptr, thread->want_lock);
	}
	_np_threads_mutex_destroy(&thread->locklists_lock);

#endif
	
}
void _np_thread_t_new(void* obj)
{
	log_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_new(void* nw){");
	np_thread_t* thread = (np_thread_t*)obj;

	thread->max_job_priority = DBL_MAX;
	thread->min_job_priority = 0;

#ifdef NP_THREADS_CHECK_THREADING
	_np_threads_mutex_init(&thread->locklists_lock,"thread locklist");
	sll_init(char_ptr, thread->has_lock);
	sll_init(char_ptr, thread->want_lock);
#endif
}

char* np_threads_printpool(np_bool asOneLine) {
	char* ret = NULL;
	char* new_line = "\n";
	if (asOneLine == TRUE) {
		new_line = "    ";
	}

	sll_iterator(np_thread_ptr) iter_threads = sll_first(_np_state()->threads);
	ret = _np_concatAndFree(ret, "--- Threadpool START ---%s", new_line);

#ifdef NP_THREADS_CHECK_THREADING
	np_sll_t(char_ptr, tmp);
	char * tmp2;
	while (iter_threads != NULL)
	{
		_LOCK_ACCESS(&(iter_threads->val->locklists_lock)) {
			tmp = _sll_char_part(iter_threads->val->has_lock, -5);
			tmp2 = _sll_char_make_flat(tmp);
			sll_free(char_ptr, tmp);
			ret = _np_concatAndFree(ret, "Thread %"PRIu32" LOCKS: %s%s", iter_threads->val->id, tmp2, new_line);
			free(tmp2);

			tmp = _sll_char_part(iter_threads->val->want_lock, -5);
			tmp2 = _sll_char_make_flat(tmp);
			sll_free(char_ptr, tmp);
			ret = _np_concatAndFree(ret, "Thread %"PRIu32" WANTS LOCKS: %s%s", iter_threads->val->id, tmp2, new_line);
			free(tmp2);

		}
		sll_next(iter_threads);
	}
#else
	while (iter_threads != NULL)
	{
		ret = _np_concatAndFree(ret, "Thread %"PRIu32" %s", iter_threads->val->id, new_line);
		sll_next(iter_threads);
	}
#endif
	ret = _np_concatAndFree(ret, "--- Threadpool END   ---%s", new_line);

	return ret;
}


np_thread_t * __np_createThread(uint8_t number, void *(fn)(void *)) {
	pthread_create(&_np_state()->thread_ids[number], &_np_state()->attr, fn, (void *)_np_state());
	np_thread_t * new_thread;
	np_new_obj(np_thread_t, new_thread);
	new_thread->id = (unsigned long)_np_state()->thread_ids[number];

	return new_thread;
}

void __np_createThreadPool(uint8_t pool_size) {
	/* create the thread pool */
	for (uint8_t i = 0; i < pool_size; i++)
	{
		np_thread_t* new_thread = __np_createThread(i, __np_jobqueue_run);

		if (
			(PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD && pool_size > 2 && i == 0) ||
			(PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD && pool_size > 3 && i == 1) ||
			(PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD && pool_size > 4 && i == 2) ||
			(PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD && pool_size > 5 && i == 3) ||
			(PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD && pool_size > 6 && i == 4) ||
			(PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD && pool_size > 7 && i == 5) ||
			(PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD && pool_size > 8 && i == 6)
		) {
			new_thread->max_job_priority = (i+1) * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
			new_thread->min_job_priority = i     * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
		}
		else {
			new_thread->max_job_priority = PRIORITY_MOD_LOWEST  * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
			new_thread->min_job_priority = PRIORITY_MOD_HIGHEST * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
		}

		sll_append(np_thread_ptr, _np_state()->threads, new_thread);

		log_debug_msg(LOG_THREADS |LOG_DEBUG, "neuropil worker thread started: %p", _np_state()->thread_ids[i]);
	}
}

void np_start_job_queue(uint8_t pool_size)
{
	log_msg(LOG_TRACE, "start: void np_start_job_queue(uint8_t pool_size){");
	if (pthread_attr_init(&_np_state()->attr) != 0)
	{
		log_msg(LOG_ERROR, "pthread_attr_init: %s", strerror(errno));
		return;
	}

	if (pthread_attr_setscope(&_np_state()->attr, PTHREAD_SCOPE_SYSTEM) != 0)
	{
		log_msg(LOG_ERROR, "pthread_attr_setscope: %s", strerror(errno));
		return;
	}

	if (pthread_attr_setdetachstate(&_np_state()->attr, PTHREAD_CREATE_DETACHED) != 0)
	{
		log_msg(LOG_ERROR, "pthread_attr_setdetachstate: %s", strerror(errno));
		return;
	}

	_np_state()->thread_count += pool_size;
	_np_state()->thread_ids = (pthread_t *)malloc(sizeof(pthread_t) * pool_size);

	CHECK_MALLOC(_np_state()->thread_ids);

	np_bool create_own_event_thread = FALSE;
	if (pool_size >= 2) {
		pool_size--;
		create_own_event_thread = TRUE;
	}

	__np_createThreadPool(pool_size);
	//start jobs

	if (create_own_event_thread) {
		__np_createThread(pool_size, _np_event_run);
	}
	else {
		np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_0, 0.0, MISC_READ_EVENTS_SEC,				_np_events_read, "_np_events_read");
	}

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_1, 0.0, MISC_SEND_PINGS_SEC,					_np_glia_send_pings, "_np_glia_send_pings");

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC,	_np_event_cleanup_msgpart_cache, "_np_event_cleanup_msgpart_cache");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_SEND_PIGGY_REQUESTS_SEC,			_np_glia_send_piggy_requests, "_np_glia_send_piggy_requests");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_RETRANSMIT_MSG_TOKENS_SEC,			_np_retransmit_message_tokens_jobexec, "_np_retransmit_message_tokens_jobexec");

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_ACKENTRY_CLEANUP_INTERVAL_SEC,		_np_cleanup_ack_jobexec, "_np_cleanup_ack_jobexec");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_KEYCACHE_CLEANUP_INTERVAL_SEC,		_np_cleanup_keycache_jobexec, "_np_cleanup_keycache_jobexec");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_CHECK_ROUTES_SEC,					_np_glia_check_neighbours, "_np_glia_check_neighbours");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, MISC_CHECK_ROUTES_SEC/2, MISC_CHECK_ROUTES_SEC, _np_glia_check_routes, "_np_glia_check_routes");

	//TODO: re-enable _np_renew_node_token_jobexec
	//np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_4, 0.0, MISC_RENEW_NODE_SEC,					_np_renew_node_token_jobexec, "_np_renew_node_token_jobexec");

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_4, 0.0, MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC, _np_event_rejoin_if_necessary, "_np_event_rejoin_if_necessary");
	np_job_submit_event_periodic(PRIORITY_MOD_LOWEST, 0.0, MISC_LOG_FLUSH_INTERVAL_SEC, _np_glia_log_flush, "_np_glia_log_flush");

	
	_LOCK_MODULE(np_threads_t){
		__np_threads_threads_initiated = TRUE;
	}
	log_debug_msg(LOG_THREADS | LOG_DEBUG, "%s event loop with %d threads started", NEUROPIL_RELEASE, pool_size);
	log_msg(LOG_INFO, "%s", NEUROPIL_COPYRIGHT);
	log_msg(LOG_INFO, "%s", NEUROPIL_TRADEMARK);

}

np_bool _np_threads_is_threadding_initiated() {
	np_bool ret;
	_LOCK_MODULE(np_threads_t) {
		ret = __np_threads_threads_initiated;
	}
	return ret;
}
