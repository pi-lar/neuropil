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
#include <unistd.h>
#include <float.h>

#include "np_threads.h"

#include "event/ev.h"
#include "pthread.h"

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

int _np_threads_lock_module(np_module_lock_type module_id, char * where ) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d.", module_id);
	if(FALSE == _np_threads_initiated ){
		log_msg(LOG_WARN, "Indirect threads init");
		_np_threads_init();
	}
	int ret =  1;
#ifdef DEBUG
	double start = np_time_now();
#endif

#ifdef CHECK_THREADING 
	char * tmp;
	asprintf(&tmp, "%d@%s", module_id, where);
	CHECK_MALLOC(tmp);

	np_thread_t* self_thread = _np_threads_get_self();
	if (self_thread != NULL)
	{
		_LOCK_ACCESS(&(self_thread->locklists_lock)) {
			sll_prepend(char_ptr, self_thread->want_lock, tmp);
		}
	}
#endif
	double diff = 0;
	while(ret != 0){
#ifdef DEBUG
		diff = np_time_now() - start;
			if(diff >MUTEX_WAIT_MAX_SEC) {
				log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id, diff);
#ifdef CHECK_THREADING			
				log_msg(LOG_ERROR, np_threads_printpool(FALSE));
#endif
				abort();
			}
			if(diff >  MUTEX_WAIT_SOFT_SEC){
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id, diff);
			}
#endif
		__NP_THREADS_GET_MUTEX_DEFAULT_WAIT(__np_default_wait, diff);
		ret = pthread_mutex_timedlock(&__mutexes[module_id].lock, __np_default_wait);
		if(ret == ETIMEDOUT) {			
			//continue;
		}else if(ret != 0) {
			log_msg(LOG_ERROR,"error at acquiring mutex for module %d. Error: %s (%d)", module_id, strerror(ret), ret);
		}
		else { // ret == 0
#ifdef CHECK_THREADING	
			if (self_thread != NULL)
			{
				_LOCK_ACCESS(&(self_thread ->locklists_lock))
				{
					sll_prepend(char_ptr, self_thread->has_lock, tmp);
					_sll_char_remove(self_thread->want_lock, tmp, strlen(tmp));
				}
			}
#endif
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locked module mutex %d.", module_id);
	return ret;
}

int _np_threads_lock_modules(np_module_lock_type module_id_a, np_module_lock_type module_id_b, char* where)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	if(FALSE == _np_threads_initiated ){
		log_msg(LOG_WARN, "Indirect threads init");
		_np_threads_init();
	}
	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locking module mutex %d and mutex %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;
#ifdef CHECK_THREADING
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

#endif
	double start = np_time_now();
	double diff = 0;
	while(ret != 0) {
		__NP_THREADS_GET_MUTEX_DEFAULT_WAIT(__np_default_wait, diff);
		ret = pthread_mutex_timedlock(lock_a, __np_default_wait);
#ifdef DEBUG
		diff = np_time_now() - start;
#endif
		if (ret == 0) {
			__NP_THREADS_GET_MUTEX_DEFAULT_WAIT(__np_default_wait2, diff);
			ret = pthread_mutex_timedlock(lock_b, __np_default_wait2);			
#ifdef DEBUG
			diff = np_time_now() - start;
#endif

			if(ret != 0) {
#ifdef DEBUG
				if (diff >MUTEX_WAIT_MAX_SEC) {
					log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id_b, diff);
#ifdef CHECK_THREADING			
					log_msg(LOG_ERROR, np_threads_printpool(FALSE));
#endif
					abort();
				}
				if (diff >  MUTEX_WAIT_SOFT_SEC) {
					log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id_b, diff);
				}
#endif

				ret = pthread_mutex_unlock(lock_a);
				ret = ret -100;
			}
		}else{
#ifdef DEBUG
			if (diff >MUTEX_WAIT_MAX_SEC) {
				log_msg(LOG_ERROR, "Thread %d waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id_a, diff);
#ifdef CHECK_THREADING			
				log_msg(LOG_ERROR, np_threads_printpool(FALSE));
#endif
				abort();
			}
			if (diff >  MUTEX_WAIT_SOFT_SEC) {
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id_a, diff);
			}
#endif
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "got module mutexes %d and %d.", module_id_a,module_id_b);
#ifdef CHECK_THREADING
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
	if(FALSE == _np_threads_initiated ){
		log_msg(LOG_WARN, "Indirect threads init");
		_np_threads_init();
	}
	int ret = -1;
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d and %d.", module_id_a,module_id_b);

	pthread_mutex_t* lock_a = &__mutexes[module_id_a].lock;
	pthread_mutex_t* lock_b = &__mutexes[module_id_b].lock;

	ret = pthread_mutex_unlock(lock_b);
#ifdef CHECK_THREADING
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
#ifdef CHECK_THREADING
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
	if(FALSE == _np_threads_initiated ){
		log_msg(LOG_WARN, "Indirect threads init");
		_np_threads_init();
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Unlocking module mutex %d.", module_id);
	int ret = pthread_mutex_unlock(&__mutexes[module_id].lock);
#ifdef CHECK_THREADING
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
int _np_threads_mutex_init(np_mutex_t* mutex,char* desc)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_init(np_mutex_t* mutex){");
	mutex->desc = strdup(desc);
	pthread_mutexattr_init(&mutex->lock_attr);
	pthread_mutexattr_settype(&mutex->lock_attr, PTHREAD_MUTEX_RECURSIVE);
	return pthread_mutex_init(&mutex->lock, &mutex->lock_attr);
}

int _np_threads_mutex_lock(np_mutex_t* mutex) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");
	int ret =  1;
	double start = np_time_now();
	double diff = 0;
	while(ret != 0) {
		__NP_THREADS_GET_MUTEX_DEFAULT_WAIT(__np_default_wait, diff);
		ret = pthread_mutex_timedlock(&mutex->lock, __np_default_wait);
		
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
int _np_threads_condition_broadcast(np_cond_t* condition)
{
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_condition_broadcast(np_cond_t* condition)");
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

#ifdef CHECK_THREADING
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

#ifdef CHECK_THREADING
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

#ifdef CHECK_THREADING
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

		if (FALSE && pool_size > PRIORITY_MOD_BEST_SINGLE_THREADED) {

			if(i <= PRIORITY_MOD_BEST_SINGLE_THREADED) {
				new_thread->max_job_priority = i * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
				new_thread->min_job_priority = i * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
			}
			else {
				new_thread->max_job_priority = PRIORITY_MOD_LOWEST * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
				new_thread->min_job_priority = PRIORITY_MOD_BEST_SINGLE_THREADED * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
			}
		}
		else {
			new_thread->max_job_priority = PRIORITY_MOD_LOWEST  * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
			new_thread->min_job_priority = PRIORITY_MOD_HIGHEST * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
		}

		sll_append(np_thread_ptr, _np_state()->threads, new_thread);

		log_debug_msg(LOG_DEBUG, "neuropil worker thread started: %p", _np_state()->thread_ids[i]);
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

	_np_state()->thread_count = pool_size;
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

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_0, 0.0, MISC_SEND_PINGS_SEC,					_np_glia_send_pings, "_np_glia_send_pings");

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC,	_np_event_cleanup_msgpart_cache, "_np_event_cleanup_msgpart_cache");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_SEND_PIGGY_REQUESTS_SEC,			_np_glia_send_piggy_requests, "_np_glia_send_piggy_requests");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_2, 0.0, MISC_RETRANSMIT_MSG_TOKENS_SEC,			_np_retransmit_message_tokens_jobexec, "_np_retransmit_message_tokens_jobexec");

	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_ACKENTRY_CLEANUP_INTERVAL_SEC,		_np_cleanup_ack_jobexec, "_np_cleanup_ack_jobexec");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_KEYCACHE_CLEANUP_INTERVAL_SEC,		_np_cleanup_keycache_jobexec, "_np_cleanup_keycache_jobexec");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_CHECK_ROUTES_SEC,					_np_glia_check_neighbours, "_np_glia_check_neighbours");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_3, 0.0, MISC_SEND_UPDATE_MSGS_SEC,				_np_glia_check_routes, "_np_glia_check_routes");

	//TODO: reanable _np_renew_node_token_jobexec
	//np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_4, 0.0, MISC_RENEW_NODE_SEC,					_np_renew_node_token_jobexec, "_np_renew_node_token_jobexec");
	np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_4, 0.0, MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC,		_np_event_rejoin_if_necessary, "_np_event_rejoin_if_necessary");


	// TODO: move output to example helpers
	log_debug_msg(LOG_DEBUG, "%s event loop with %d threads started", NEUROPIL_RELEASE, pool_size);
	log_msg(LOG_INFO, "%s", NEUROPIL_COPYRIGHT);
	log_msg(LOG_INFO, "%s", NEUROPIL_TRADEMARK);

	fprintf(stdout, "\n");
	fprintf(stdout, "%s initializiation successful\n", NEUROPIL_RELEASE);
	fprintf(stdout, "%s event loop with %d worker threads started\n", NEUROPIL_RELEASE, pool_size);
	fprintf(stdout, "your neuropil node will be addressable as:\n");
	fprintf(stdout, "\n");

	char* connection_str = np_get_connection_string();
	fprintf(stdout, "\t%s\n", connection_str);
	free(connection_str);

	fprintf(stdout, "\n");
	fprintf(stdout, "%s\n", NEUROPIL_COPYRIGHT);
	fprintf(stdout, "%s\n", NEUROPIL_TRADEMARK);
	fprintf(stdout, "\n");
	fflush(stdout);
}