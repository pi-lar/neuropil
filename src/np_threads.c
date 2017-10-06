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
#include <unistd.h>

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

int _np_threads_lock_module(np_module_lock_type module_id, const char * where ) {
	log_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %d.", module_id);
	if(FALSE == _np_threads_initiated ){
		log_msg(LOG_WARN, "Indirect threads init");
		_np_threads_init();
	}
	int ret =  1;
#ifdef DEBUG
	double start = ev_time();
#endif

#ifdef CHECK_THREADING 
	char * tmp;
	asprintf(&tmp, "%d@%s", module_id, where);
	CHECK_MALLOC(tmp);

	np_thread_t* self_thread = _np_threads_get_self();
	if (self_thread != NULL)
	{
		_LOCK_ACCESS(&(self_thread ->locklists_lock)) {
			sll_prepend(char_ptr, self_thread->want_lock, tmp);
		}
	}
#endif

	while(ret != 0){
#ifdef DEBUG
		double diff = ev_time() - start;
			if(diff > (MUTEX_WAIT_SEC*1000)){
				log_msg(LOG_ERROR, "Thread %lu waits too long for module mutex %"PRIu32" (%f sec)", self_thread->id, module_id, diff);
#ifdef CHECK_THREADING			
				log_msg(LOG_ERROR, "%s", np_threads_printpool(FALSE));
#endif
				abort();
			}
			if(diff > (MUTEX_WAIT_SEC*10)){
				log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %d (%f sec)", module_id, diff);
			}
#endif

		ret = pthread_mutex_trylock(&__mutexes[module_id].lock);

		if(ret == EBUSY){			
			ev_sleep(MUTEX_WAIT_SEC);
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

int _np_threads_lock_modules(np_module_lock_type module_id_a, np_module_lock_type module_id_b, const char* where)
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
	while(ret != 0) {
		ret = pthread_mutex_trylock(lock_a);
		if (ret == 0) {
			ret = pthread_mutex_trylock(lock_b);
			if(ret != 0) {
				pthread_mutex_unlock(lock_a);
				ev_sleep(MUTEX_WAIT_SEC);
				ret = ret -100;
			}
		}else{
			ev_sleep(MUTEX_WAIT_SEC);
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

#ifdef CHECK_THREADING
	_np_threads_mutex_init(&thread->locklists_lock);
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
