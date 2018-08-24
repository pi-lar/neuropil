//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <float.h>
#include <math.h>

#include "np_threads.h"

#include "event/ev.h"
#include "pthread.h"

#include "dtime.h"
#include "np_legacy.h"
#include "np_key.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_log.h"
#include "np_settings.h"
#include "np_msgproperty.h"
#include "np_constants.h"
#include "np_network.h"

#include "np_jobqueue.h"
#include "np_glia.h"
#include "np_event.h"


/** predefined module mutex array **/
np_module_struct(threads) {
	np_state_t* context;
	np_mutex_t __mutexes[PREDEFINED_DUMMY_START];
	bool    __np_threads_threads_initiated;
	pthread_once_t __thread_init_once;
	pthread_key_t  __pthread_thread_ptr_key;

	pthread_attr_t attr;

	
	TSP(np_sll_type(np_thread_ptr), threads);

};

bool _np_threads_init(np_state_t* context)
{
	if (!np_module_initiated(threads))
	{
		np_module_malloc(threads);		
		_module->__np_threads_threads_initiated = false;
		
		pthread_key_create(&_module->__pthread_thread_ptr_key, NULL);

		// init module mutexes
		for (int module_id = 0; module_id < PREDEFINED_DUMMY_START; module_id++) {
			pthread_mutexattr_init(&_module->__mutexes[module_id].lock_attr);
			pthread_mutexattr_settype(&_module->__mutexes[module_id].lock_attr, PTHREAD_MUTEX_RECURSIVE);
			pthread_mutex_init(&_module->__mutexes[module_id].lock, &_module->__mutexes[module_id].lock_attr);
			_module->__mutexes[module_id].desc = np_module_lock_str[module_id];
			log_debug_msg(LOG_MUTEX | LOG_DEBUG, "created module mutex %d", module_id);
		}

		_module->threads = sll_init_part(np_thread_ptr);
		TSP_INIT(_module->threads);
	}
	return true;
}

int _np_threads_lock_module(np_state_t* context, np_module_lock_type module_id, const char * where ) {
    //log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");

    log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locking module mutex %d/%s.", module_id, np_module_lock_str[module_id]);

	_np_threads_init(context);
    int ret =  1;

#if defined(NP_THREADS_CHECK_THREADING) 
	char * tmp = NULL;
	np_thread_t* self_thread = _np_threads_get_self(context);
	if (self_thread != NULL)
	{
		asprintf(&tmp, "%s@%s", np_module_lock_str[module_id], where);
		CHECK_MALLOC(tmp);

		_LOCK_ACCESS(&(self_thread->locklists_lock)) {
			sll_prepend(char_ptr, self_thread->want_lock, tmp);
		}
}
#endif
#if !defined(NP_THREADS_CHECK_THREADING) || !NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK
    ret = pthread_mutex_lock(&np_module(threads)->__mutexes[module_id].lock);
#else
    double start = np_time_now();
   
    double diff = 0;
    while(ret != 0){
        diff = np_time_now() - start;
            if(diff >MUTEX_WAIT_MAX_SEC) {
                log_msg(LOG_ERROR, "Thread %lu waits too long for module mutex %s (%f sec)", self_thread->id, np_module_lock_str[module_id], diff);
                log_msg(LOG_ERROR, "%s", np_threads_printpool(context, false));
                abort();
            }
            if(diff >  MUTEX_WAIT_SOFT_SEC){
                log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for module mutex %s (%f sec)", np_module_lock_str[module_id], diff);
            }
        ret = _np_threads_mutex_timedlock(context, &np_module(threads)->__mutexes[module_id], fmin(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));

        if(ret == ETIMEDOUT) {
            //continue;
        }else if(ret != 0) {
            log_msg(LOG_ERROR,"error at acquiring mutex for module %s. Error: %s (%d)", np_module_lock_str[module_id], strerror(ret), ret);
        }
    }
#endif
#if defined(NP_THREADS_CHECK_THREADING) 

	if (self_thread != NULL)
	{
		_LOCK_ACCESS(&(self_thread->locklists_lock))
		{
			sll_prepend(char_ptr, self_thread->has_lock, tmp);
			_sll_char_remove(self_thread->want_lock, tmp, strlen(tmp));
		}
	}
	log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locked module mutex %d/%s.", module_id, np_module_lock_str[module_id]);

#endif

    
    return ret;
}

int _np_threads_mutex_timedlock(np_state_t* context, np_mutex_t * mutex, const double timeout)
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

int _np_threads_unlock_modules(np_state_t* context, np_module_lock_type module_id_a,np_module_lock_type module_id_b) {
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");
	
    int ret = -1;
    log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Locking module mutex %s and %s.", np_module_lock_str[module_id_a], np_module_lock_str[module_id_b]);

    pthread_mutex_t* lock_a = &np_module(threads)->__mutexes[module_id_a].lock;
    pthread_mutex_t* lock_b = &np_module(threads)->__mutexes[module_id_b].lock;

    ret = pthread_mutex_unlock(lock_b);
#ifdef NP_THREADS_CHECK_THREADING
    char * tmp = NULL;
    char * rm = NULL;
    np_thread_t* self_thread = _np_threads_get_self(context);

    if(ret == 0){
        asprintf(&tmp, "%s@", np_module_lock_str[module_id_b]);
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
        asprintf(&tmp, "%s@", np_module_lock_str[module_id_a]);
        _LOCK_ACCESS(&(self_thread ->locklists_lock)) {
            rm = _sll_char_remove(self_thread->has_lock, tmp, strlen(tmp));
            free(rm);
        }
        free(tmp);
    }
#endif

    return ret;
}

int _np_threads_unlock_module(np_state_t* context, np_module_lock_type module_id) {
    //log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_unlock_module(np_module_lock_type module_id) {");
    
#ifdef NP_THREADS_CHECK_THREADING
    log_debug_msg(LOG_MUTEX | LOG_DEBUG,"Unlocking module mutex %s.", np_module_lock_str[module_id]);
#endif
    int ret = pthread_mutex_unlock(&np_module(threads)->__mutexes[module_id].lock);
#ifdef NP_THREADS_CHECK_THREADING
    char * tmp = NULL;
    np_thread_t* self_thread = _np_threads_get_self(context);

    if (ret == 0 && self_thread  != NULL)
    {
        asprintf(&tmp, "%s@", np_module_lock_str[module_id]);
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
int _np_threads_mutex_init(np_state_t* context, np_mutex_t* mutex, const char* desc)
{
    int ret = 0;
    mutex->desc = strndup(desc, 32);
    pthread_mutexattr_init(&mutex->lock_attr);
    pthread_mutexattr_settype(&mutex->lock_attr, PTHREAD_MUTEX_RECURSIVE);

    _np_threads_condition_init(context, &mutex->condition);

    ret = pthread_mutex_init(&mutex->lock, &mutex->lock_attr);
    if (ret != 0)
    {
        log_msg(LOG_ERROR, "pthread_mutex_init: %s (%d)",
            strerror(ret), ret);
    }
    return ret;
}

int _np_threads_mutex_lock(np_state_t* context, np_mutex_t* mutex, const char* where) {
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");
    int ret =  1;

#ifdef NP_THREADS_CHECK_THREADING
    double diff = 0;
    double start = np_time_now();
    np_thread_t* self_thread = _np_threads_get_self(context);

    char* tmp_mutex_id = NULL;

    if (self_thread != NULL)
    {
        asprintf(&tmp_mutex_id, "%s@%s", mutex->desc, where);

        //_LOCK_ACCESS(&(self_thread->locklists_lock)) cannot be used due to recusion
        pthread_mutex_lock(&self_thread->locklists_lock.lock);
        {

            sll_prepend(char_ptr, self_thread->want_lock, tmp_mutex_id);
        }
        pthread_mutex_unlock(&self_thread->locklists_lock.lock);
    }
#endif

    while(ret != 0) {

#if defined(NP_THREADS_CHECK_THREADING) && NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK
        ret = _np_threads_mutex_timedlock(context, mutex, fmin(MUTEX_WAIT_MAX_SEC - diff, MUTEX_WAIT_SOFT_SEC - MUTEX_WAIT_SEC));

        diff = np_time_now() - start;
        if (diff > MUTEX_WAIT_MAX_SEC) {
            log_msg(LOG_ERROR, "Thread %lu waits too long for mutex %s(%p) (%f sec)", _np_threads_get_self(context)->id, mutex->desc, mutex, diff);
            log_msg(LOG_ERROR, "%s", np_threads_printpool(context, false));
            abort();
        }
        if (diff > MUTEX_WAIT_SOFT_SEC) {
            log_msg(LOG_MUTEX | LOG_WARN, "Waiting long time for mutex %p (%f sec)", mutex, diff);
        }
#else
        ret = pthread_mutex_lock(&mutex->lock);
#endif
    }


#ifdef NP_THREADS_CHECK_THREADING
    if (self_thread != NULL)
    {
        //_LOCK_ACCESS(&(self_thread->locklists_lock)) cannot be used due to recusion
        pthread_mutex_lock(&self_thread->locklists_lock.lock);
        {
            _sll_char_remove(self_thread->want_lock, tmp_mutex_id, strlen(tmp_mutex_id));
            sll_prepend(char_ptr, self_thread->has_lock, tmp_mutex_id);
        }
        pthread_mutex_unlock(&self_thread->locklists_lock.lock);
    }
#endif
    return ret;
}

int _np_threads_mutex_trylock(np_state_t* context, np_mutex_t* mutex, const char* where) {
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_lock(np_mutex_t* mutex){");

    int ret = pthread_mutex_trylock(&mutex->lock);

#ifdef NP_THREADS_CHECK_THREADING
    if (ret == 0) {
        np_thread_t* self_thread = _np_threads_get_self(context);

        char* tmp_mutex_id = NULL;


        if (self_thread != NULL)
        {
            asprintf(&tmp_mutex_id, "%s@%s", mutex->desc, where);

            _LOCK_ACCESS(&(self_thread->locklists_lock)) {

                sll_prepend(char_ptr, self_thread->has_lock, tmp_mutex_id);
            }
        }
    }
#endif
    return ret;
}

int _np_threads_mutex_unlock(np_state_t* context, np_mutex_t* mutex)
{
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_mutex_unlock(np_mutex_t* mutex){");

#ifdef NP_THREADS_CHECK_THREADING
    np_thread_t* self_thread = _np_threads_get_self(context);
    char* tmp_mutex_id;

    if (self_thread != NULL)
    {
        asprintf(&tmp_mutex_id, "%s@", mutex->desc);

        //_LOCK_ACCESS(&(self_thread->locklists_lock)) cannot be used due to recusion
        pthread_mutex_lock(&self_thread->locklists_lock.lock);
        {
            char * rm =  _sll_char_remove(self_thread->has_lock, tmp_mutex_id, strlen(tmp_mutex_id));
            free(rm);
            free(tmp_mutex_id);
        }
        pthread_mutex_unlock(&self_thread->locklists_lock.lock);
    }
#endif

    return pthread_mutex_unlock(&mutex->lock);
}

void _np_threads_mutex_destroy(np_state_t* context, np_mutex_t* mutex)
{
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_mutex_destroy(np_mutex_t* mutex){");	
    if (mutex != NULL) {
        _np_threads_condition_destroy(context, &mutex->condition);
        pthread_mutex_destroy(&mutex->lock);
        free(mutex->desc);
    }
}

/** pthread condition platform wrapper functions following this line **/
void _np_threads_condition_init(np_state_t* context, np_cond_t* condition)
{
    int result = pthread_condattr_init(&condition->cond_attr);
    ASSERT(result == 0, "cannot init cond shared");
    result = pthread_cond_init (&condition->cond, &condition->cond_attr);
    ASSERT(result == 0, "cannot init cond");
}

void _np_threads_condition_init_shared(np_state_t* context, np_cond_t* condition)
{
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_init_shared(np_cond_t* condition){");
    int result; 

    result = pthread_condattr_init(&condition->cond_attr);
    ASSERT(result == 0, "cannot init cond shared");

    result = pthread_condattr_setpshared(&condition->cond_attr, PTHREAD_PROCESS_SHARED);
    ASSERT(result == 0, "cannot setpshared cond");	

    result = pthread_cond_init (&condition->cond, &condition->cond_attr);
    ASSERT(result == 0, "cannot init cond shared");
    
}

void _np_threads_condition_destroy(np_state_t* context, np_cond_t* condition)
{
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_destroy(np_cond_t* condition){");
    int result;		
    result = pthread_condattr_destroy(&condition->cond_attr);
    ASSERT(result == 0, "cannot destroy condattr");
    result = pthread_cond_destroy(&condition->cond);
    ASSERT(result == 0, "cannot destroy cond");
    //memset(condition, 0, sizeof(np_cond_t));
}

int _np_threads_condition_wait(np_state_t* context, np_cond_t* condition, np_mutex_t* mutex)
{
    return pthread_cond_wait(&condition->cond, &mutex->lock);
}

int _np_threads_module_condition_timedwait(np_state_t* context, np_cond_t* condition, np_module_lock_type module_id, struct timespec* waittime)
{
    return pthread_cond_timedwait(&condition->cond, &np_module(threads)->__mutexes[module_id].lock, waittime);
}

int _np_threads_mutex_condition_timedwait(np_state_t* context, np_mutex_t* mutex, struct timespec* waittime)
{
    return pthread_cond_timedwait(&mutex->condition.cond, &mutex->lock, waittime);
}

int _np_threads_condition_broadcast(np_state_t* context, np_cond_t* condition)
{
    return pthread_cond_broadcast(&condition->cond);
}

int _np_threads_module_condition_broadcast(np_state_t* context, np_module_lock_type module_id)
{
    return pthread_cond_broadcast(&np_module(threads)->__mutexes[module_id].condition.cond);
}

int _np_threads_module_condition_signal(np_state_t* context, np_module_lock_type module_id)
{
    return pthread_cond_signal(&np_module(threads)->__mutexes[module_id].condition.cond);
}

int _np_threads_module_condition_wait(np_state_t* context, np_cond_t* condition, np_module_lock_type module_id)
{
    return pthread_cond_wait(&condition->cond, &np_module(threads)->__mutexes[module_id].lock);
}

int _np_threads_mutex_condition_wait(np_state_t* context, np_mutex_t* mutex)
{
    return pthread_cond_wait(&mutex->condition.cond, &mutex->lock);
}

int _np_threads_condition_signal(np_state_t* context, np_cond_t* condition)
{
    return pthread_cond_signal(&condition->cond);
}

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_thread_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_thread_ptr);

NP_DLL_GENERATE_IMPLEMENTATION(np_thread_ptr);

void _np_threads_set_self(np_thread_t * myThread) {

    np_ctx_memory(myThread);
    int ret = pthread_setspecific(np_module(threads)->__pthread_thread_ptr_key, myThread);
    log_debug_msg(LOG_DEBUG | LOG_THREADS, "Setting thread data to %p. Result:: %"PRIi32, myThread, ret);

    if (ret != 0) {
        log_msg(LOG_ERROR, "Cannot set thread specific data! Error: %"PRIi32, ret);
    }
}

np_thread_t*_np_threads_get_self(np_state_t* context)
{
    np_thread_t* ret = pthread_getspecific(np_module(threads)->__pthread_thread_ptr_key);

    if (ret == NULL && context != NULL)
    {
        unsigned long id_to_find = (unsigned long)pthread_self();
			
		//TSP_SCOPE(np_module(threads)->threads) cannot be used due to recusion
		if( 0 == pthread_mutex_lock(&np_module(threads)->threads_mutex.lock))
		{
            sll_iterator(np_thread_ptr) iter_threads = sll_first(np_module(threads)->threads);
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

                iter_threads = sll_first(np_module(threads)->threads);
                while (iter_threads != NULL)
                {
                    if (iter_threads->val->id == id_to_find) {
                        ret = iter_threads->val;
                        break;
                    }
                    sll_next(iter_threads);
                }

            }
			pthread_mutex_unlock(&np_module(threads)->threads_mutex.lock);
        }
    }
    return ret;
}

void _np_thread_t_del(np_state_t * context, uint8_t type, size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_del(void* nw){");
    np_thread_t* thread = (np_thread_t*)data;	

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
    _np_threads_mutex_destroy(context, &thread->locklists_lock);

#endif

}

void _np_thread_t_new(np_state_t * context, uint8_t type, size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_new(void* nw){");
    np_thread_t* thread = (np_thread_t*)data;

    thread->max_job_priority = DBL_MAX;
    thread->min_job_priority = 0;

    _np_threads_mutex_init(context, &thread->job_lock, "job_lock");
    thread->run_fn = NULL;
    thread->job = NULL;
    thread->thread_type = np_thread_type_other;

#ifdef NP_THREADS_CHECK_THREADING
    _np_threads_mutex_init(context, &thread->locklists_lock,"thread locklist");
    sll_init(char_ptr, thread->has_lock);
    sll_init(char_ptr, thread->want_lock);
#endif
}

char* np_threads_printpool(np_state_t* context, bool asOneLine) {
    char* ret = NULL;
#ifdef NP_THREADS_CHECK_THREADING

    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }
	TSP_TRYSCOPE(np_module(threads)->threads) {

        sll_iterator(np_thread_ptr) iter_threads = sll_first(np_module(threads)->threads);
        ret = np_str_concatAndFree(ret, "--- Threadpool START ---%s", new_line);

        np_sll_t(char_ptr, tmp);
        char * tmp2;
        while (iter_threads != NULL)
        {
            _LOCK_ACCESS(&(iter_threads->val->locklists_lock)) {
                tmp = _sll_char_part(iter_threads->val->has_lock, -5);
                tmp2 = _sll_char_make_flat(context, tmp);
                sll_free(char_ptr, tmp);
                ret = np_str_concatAndFree(ret, "Thread %"PRIu32" LOCKS: %s%s", iter_threads->val->id, tmp2, new_line);
                free(tmp2);

                tmp = _sll_char_part(iter_threads->val->want_lock, -5);
                tmp2 = _sll_char_make_flat(context, tmp);
                sll_free(char_ptr, tmp);
                ret = np_str_concatAndFree(ret, "Thread %"PRIu32" WANTS LOCKS: %s%s", iter_threads->val->id, tmp2, new_line);
                free(tmp2);

            }
            sll_next(iter_threads);
        }
//#else
//		while (iter_threads != NULL)
//		{
//			ret = np_str_concatAndFree(ret, "Thread %"PRIu32" %s", iter_threads->val->id, new_line);
//			sll_next(iter_threads);
//		}
//#endif
		ret = np_str_concatAndFree(ret, "--- Threadpool END   ---%s", new_line);
    }
#endif

    return ret;
}

void _np_thread_run(np_thread_t * thread) {
	np_ctx_memory(thread);
    pthread_create(thread->thread_id, &np_module(threads)->attr, thread->run_fn, (void *)thread);
    thread->id = (unsigned long)thread->thread_id;
}

np_thread_t * __np_createThread(np_state_t* context, uint8_t number, void *(fn)(void *), bool auto_run, enum np_thread_type_e type) {
    np_thread_t * new_thread;
    np_new_obj(np_thread_t, new_thread);
    new_thread->idx = number;
    new_thread->run_fn = fn;
    new_thread->thread_type = type;
	new_thread->thread_id = malloc(sizeof(pthread_t));
	CHECK_MALLOC(new_thread->thread_id);

	//TSP_SCOPE(np_module(threads)->threads) cannot be used due to recusion
	if (0 == pthread_mutex_lock(&np_module(threads)->threads_mutex.lock))
	{
        sll_append(np_thread_ptr, np_module(threads)->threads, new_thread);
		pthread_mutex_unlock(&np_module(threads)->threads_mutex.lock);
    }
    if(auto_run) {
        _np_thread_run(new_thread);
    }

    return new_thread;
}

void __np_createWorkerPool(np_state_t* context, uint8_t pool_size) {
    /* create the thread pool */
    for (uint8_t i = 0; i < pool_size; i++)
    {
        np_thread_t* new_thread = __np_createThread(context, i, __np_jobqueue_run_worker, false, np_thread_type_worker );

        if (
            (PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD && pool_size > 2 && i == 0) ||
            (PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD && pool_size > 3 && i == 1) ||
            (PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD && pool_size > 4 && i == 2) ||
            (PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD && pool_size > 5 && i == 3) ||
            (PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD && pool_size > 6 && i == 4) ||
            (PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD && pool_size > 7 && i == 5) ||
            (PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD && pool_size > 8 && i == 6)
        ) {
            new_thread->max_job_priority = (i+2) * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
            new_thread->min_job_priority =  i    * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
        } else {
            new_thread->max_job_priority = PRIORITY_MOD_LOWEST  * JOBQUEUE_PRIORITY_MOD_BASE_STEP + (JOBQUEUE_PRIORITY_MOD_BASE_STEP - 1);
            new_thread->min_job_priority = PRIORITY_MOD_HIGHEST * JOBQUEUE_PRIORITY_MOD_BASE_STEP;
        }

        _np_jobqueue_add_worker_thread(new_thread);
        _np_thread_run(new_thread);

        log_debug_msg(LOG_THREADS |LOG_DEBUG, "neuropil worker thread started: %d", new_thread->id);
    }
}


/*
    min pool_size is 2
*/
void np_threads_start_workers(np_state_t* context, uint8_t pool_size)
{	
    log_trace_msg(LOG_TRACE, "start: void np_threads_start_workers(uint8_t pool_size){");
    log_debug_msg(LOG_THREADS | LOG_DEBUG, "starting neuropil with %"PRIu8" threads", pool_size);


    if (pthread_attr_init(&np_module(threads)->attr) != 0)
    {
        log_msg(LOG_ERROR, "pthread_attr_init: %s", strerror(errno));
        return;
    }

    if (pthread_attr_setscope(&np_module(threads)->attr, PTHREAD_SCOPE_SYSTEM) != 0)
    {
        log_msg(LOG_ERROR, "pthread_attr_setscope: %s", strerror(errno));
        return;
    }

    if (pthread_attr_setdetachstate(&np_module(threads)->attr, PTHREAD_CREATE_DETACHED) != 0)
    {
        log_msg(LOG_ERROR, "pthread_attr_setdetachstate: %s", strerror(errno));
        return;
    }

    context->thread_count += pool_size;
    uint8_t worker_threads = ((int)pool_size/2) + 1;
	 
    _LOCK_MODULE(np_jobqueue_t)
    {
        // start jobs
        np_thread_t* special_thread;

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_in_run, true, np_thread_type_other);
        } else {
            np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_1, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_in, "_np_events_read_in");
        }

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_out_run, true, np_thread_type_other);
        } else {
            np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_1, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_out, "_np_events_read_out");
        }

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_io_run, true, np_thread_type_other);
        } else {
            np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_3, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_io, "_np_events_read_io");
        }

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_http_run, true, np_thread_type_other);
        } else {
            np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_5, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_http, "_np_events_read_http");
        }

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_0, 0.0, MISC_MEMORY_REFRESH_INTERVAL_SEC, _np_memory_job_memory_management, "_np_memory_job_memory_management");

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_1, 0.0, MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC, _np_event_cleanup_msgpart_cache, "_np_event_cleanup_msgpart_cache");

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_2, 0.0, MISC_RESPONSECONTAINER_CLEANUP_INTERVAL_SEC, _np_cleanup_ack_jobexec, "_np_cleanup_ack_jobexec");
        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_2, 0.0, MISC_MSGPROPERTY_MSG_UNIQUITY_CHECK_SEC, _np_msgproperty_job_msg_uniquety, "_np_msgproperty_job_msg_uniquety");
        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_2, 0.0, MISC_KEYCACHE_CLEANUP_INTERVAL_SEC, _np_cleanup_keycache_jobexec, "_np_cleanup_keycache_jobexec");

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_3, 0.0, MISC_SEND_PINGS_SEC, _np_glia_send_pings, "_np_glia_send_pings");
        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_3, 0.0, MISC_CHECK_ROUTES_SEC, _np_glia_check_neighbours, "_np_glia_check_neighbours");

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_4, 0.0, MISC_SEND_PIGGY_REQUESTS_SEC, _np_glia_send_piggy_requests, "_np_glia_send_piggy_requests");
        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_4, 0.0, MISC_RETRANSMIT_MSG_TOKENS_SEC, _np_retransmit_message_tokens_jobexec, "_np_retransmit_message_tokens_jobexec");

        np_job_submit_event_periodic(context, PRIORITY_MOD_LEVEL_5, 0.0, MISC_SEND_UPDATE_MSGS_SEC, _np_glia_check_routes, "_np_glia_check_routes");

        // TODO: re-enable _np_renew_node_token_jobexec
        // np_job_submit_event_periodic(PRIORITY_MOD_LEVEL_4, 0.0, MISC_RENEW_NODE_SEC,					_np_renew_node_token_jobexec, "_np_renew_node_token_jobexec");

        if (pool_size > worker_threads) {
            // a bunch of threads plus a coordinator
            pool_size--;
            __np_createWorkerPool(context, pool_size-1);
            special_thread = __np_createThread(context, pool_size, __np_jobqueue_run_manager, true, np_thread_type_manager);
        } else {
            // just a bunch of threads trying to get the first element from a priority queue
            for (int8_t i=0; i < pool_size; i++)
            {
                special_thread = __np_createThread(context, pool_size, __np_jobqueue_run_jobs, true, np_thread_type_manager);
            }
        }
    }

    log_debug_msg(LOG_DEBUG, "jobqueue threads started: pool %"PRIu8", worker %"PRIu8, pool_size, worker_threads);
    log_msg(LOG_INFO, "%s.%05d", NEUROPIL_RELEASE, NEUROPIL_RELEASE_BUILD);
    log_msg(LOG_INFO, "%s", NEUROPIL_COPYRIGHT);
    log_msg(LOG_INFO, "%s", NEUROPIL_TRADEMARK);

    _np_network_start(context->my_node_key->network);

}

