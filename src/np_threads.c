//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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
#include "np_constants.h"
#include "np_event.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_list.h"
#include "np_log.h"
#include "core/np_comp_msgproperty.h"
#include "np_network.h"
#include "np_settings.h"
#include "np_types.h"
#include "np_util.h"

pthread_key_t  __pthread_thread_ptr_key;

np_module_struct(threads) {
    bool        __np_threads_initiated;
    np_state_t* context;
    np_mutex_t  __mutexes[PREDEFINED_DUMMY_START];

    pthread_once_t __thread_init_once;    
    pthread_attr_t __attributes;
    
    TSP(np_sll_type(np_thread_ptr), threads);

};

bool _np_threads_init(np_state_t* context)
{
    if (!np_module_initiated(threads))
    {
        np_module_malloc(threads);		
        _module->__np_threads_initiated = false;
        
        pthread_key_create(&__pthread_thread_ptr_key, NULL);

        // init module mutexes
        int t, c;
        for (int module_id = 0; module_id < PREDEFINED_DUMMY_START; module_id++) 
        {
            t = pthread_mutexattr_init(&_module->__mutexes[module_id].lock_attr);
            assert(t==0);
            t = pthread_mutexattr_settype(&_module->__mutexes[module_id].lock_attr, PTHREAD_MUTEX_RECURSIVE);
            assert(t==0);
            t = pthread_mutex_init(&_module->__mutexes[module_id].lock, &_module->__mutexes[module_id].lock_attr);
            assert(t==0);

            c = pthread_condattr_init(&_module->__mutexes[module_id].condition.cond_attr);
            assert(c==0);
            c = pthread_cond_init(&_module->__mutexes[module_id].condition.cond, &_module->__mutexes[module_id].condition.cond_attr);
            assert(c==0);

            strncpy(_module->__mutexes[module_id].desc, np_module_lock_str[module_id], 63);
            log_debug_msg(LOG_DEBUG | LOG_MUTEX, "created module mutex %d / %p / %p", module_id, &_module, &_module->__mutexes[module_id]);
        }
        _module->threads = sll_init_part(np_thread_ptr);
        TSP_INIT(_module->threads);

        _module->__np_threads_initiated = true;
    }
    return true;
}

void _np_threads_destroy(np_state_t* context)
{
    if (np_module_initiated(threads))
    {        
        np_module_var(threads);
        
        //pthread_key_delete(_module->__pthread_thread_ptr_key);        
        // init module mutexes
        for (int module_id = 0; module_id < PREDEFINED_DUMMY_START; module_id++) {            
            pthread_mutex_destroy(&_module->__mutexes[module_id].lock);
            pthread_mutexattr_destroy(&_module->__mutexes[module_id].lock_attr);            
        }
        
        sll_iterator(np_thread_ptr) iter_threads = sll_first(np_module(threads)->threads);
        uint32_t iterated_threads = 0;
        while(iter_threads != NULL) {            
             //np_unref_obj(np_thread_t,iter_threads->val , ref_obj_creation); //cannot use as the memory gets destroyed before the threads
            if( iter_threads->val) {
                 _np_thread_t_del(context, np_memory_types_np_thread_t, sizeof(np_thread_t), iter_threads->val);
                _np_memory_delete_item(context, iter_threads->val, ref_obj_creation,  iterated_threads == (sll_size(np_module(threads)->threads)-1));
            }
            sll_next(iter_threads);
            iterated_threads++;
        }
        sll_free(np_thread_ptr, _module->threads);                

        TSP_DESTROY(_module->threads);

        np_module_free(threads);		
    }
}

int _np_threads_lock_module(np_state_t* context, np_module_lock_type module_id, const char * where ) {       
    //log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: int _np_threads_lock_module(np_module_lock_type module_id) {");

    log_debug_msg(LOG_MUTEX | LOG_DEBUG, "Locking module mutex %d/%s.", module_id, np_module_lock_str[module_id]);

    if (!np_module_initiated(threads)) _np_threads_init(context);
    
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
#if !defined(NP_THREADS_CHECK_THREADING) || !defined(NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK)
    ret = pthread_mutex_lock(&np_module(threads)->__mutexes[module_id].lock);
#else
    double start = np_time_now();
   
    double diff = 0;
    while(ret != 0){
        diff = np_time_now() - start;
            if(diff >MUTEX_WAIT_MAX_SEC) {
                log_msg(LOG_ERROR, "Thread %lu waits too long for module mutex %s (%f sec)", self_thread->id, np_module_lock_str[module_id], diff);
                log_msg(LOG_ERROR, "%s", np_threads_print_locks(context, false, true));                
                abort();
            }
        ret = _np_threads_mutex_timedlock(context, &np_module(threads)->__mutexes[module_id], MUTEX_WAIT_MAX_SEC);

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

int _np_threads_mutex_timedlock(NP_UNUSED np_state_t* context, np_mutex_t * mutex, const double timeout)
{
    int ret = -1;
#if defined(NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK)
    {
        double d_sleep = np_time_now() + timeout;
        d_sleep += 0.5e-9;
        struct timespec waittime = {0};
        waittime.tv_sec  = (long) d_sleep;
        waittime.tv_nsec = (d_sleep - waittime.tv_sec) * 1000000000L;
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
                struct timespec ts = {0};
                ts.tv_sec = 0;
                ts.tv_nsec= 20 /* ms */ * 1000000000L; // to nanoseconds

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

/** pthread mutex platform wrapper functions following this line **/
int _np_threads_mutex_init(np_state_t* context, np_mutex_t* mutex, const char* desc)
{
    int ret = 0;
    strncpy(mutex->desc, desc, 63);
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

int _np_threads_mutex_lock(NP_UNUSED  np_state_t* context, np_mutex_t* mutex, const char* where) {
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
        ret = _np_threads_mutex_timedlock(context, mutex, MUTEX_WAIT_MAX_SEC - diff);

        diff = np_time_now() - start;
        if (diff > MUTEX_WAIT_MAX_SEC) {
            log_msg(LOG_ERROR, "Thread %lu waits too long for mutex %s(%p) (%f sec)", _np_threads_get_self(context)->id, mutex->desc, mutex, diff);
            log_msg(LOG_ERROR, "%s", np_threads_print_locks(context, false, true));
            abort();
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

int _np_threads_mutex_trylock(NP_UNUSED np_state_t* context, np_mutex_t* mutex, const char* where) {
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

int _np_threads_mutex_unlock(NP_UNUSED np_state_t* context, np_mutex_t* mutex)
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
    }
}

int _np_threads_module_condition_wait(np_state_t* context, np_module_lock_type module_id)
{
    log_debug_msg(LOG_DEBUG | LOG_MUTEX, "waiting %p", &np_module(threads)->__mutexes[module_id].condition.cond);

    return pthread_cond_wait(&np_module(threads)->__mutexes[module_id].condition.cond, &np_module(threads)->__mutexes[module_id].lock);
}

int _np_threads_module_condition_timedwait(np_state_t* context, np_module_lock_type module_id, double sec)
{
    double d_sleep = np_time_now() + sec;
    struct timespec waittime = { 0 };
    waittime.tv_sec = (long)d_sleep;
    waittime.tv_nsec = (d_sleep - waittime.tv_sec) / 1e-9;

    int ret = pthread_cond_timedwait(&np_module(threads)->__mutexes[module_id].condition.cond, 
                                     &np_module(threads)->__mutexes[module_id].lock, &waittime);

    return ret;
}

int _np_threads_module_condition_broadcast(np_state_t* context, np_module_lock_type module_id)
{
    if (!np_module_initiated(threads)) return 0;

    return pthread_cond_broadcast(&np_module(threads)->__mutexes[module_id].condition.cond);
}

int _np_threads_module_condition_signal(np_state_t* context, np_module_lock_type module_id)
{
    if (!np_module_initiated(threads)) return 0;

    log_debug_msg(LOG_DEBUG | LOG_MUTEX, "signalling %p", &np_module(threads)->__mutexes[module_id].condition.cond);
    return pthread_cond_signal(&np_module(threads)->__mutexes[module_id].condition.cond);
}

int _np_threads_mutex_condition_signal(NP_UNUSED np_state_t* context, np_mutex_t* mutex)
{
    return pthread_cond_signal(&mutex->condition.cond);
}

int _np_threads_mutex_condition_wait(NP_UNUSED np_state_t* context, np_mutex_t* mutex)
{
    return pthread_cond_wait(&mutex->condition.cond, &mutex->lock);
}

int _np_threads_mutex_condition_timedwait(NP_UNUSED np_state_t* context, np_mutex_t* mutex, struct timespec* waittime)
{
    int ret =  pthread_cond_timedwait(&mutex->condition.cond, &mutex->lock, waittime);
    return ret;
}

/** pthread condition platform wrapper functions following this line **/
void _np_threads_condition_init(NP_UNUSED np_state_t* context, np_cond_t* condition)
{
    int result = pthread_condattr_init(&condition->cond_attr);
    ASSERT(result == 0, "cannot init cond shared");
    result = pthread_cond_init (&condition->cond, &condition->cond_attr);
    ASSERT(result == 0, "cannot init cond");
}

void _np_threads_condition_init_shared(NP_UNUSED np_state_t* context, np_cond_t* condition)
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

void _np_threads_condition_destroy(NP_UNUSED np_state_t* context, np_cond_t* condition)
{
    log_trace_msg(LOG_TRACE | LOG_MUTEX, "start: void _np_threads_condition_destroy(np_cond_t* condition){");
    int result;		
    result = pthread_condattr_destroy(&condition->cond_attr);
    ASSERT(result == 0, "cannot destroy condattr");
    result = pthread_cond_destroy(&condition->cond);
    ASSERT(result == 0, "cannot destroy cond");
    //memset(condition, 0, sizeof(np_cond_t));
}

int _np_threads_condition_wait(NP_UNUSED np_state_t* context, np_cond_t* condition, np_mutex_t* mutex)
{
    return pthread_cond_wait(&condition->cond, &mutex->lock);
}

int _np_threads_condition_broadcast(NP_UNUSED np_state_t* context, np_cond_t* condition)
{
    return pthread_cond_broadcast(&condition->cond);
}

int _np_threads_condition_signal(NP_UNUSED np_state_t* context, np_cond_t* condition)
{
    return pthread_cond_signal(&condition->cond);
}

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_thread_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_thread_ptr);

NP_DLL_GENERATE_IMPLEMENTATION(np_thread_ptr);

void _np_threads_set_self(np_thread_t * myThread) {

    np_ctx_memory(myThread);
    int ret = pthread_setspecific(__pthread_thread_ptr_key, myThread);
    log_debug_msg(LOG_DEBUG | LOG_THREADS, "Setting thread data to %p. Result:: %"PRIi32, myThread, ret);

    if (ret != 0) {
        log_msg(LOG_ERROR, "Cannot set thread specific data! Error: %"PRIi32, ret);
    }
}

np_thread_t*_np_threads_get_self(np_state_t* context)
{
    np_thread_t* ret = pthread_getspecific(__pthread_thread_ptr_key);

    if (ret == NULL && context != NULL)
    {
        size_t id_to_find = (size_t)pthread_self();
            
        //TSP_SCOPE(np_module(threads)->threads) cannot be used due to recusion
        if( 0 == pthread_mutex_lock(&np_module(threads)->threads_mutex.lock))
        {
            sll_iterator(np_thread_ptr) iter_threads = sll_first(np_module(threads)->threads);
            while (iter_threads != NULL && iter_threads->val != NULL)
            {
                if (iter_threads->val->id == id_to_find) {
                    ret = iter_threads->val;
                    break;
                }
                sll_next(iter_threads);
            }

            if (ret == NULL) {
                id_to_find = (size_t)getpid();

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

void _np_thread_t_del(NP_UNUSED np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_del(void* nw){");
    np_thread_t* thread = (np_thread_t*)data;
#ifdef NP_THREADS_CHECK_THREADING
     

    assert(thread->has_lock != NULL);
    //_LOCK_ACCESS(&thread->locklists_lock)
    {
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

        #ifdef NP_STATISTICS_THREADS 
            if(thread->stats)free(thread->stats);
        #endif
    _np_threads_mutex_destroy(context, &thread->job_lock);

}

void _np_thread_t_new(NP_UNUSED np_state_t * context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_new(void* nw){");
    np_thread_t* thread = (np_thread_t*)data;

#ifdef NP_STATISTICS_THREADS 
    thread->stats = NULL;
#endif

    thread->max_job_priority = DBL_MAX;
    thread->min_job_priority = 0;

    char mutex_str[64];
    snprintf(mutex_str, 63, "%s:%p", "urn:np:thread:job", thread);
    _np_threads_mutex_init(context, &thread->job_lock, mutex_str);
    thread->run_fn = NULL;
    // thread->job = { 0 };
    thread->thread_type = np_thread_type_other;

#ifdef NP_THREADS_CHECK_THREADING

    snprintf(mutex_str, 63, "%s:%p", "urn:np:thread:lock_list", thread);
    _np_threads_mutex_init(context, &thread->locklists_lock, mutex_str);
    sll_init(char_ptr, thread->has_lock);
    sll_init(char_ptr, thread->want_lock);
#endif
}
#ifdef NP_THREADS_CHECK_THREADING

char* __np_threads_print_locks(np_state_t* context, char* ret, char* new_line) {
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

    return ret;
}
#endif


char* np_threads_print_locks(np_state_t* context, bool asOneLine, bool force) {
    char* ret = NULL;
#ifdef NP_THREADS_CHECK_THREADING

    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }
    TSP_TRYSCOPE(np_module(threads)->threads) {
        ret = __np_threads_print_locks(context, ret, new_line);
    }
    if(force && ret == NULL){
        ret = __np_threads_print_locks(context, ret, new_line);
    }
#endif

    return ret;
}

void* __np_thread_status_wrapper(void* self){
    np_ctx_memory(self);
    log_debug_msg(LOG_JOBS | LOG_THREADS | LOG_DEBUG, "job queue thread starting");
    _np_threads_set_self(self);
    np_thread_t* thread = self;
    thread->status = np_running;
    thread->run_fn(context, thread);
    thread->status = np_stopped;

    return NULL;
}

void _np_thread_run(np_thread_t * thread) {
    np_ctx_memory(thread);    
    pthread_create(&thread->thread_id, &np_module(threads)->__attributes, __np_thread_status_wrapper, (void *)thread);
    thread->id = (size_t)thread->thread_id;    
}

np_thread_t * __np_createThread(NP_UNUSED np_state_t* context, uint8_t number, np_threads_worker_run fn, bool auto_run, enum np_thread_type_e type) {

    np_thread_t * new_thread;
    np_new_obj(np_thread_t, new_thread);

    new_thread->idx = number;
    new_thread->run_fn = fn;
    new_thread->thread_type = type;
    new_thread->_busy = false;
    int r;

    //TSP_SCOPE(np_module(threads)->threads) cannot be used due to recusion
    if (0 == (r = pthread_mutex_lock(&np_module(threads)->threads_mutex.lock)))
    {
        sll_append(np_thread_ptr, np_module(threads)->threads, new_thread);
        pthread_mutex_unlock(&np_module(threads)->threads_mutex.lock);
    }
#ifdef DEBUG
    else{
        log_error("Mutex returned %d",r);
        abort();
    }
    #endif

    if(auto_run) {
        // _np_jobqueue_add_worker_thread(new_thread);
        _np_thread_run(new_thread);
    }

    return new_thread;
}

void __np_createWorkerPool(NP_UNUSED np_state_t* context, uint8_t pool_size) {
    /* create the thread pool */
    for (uint8_t i = 0; i < pool_size; i++)
    {
        np_thread_t* new_thread = __np_createThread(context, i, __np_jobqueue_run_worker, false, np_thread_type_managed );

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


void np_threads_shutdown_workers(np_state_t* context){
    bool shutdown_complete;
    sll_iterator(np_thread_ptr) iter_threads;
    do {
        np_time_sleep(0.0);
        _np_jobqueue_check(context);
        shutdown_complete = true;
        iter_threads = sll_first(np_module(threads)->threads);
        while (iter_threads != NULL)
        {     
            // only the main thread cannot be shut down (np_threads_shutdown_workers needs to be invoked from here)
            if(iter_threads->val->thread_type != np_thread_type_main 
            && iter_threads->val->status != np_stopped){
                _np_threads_condition_signal(context, &iter_threads->val->job_lock.condition);
                shutdown_complete = false;
                break;
            }
            sll_next(iter_threads);
        }        
    }while(!shutdown_complete);
}

void np_threads_start_workers(NP_UNUSED np_state_t* context, uint8_t pool_size)
{	
    log_trace_msg(LOG_TRACE, "start: void np_threads_start_workers(uint8_t pool_size){");
    log_debug_msg(LOG_THREADS | LOG_DEBUG, "starting neuropil with %"PRIu8" threads", pool_size);


    if (pthread_attr_init(&np_module(threads)->__attributes) != 0)
    {
        log_msg(LOG_ERROR, "pthread_attr_init: %s", strerror(errno));
        return;
    }

    if (pthread_attr_setscope(&np_module(threads)->__attributes, PTHREAD_SCOPE_SYSTEM) != 0)
    {
        log_msg(LOG_ERROR, "pthread_attr_setscope: %s", strerror(errno));
        return;
    }

    if (pthread_attr_setdetachstate(&np_module(threads)->__attributes, PTHREAD_CREATE_DETACHED) != 0)
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
#ifdef DEBUG
            strcpy(special_thread->job.ident, "_np_event_in_run");
#endif
        } else {
            np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_1, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_in, "_np_events_read_in");
        }

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_out_run, true, np_thread_type_other);
#ifdef DEBUG
            strcpy(special_thread->job.ident, "_np_event_out_run");
#endif
        } else {
            np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_1, 0.0, MISC_READ_EVENTS_SEC, _np_events_read_out, "_np_events_read_out");
        } 

        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_file_run, true, np_thread_type_other);
#ifdef DEBUG
            strcpy(special_thread->job.ident, "_np_event_file_run");
#endif
        } else {
            np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_2, 0.0, MISC_LOG_FLUSH_INTERVAL_SEC, _np_events_read_file, "_np_events_read_file");
        }        

/*
        if (pool_size > worker_threads) {
            pool_size--;
            special_thread = __np_createThread(context, pool_size, _np_event_http_run, true, np_thread_type_other);
#ifdef DEBUG
            strcpy(special_thread->job.ident, "_np_event_http_run");
#endif
        } else {
*/
        np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_3, 0.0, MISC_READ_EVENTS_SEC*10, _np_events_read_http, "_np_events_read_http");
//  }

        np_jobqueue_submit_event_periodic(context, PRIORITY_MOD_LEVEL_2, MISC_KEYCACHE_CLEANUP_INTERVAL_SEC, MISC_KEYCACHE_CLEANUP_INTERVAL_SEC, _np_keycache_check_state, "_np_keycache_check_state");

        if (pool_size > worker_threads) {
            // a bunch of threads plus a coordinator
            __np_createWorkerPool(context, pool_size-1);
            pool_size--;
            special_thread = __np_createThread(context, pool_size, __np_jobqueue_run_manager, true, np_thread_type_manager);
#ifdef DEBUG
            strcpy(special_thread->job.ident, "__np_jobqueue_run_manager");
#endif

        } else {
            // just a bunch of threads trying to get the first element from a priority queue
            for (int8_t i=0; i < pool_size; i++)
            {
                special_thread = __np_createThread(context, pool_size, __np_jobqueue_run_jobs, true, np_thread_type_worker);
            }
        }
    }

    log_debug_msg(LOG_DEBUG, "jobqueue threads started: pool %"PRIu8", worker %"PRIu8, pool_size, worker_threads);
    _np_jobqueue_print_jobs(context);

    log_msg(LOG_INFO, "%s", NEUROPIL_RELEASE);
    log_msg(LOG_INFO, "%s", NEUROPIL_COPYRIGHT);
    log_msg(LOG_INFO, "%s", NEUROPIL_TRADEMARK);
}

char* np_threads_print(np_state_t * context, bool asOneLine) {
    char* ret = NULL;
    char* new_line = "\n";
    if (asOneLine == true) {
        new_line = "    ";
    }
#ifdef DEBUG

    ret = np_str_concatAndFree(ret,
        "%-15s | %-7s | %14s | %-275s" "%s",
        "Thread ID","Type","Busy(1s/1m/5m)", "Last FN pointer ident",
        new_line
    );         
    
    TSP_SCOPE(np_module(threads)->threads) {    
        sll_iterator(np_thread_ptr) thread_iter = sll_first(np_module(threads)->threads) ;
        while (thread_iter != NULL) {
            np_thread_t * thread = thread_iter->val;      
            assert(thread != NULL);          
            _LOCK_ACCESS(&thread->job_lock) {
                double perc_0=0, perc_1=0,perc_2=0;
                np_threads_busyness_statistics(context, thread, &perc_0, &perc_1, &perc_2);

                void* a= NULL;
                if(thread->_busy)
                 if(thread->job.processorFuncs != NULL) 
                  if(sll_size(thread->job.processorFuncs) > 0)
                    a = sll_first(thread->job.processorFuncs)->val;
                
                ret = np_str_concatAndFree(ret,
                    "%15"PRIu32" | %7s | %3.0f%%%% %3.0f%%%% %3.0f%%%% | %15p / %-257s"	"%s",
                    thread->id, 
                    np_thread_type_str[thread->thread_type],
                    perc_0,perc_1,perc_2,
                    a,
                    thread->job.ident,
                    new_line
                ); 
            }
            sll_next(thread_iter);
        }
    }
#else
     ret = np_str_concatAndFree(ret, "Only available in DEBUG");
#endif
    return ret;
}


struct np_thread_stat_s {
    double interval;
    double interval_start;
    double interval_end;
    double usage;
    double last_usage;
};
struct np_thread_stats_s {
    np_mutex_t mutex;
    double last_busy_mark;
    struct np_thread_stat_s items[3];
};

#ifdef NP_STATISTICS_THREADS 
void _np_threads_busyness_stat(np_state_t* context, np_thread_t* self, bool is_busy) {
    double now = np_time_now();
    for(int i = 0; i < ARRAY_SIZE(self->stats->items); i++) {
        if(now >= self->stats->items[i].interval_end) {
            self->stats->items[i].usage = self->stats->items[i].last_usage;
            self->stats->items[i].usage = 0;
            self->stats->items[i].interval_start  = now;
            self->stats->items[i].interval_end = now + self->stats->items[i].interval;
            self->stats->last_busy_mark = 0;
        }
    }
    if(self->stats->last_busy_mark != 0) {
        double diff = now - self->stats->last_busy_mark;
        for(int i = 0; i < ARRAY_SIZE(self->stats->items); i++) {
            self->stats->items[i].usage += diff;
        }
    }
    if(is_busy) {                        
        self->stats->last_busy_mark = now;
    } else {
        self->stats->last_busy_mark = 0;
    }
}

void np_threads_busyness_stat(np_state_t* context, np_thread_t* self) {
    _np_threads_busyness_stat(context, self, self->_busy);
}
#endif
void np_threads_busyness(np_state_t* context, np_thread_t* self, bool is_busy){
    if(self->_busy != is_busy){                
        self->_busy = is_busy;
    }
#ifdef NP_STATISTICS_THREADS         
        if(self->stats==NULL) {
            self->stats = calloc(1, sizeof(struct np_thread_stats_s));
            self->stats->items[0].interval = 1;
            self->stats->items[1].interval = 60;
            self->stats->items[2].interval = 60*5;            
        }        
        _np_threads_busyness_stat(context, self, is_busy);
#endif
}
#ifdef NP_STATISTICS_THREADS 
void np_threads_busyness_statistics(np_state_t* context, np_thread_t* self, double *perc_0, double *perc_1, double *perc_2) {
    if(self->stats)
    {
        #define code(i)                                                                                          \
            *perc_##i = self->stats->items[i].usage / (np_time_now() - self->stats->items[i].interval_start);    \
            if(self->stats->items[i].last_usage != 0) {                                                          \
                *perc_##i = (self->stats->items[i].last_usage / self->stats->items[i].interval + *perc_##i) / 2; \
            }                                                                                                    \
            *perc_##i = *perc_##i *100;
        code(0)
        code(1)
        code(2)        
        #undef code
    }
}
#endif