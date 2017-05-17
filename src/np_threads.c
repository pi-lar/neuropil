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

typedef struct mutex {
    int lock_id;
    pthread_mutex_t lock;
} mutex_t;

mutex_t* mutexes[PREDEFINED_DUMMY_START-1];

np_bool _np_threads_init()
{
	np_bool ret = TRUE;
	for(int i = 0; i < PREDEFINED_DUMMY_START; i++){
		ret = _np_threads_create_mutex(i);
		if(FALSE == ret) {
			log_msg(LOG_ERROR,"Cannot initialize mutex %d.", i);
			break;
		}
	}
	return ret;
}

pthread_mutex_t* _np_threads_get_mutex(int mutex_id)
{
	mutex_t* mutex = mutexes[mutex_id];
	if(NULL == mutex ){
		log_msg(LOG_MUTEX | LOG_WARN, "Mutex %d was not initialised. Do so now.", mutex_id);
		_np_threads_create_mutex(mutex_id);
	}else{
		log_msg(LOG_MUTEX | LOG_DEBUG, "Got mutex %d.", mutex_id);
	}
	return &(mutexes[mutex_id]->lock);
}

np_bool _np_threads_create_mutex(int mutex_id){

	mutex_t* new_mutex = (mutex_t*) malloc(sizeof(mutex_t));
	if(new_mutex != NULL){
		new_mutex->lock_id = mutex_id;
		pthread_mutex_init(&(new_mutex->lock), NULL);

		mutexes[mutex_id] = new_mutex;
		log_msg(LOG_MUTEX | LOG_DEBUG, "Created mutex %d.", mutex_id);
	} else {
		log_msg(LOG_ERROR, "Cannot allocate mutex %d.", mutex_id);
	}
	return new_mutex != NULL ? TRUE : FALSE;
}
