//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0); please see LICENSE file for details
//
#include "event/ev.h"
#include <time.h>
#include <math.h>
#include <pthread.h>

#include "np_legacy.h"
#include "np_util.h"

static pthread_once_t __chached_time_is_initialized = PTHREAD_ONCE_INIT;
static pthread_mutex_t __chached_time_lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static double __chached_time = 0;

int __initialize_chached_time()
{
    __chached_time = ev_time();
}
// 
//double np_time_now() {
//	(void)pthread_once(&__chached_time_is_initialized, __initialize_chached_time);
//	pthread_mutex_lock(&__chached_time_lock);
//	double ret = __chached_time;
//	pthread_mutex_unlock(&__chached_time_lock);
//	return  ret;
//}
double np_time_now() {
    return ev_time();
}

double np_time_update_cache_now() {
    return np_time_now();

    /*(void)pthread_once(&__chached_time_is_initialized, __initialize_chached_time);
    pthread_mutex_lock(&__chached_time_lock);
    double ret = __chached_time = ev_time();
    pthread_mutex_unlock(&__chached_time_lock);
    return  ret;*/
}

double np_time_sleep(double sleeptime) {

    sleeptime = fmax(sleeptime, NP_SLEEP_MIN);
    ev_sleep(sleeptime);

/*
    struct timespec ts;
    ts.tv_sec = (int)sleeptime;
    ts.tv_nsec = (sleeptime - ((int)sleeptime)) * 1000000; // to nanoseconds

    int status = -1;
    while (status == -1)
        status = nanosleep(&ts, &ts);
*/
    return sleeptime;
}
