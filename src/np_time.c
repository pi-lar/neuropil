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
#include "np_threads.h"
#include "np_time.h"



np_module_struct(time)
{
    np_state_t* context;	
    bool cache_time;
    TSP(double, __time_cache);
};

double _np_time_force_now() {
    return ev_time();
}
bool _np_time_init(np_state_t* context)
{
    bool ret = false;
    if (!np_module_initiated(time)) {
        np_module_malloc(time);
        ret = true;
        _module->cache_time = false;
        TSP_INITD(_module->__time_cache,_np_time_force_now());
    }
    return ret;
}
void _np_time_destroy(np_state_t* context)
{
    if (np_module_initiated(time)) {
        np_module_var(time);

        TSP_DESTROY(_module->__time_cache);

        np_module_free(time);
    }
}

double _np_time_now(np_state_t* context) {
    double ret =0;

    if(context == NULL || !np_module_initiated(time) || !np_module(time)->cache_time){
        ret = _np_time_force_now();
    }else{
        TSP_GET(double, np_module(time)->__time_cache, r);
        ret = r;
    }

    return ret;
}

double _np_time_update_cache(np_state_t* context) {
    TSP_SET(np_module(time)->__time_cache, _np_time_force_now());
    
    if(!np_module(time)->cache_time)
        np_module(time)->cache_time = true;

    return _np_time_now(context);
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
