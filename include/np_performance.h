//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_PERFORMANCE_H_
#define _NP_PERFORMANCE_H_

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>

#include "np_legacy.h"
#include "np_types.h"
#include "np_list.h"
#include "np_threads.h"
#include "np_settings.h"


#ifdef __cplusplus
extern "C" {
#endif

#ifdef NP_BENCHMARKING
    enum np_statistics_performance_point_e {
        np_statistics_performance_point_memory_new = 1,
        np_statistics_performance_point_memory_free,
        np_statistics_performance_point_memory_management,
        np_statistics_performance_point_msg_discovery_out,
        np_statistics_performance_point_jobs_management_select,

        np_statistics_performance_point_network_start_access_lock,
        np_statistics_performance_point_network_start_out_events_lock,
        
        np_statistics_performance_point_message_serialize_chunked,

        np_statistics_performance_point_tokenfactory_new_handshake,

        np_statistics_performance_point_event_resume_io,
        np_statistics_performance_point_event_resume_in,
        np_statistics_performance_point_event_resume_out,
        np_statistics_performance_point_event_resume_http,
        np_statistics_performance_point_event_suspend_io,
        np_statistics_performance_point_event_suspend_in,
        np_statistics_performance_point_event_suspend_out,
        np_statistics_performance_point_event_suspend_http,

        np_statistics_performance_point_jobqueue_insert,

        np_statistics_performance_point_handshake_out,
        np_statistics_performance_point_handshake_test_1,
        np_statistics_performance_point_handshake_test_2,
        np_statistics_performance_point_handshake_out_lock,
        np_statistics_performance_point_handshake_out_network,
        np_statistics_performance_point_handshake_out_msg_chunks_lock,
        np_statistics_performance_point_handshake_out_events_lock,

        np_statistics_performance_point_END
    };

    typedef struct np_statistics_performance_point_s {
        char* name;
        double durations[NP_BENCHMARKING];
        uint16_t durations_idx;
        uint32_t hit_count;
        uint32_t durations_count;
        np_mutex_t access;
    } np_statistics_performance_point_t;

#define CALC_STATISTICS(array, accessor, max_size, min_v, max_v, avg_v, stddev_v)			\
            double min_v = DBL_MAX, max_v = 0.0, avg_v = 0.0, stddev_v = 0.0;               \
            for (uint16_t j = 0; j < max_size; j++)                                         \
            {                                                                               \
                min_v = fmin(min_v,(array[j]accessor));										\
                max_v = fmax(max_v,(array[j]accessor));										\
                /*avg = (avg * max_size + array[j]accessor) / (max_size + 1);*/             \
                avg_v += array[j]accessor;                                                  \
            }                                                                               \
            avg_v = avg_v / max_size;                                                       \
            for (uint16_t j = 0; j < max_size; j++) {                                       \
                stddev_v += pow((array[j]accessor) - avg_v, 2);                             \
            }                                                                               \
            stddev_v = sqrt(stddev_v/(max_size-1));                                         \


#define __NP_PERFORMANCE_POINT_INIT_CONTAINER(container, NAME)											\
        if (container == NULL) {																		\
            container = malloc(sizeof(np_statistics_performance_point_t));								\
            container->name = #NAME;																	\
            container->durations_idx = 0;																\
            container->durations_count = 0;																\
            container->hit_count = 0;																	\
            _np_threads_mutex_init(context, &container->access, "performance point "#NAME" access");	\
        }																														

#define NP_PERFORMANCE_POINT_START(NAME) 																						\
    double t1_##NAME;																											\
    {																															\
        np_statistics_performance_point_t* container = np_module(statistics)->performance_points[np_statistics_performance_point_##NAME];			\
        __NP_PERFORMANCE_POINT_INIT_CONTAINER(container, NAME)																	\
        np_module(statistics)->performance_points[np_statistics_performance_point_##NAME] = container;												\
        _LOCK_ACCESS(&container->access) {																						\
            container->hit_count++;																								\
        }																														\
        t1_##NAME = np_time_update_cache_now(); /*(double)clock()/CLOCKS_PER_SEC;*/																				\
    }
#define NP_PERFORMANCE_POINT_END(NAME) {																						\
        double t2 = np_time_update_cache_now(); /*(double)clock()/CLOCKS_PER_SEC;*/																				\
        np_statistics_performance_point_t* container = np_module(statistics)->performance_points[np_statistics_performance_point_##NAME];			\
        _LOCK_ACCESS(&container->access) {																						\
            container->durations[container->durations_idx] = t2 - t1_##NAME;													\
            container->durations_idx = (container->durations_idx + 1)  % NP_BENCHMARKING;										\
            container->durations_count++;																						\
        }																														\
    }
#define __NP_PERFORMANCE_GET_POINTS_STR_CONTAINER(STR, container) 																\
        if (container != NULL) {																								\
            _LOCK_ACCESS(&container->access) {																					\
                CALC_STATISTICS(container->durations, ,																			\
                (container->durations_count > NP_BENCHMARKING ? NP_BENCHMARKING : container->durations_idx),					\
                    min_v, max_v, avg_v, stddev_v);																				\
                STR = np_str_concatAndFree(STR, "%30s --> %8.6f / %8.6f / %8.6f / %8.6f / %10"PRIu32" / %10"PRIu32"\n",			\
                    container->name, min_v, avg_v, max_v, stddev_v, container->hit_count,container->durations_count);			\
            }																													\
        }

#ifdef DEBUG_CALLBACKS																											
#define ___NP_PERFORMANCE_GET_POINTS_STR(STR)																				\
    char * stats = __np_util_debug_statistics_print(context);																\
    STR = np_str_concatAndFree(STR, stats);																					\
    free(stats);																											
#else
#define ___NP_PERFORMANCE_GET_POINTS_STR(STR) ;
#endif


#define NP_PERFORMANCE_GET_POINTS_STR(STR) 																						\
    char* STR = NULL;																											\
    {																															\
        STR = np_str_concatAndFree(STR,																							\
                "%30s --> %8s / %8s / %8s / %8s / %10s / %10s \n", "name", "min", "avg", "max", "stddev", "hits", "completed");	\
        for (int i = 0; i < np_statistics_performance_point_END; i++) {															\
            np_statistics_performance_point_t* container = np_module(statistics)->performance_points[i];						\
            __NP_PERFORMANCE_GET_POINTS_STR_CONTAINER(STR, container);															\
        }																														\
        ___NP_PERFORMANCE_GET_POINTS_STR(STR)																					\
    }																															
#else																														
#define NP_PERFORMANCE_POINT_START(name)
#define NP_PERFORMANCE_POINT_END(name)
#define NP_PERFORMANCE_GET_POINTS_STR(STR)												\
    char* STR = NULL;	
#define CALC_STATISTICS(array, accessor, max_size, min_v, max_v, avg_v, stddev_v)		\
        double min_v = DBL_MAX, max_v = 0.0, avg_v = 0.0, stddev_v = 0.0;               
#endif

#ifdef __cplusplus
}
#endif

#endif /* NP_PERFORMANCE_H_ */
