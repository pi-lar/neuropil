//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_STATISTICS_H_
#define NP_STATISTICS_H_

    #include <stdint.h>
    #include <inttypes.h>
    #include <stdlib.h>
    #include <float.h>


    #include "np_settings.h"
    #include "np_types.h"

    #include "np_legacy.h"


    #include "util/np_list.h"
    #include "util/np_scache.h"
    #include "np_threads.h"
    #include "np_util.h"

    #include "prometheus/prometheus.h"

    #ifdef __cplusplus
    extern "C" {
    #endif

enum np_prometheus_exposed_metrics {
    np_prometheus_exposed_metrics_uptime,
    np_prometheus_exposed_metrics_forwarded_msgs,
    np_prometheus_exposed_metrics_received_msgs,
    np_prometheus_exposed_metrics_send_msgs,
    np_prometheus_exposed_metrics_job_count,
    np_prometheus_exposed_metrics_routing_neighbor_count,
    np_prometheus_exposed_metrics_routing_route_count,
    np_prometheus_exposed_metrics_network_in,
    np_prometheus_exposed_metrics_network_in_per_sec,
    np_prometheus_exposed_metrics_network_out,
    np_prometheus_exposed_metrics_network_out_per_sec,
    np_prometheus_exposed_metrics_END
};


char* np_statistics_prometheus_export(np_context*ac);

        #ifdef NP_BENCHMARKING
            struct np_statistics_performance_point_s {
                char* name;
                double durations[NP_BENCHMARKING];
                uint16_t durations_idx;
                uint32_t hit_count;
                uint32_t durations_count;
                np_mutex_t access;
            };

            typedef struct np_statistics_performance_point_s np_statistics_performance_point_t;
            GENERATE_ENUM_STR(np_statistics_performance_point,
                memory_new,
                memory_free,
                memory_management,
                msg_discovery_out,
                jobs_management_select,
                network_start_access_lock,
                network_start_in_events_lock,
                network_start_out_events_lock,
                message_serialize_chunked,
                tokenfactory_new_handshake,
                event_resume_io,
                event_resume_in,
                event_resume_out,
                event_resume_http,
                event_resume_file,
                event_suspend_io,
                event_suspend_in,
                event_suspend_out,
                event_suspend_http,
                event_suspend_file,
                is_dht_message,
                is_usr_in_message,
                is_discovery_message,
                handshake_out,
                handshake_out_lock,
                handshake_out_network,
                handshake_out_msg_chunks_lock,
                handshake_out_events_lock,
                jobqueue_insert,
                jobqueue_run,
                jobqueue_manager_distribute_job,
                message_decrypt
            )

        #endif

        np_module_struct(statistics) {
            np_state_t* context;
            np_simple_cache_table_t __cache;
            np_sll_t(char_ptr, __watched_subjects);
            prometheus_context* _prometheus_context;
            prometheus_metric* _prometheus_metrics[np_prometheus_exposed_metrics_END];
            double startup_time;
            np_tree_t* _per_subject_metrics;
            np_tree_t* _per_dhkey_metrics;

    #ifdef DEBUG_CALLBACKS
            np_sll_t(void_ptr, __np_debug_statistics);
    #endif
    #ifdef NP_BENCHMARKING
            np_statistics_performance_point_t performance_points[np_statistics_performance_point_END];
    #endif

        };

        NP_API_INTERN
            bool _np_statistics_init(np_state_t* context);
        NP_API_INTERN
            bool _np_statistics_enable(np_state_t* context);
        NP_API_INTERN
            void _np_statistics_destroy(np_state_t* context);
        NP_API_INTERN
            void _np_statistics_update_prometheus_labels(np_state_t*context, prometheus_metric* metric);

        NP_API_EXPORT
            void np_statistics_add_watch(np_state_t* context, const char* subject);

        NP_API_EXPORT
            char * np_statistics_print(np_state_t* context, bool asOneLine);

        NP_API_EXPORT
            void np_statistics_add_watch_internals(np_state_t* context);

    #ifdef NP_STATISTICS_COUNTER
        NP_API_INTERN
            void __np_increment_forwarding_counter(np_state_t* context, char * subject);
        NP_API_INTERN
            void __np_increment_received_msgs_counter(np_state_t* context, char * subject);
            NP_API_INTERN
            void __np_increment_send_msgs_counter(np_state_t* context, char * subject);
        NP_API_INTERN
            void __np_statistics_add_send_bytes(np_state_t* context, uint32_t add);
        NP_API_INTERN
            void __np_statistics_add_received_bytes(np_state_t* context, uint32_t add);
        NP_API_INTERN
            void __np_statistics_set_latency(np_state_t* context, np_dhkey_t id, float value);
        NP_API_INTERN
            void __np_statistics_set_success_avg(np_state_t* context, np_dhkey_t id, float value);

        #define _np_set_latency(id, value) __np_statistics_set_latency(context, id, value)
        #define _np_set_success_avg(id, value) __np_statistics_set_success_avg(context, id, value)
        #define _np_increment_forwarding_counter(subject) __np_increment_forwarding_counter(context, subject)
        #define _np_increment_received_msgs_counter(subject) __np_increment_received_msgs_counter(context, subject)
        #define _np_increment_send_msgs_counter(subject) __np_increment_send_msgs_counter(context, subject)
        #define _np_statistics_add_send_bytes(add) __np_statistics_add_send_bytes(context, add)
        #define _np_statistics_add_received_bytes(add) __np_statistics_add_received_bytes(context, add)
    #else
        #define _np_set_latency(id, value)
        #define _np_set_success_avg(id, value)
        #define _np_increment_forwarding_counter(subject)
        #define _np_increment_received_msgs_counter(subject)
        #define _np_increment_send_msgs_counter(subject)
        #define _np_statistics_add_send_bytes(add)
        #define _np_statistics_add_received_bytes(add)
    #endif // DEBUG



    #ifdef NP_BENCHMARKING
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

    #define NP_PERFORMANCE_POINT_DESTROY()											                        \
        for(int i=0; i < np_statistics_performance_point_END; i++) {                                        \
            _np_threads_mutex_destroy(context, &np_module(statistics)->performance_points[i].access);	    \
        }

    #define NP_PERFORMANCE_POINT_START(NAME)                                                                                                            \
        double t1_##NAME;                                                                                                                               \
        np_statistics_performance_point_t container_##NAME = np_module(statistics)->performance_points[np_statistics_performance_point_##NAME];        \
        {                                                                                                                                               \
            _LOCK_ACCESS(&container_##NAME.access) {                                                                                                   \
                container_##NAME.hit_count++;                                                                                                          \
            }                                                                                                                                           \
            t1_##NAME = np_time_now(); /*(double)clock()/CLOCKS_PER_SEC;*/                                                                              \
        }                                                                                                                                               \

    #define NP_PERFORMANCE_POINT_END(NAME) {																						\
            double t2_##NAME = np_time_now(); /*(double)clock()/CLOCKS_PER_SEC;*/								                    \
            {																						                                \
                _LOCK_ACCESS(&container_##NAME.access) {																			\
                    container_##NAME.durations[container_##NAME.durations_idx] = t2_##NAME - t1_##NAME;							    \
                    container_##NAME.durations_idx = (container_##NAME.durations_idx + 1)  % NP_BENCHMARKING;						\
                    container_##NAME.durations_count++;																			    \
                }																													\
            }																														\
        }                                                                                                                           \

    #define __NP_PERFORMANCE_GET_POINTS_STR_CONTAINER(STR, container) 																\
                _LOCK_ACCESS(&container.access) {																					\
                    CALC_STATISTICS(container.durations, ,																			\
                    (container.durations_count > NP_BENCHMARKING ? NP_BENCHMARKING : container.durations_idx),					\
                        min_v, max_v, avg_v, stddev_v);																				\
                    STR = np_str_concatAndFree(STR, "%30s --> %8.6f / %8.6f / %8.6f / %8.6f / %10"PRIu32" / %10"PRIu32"\n",			\
                        container.name, min_v, avg_v, max_v, stddev_v, container.hit_count,container.durations_count);			\
            }

    #ifdef DEBUG_CALLBACKS
    #define ___NP_PERFORMANCE_GET_POINTS_STR(STR)																				\
        char * stats = __np_statistics_debug_print(context);																    \
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
                np_statistics_performance_point_t container = np_module(statistics)->performance_points[i];						\
                __NP_PERFORMANCE_GET_POINTS_STR_CONTAINER(STR, container);															\
            }																														\
            ___NP_PERFORMANCE_GET_POINTS_STR(STR)																					\
        }
    #else
    #define NP_PERFORMANCE_POINT_DESTROY()
    #define NP_PERFORMANCE_POINT_START(name)
    #define NP_PERFORMANCE_POINT_END(name)
    #define NP_PERFORMANCE_GET_POINTS_STR(STR)												\
        char* STR = NULL;
    #define CALC_STATISTICS(array, accessor, max_size, min_v, max_v, avg_v, stddev_v)		\
            double min_v = DBL_MAX, max_v = 0.0, avg_v = 0.0, stddev_v = 0.0;
    #endif




#ifdef DEBUG_CALLBACKS
typedef struct {
	char key[255];
	uint32_t count;
	np_mutex_t lock;
	double avg;
	double min;
	double max;
} _np_statistics_debug_t;

NP_API_INTERN
_np_statistics_debug_t* _np_statistics_debug_add(np_state_t * context, char* key, double value);
NP_API_INTERN
_np_statistics_debug_t* __np_statistics_debug_get(np_state_t * context, char* key);
NP_API_INTERN
char* __np_statistics_debug_print(np_state_t * context);
NP_API_INTERN
void  _np_statistics_debug_destroy(np_state_t * context);
NP_API_INTERN
void _np_statistics_debug_ele_destroy(np_state_t* context, void* item) ;
#else 
	#define _np_statistics_debug_destroy(context) ;
	#define _np_statistics_debug_ele_destroy(context, item) ;
#endif
NP_API_EXPORT
void np_statistics_set_node_description(np_context* ac, char description[255]);

    #ifdef __cplusplus
    }
    #endif

#endif /* NP_STATISTICS_H_ */
