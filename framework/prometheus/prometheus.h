//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_PROMETHEUS_H_
    #define _NP_PROMETHEUS_H_

#include <stdint.h>

    #ifdef __cplusplus
    extern "C" {
    #endif
enum prometheus_metric_types {
    prometheus_metric_type_counter
};
typedef struct prometheus_context_s prometheus_context;
typedef struct prometheus_metric_s prometheus_metric;
typedef struct prometheus_label_s {
    char  name[255];
    char  value[255];
}prometheus_label;

typedef uint64_t (*get_time_callback)();

prometheus_context* prometheus_create_context(get_time_callback time);
void prometheus_destroy_context(prometheus_context * c);

prometheus_metric* prometheus_register_metric(prometheus_context* c, char name[255]);


prometheus_metric* prometheus_register_sub_metric_time(prometheus_metric* main, uint16_t interval_sec);

void prometheus_metric_add_label(prometheus_metric* self, prometheus_label label);
void prometheus_metric_replace_label(prometheus_metric* self, prometheus_label label);

void prometheus_metric_inc(prometheus_metric* self, float value);

void prometheus_metric_set(prometheus_metric* self, float value);
float prometheus_metric_get(prometheus_metric* self);
char* prometheus_format(prometheus_context* self);
void prometheus_disable_value_output(prometheus_metric* self);

    #ifdef __cplusplus
    }
    #endif

#endif /* _NP_PROMETHEUS_H_ */
