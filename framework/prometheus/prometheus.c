//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <inttypes.h>

#include <pthread.h>

#include "prometheus.h"

typedef struct prometheus_item_s prometheus_item;
struct prometheus_item_s {
     prometheus_item *next;
    void* data;
};

 struct prometheus_context_s {
    pthread_mutex_t w_lock;
    pthread_mutexattr_t w_lock_attr;


    prometheus_item* metrics;
    get_time_callback time;
};


struct prometheus_metric_s {

    char  name[255];
    pthread_mutex_t rw_lock;
    pthread_mutexattr_t rw_lock_attr;

    float value;
    uint64_t time_ms;
    prometheus_item* labels;
    prometheus_context* context;

    prometheus_item* sub_metrics;
};

enum prometheus_sub_metric_type{
    prometheus_sub_metric_type_time
};
typedef struct prometheus_sub_metric_time_config_s {

    uint64_t interval_ms;
    uint64_t last_update;
    float last_value;

}prometheus_sub_metric_time_config;
typedef struct prometheus_sub_metric_s {
    enum prometheus_sub_metric_type type;
    prometheus_metric* self;
    union{
        prometheus_sub_metric_time_config time;
    };
} prometheus_sub_metric;

prometheus_context* prometheus_create_context(get_time_callback time){
    prometheus_context* ret = calloc(1,sizeof(prometheus_context));
    pthread_mutexattr_init(&ret->w_lock_attr);
    pthread_mutexattr_settype(&ret->w_lock_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&ret->w_lock, &ret->w_lock_attr);
    ret->time = time;
    return ret;
}


void prometheus_destroy_label(prometheus_label* l){
    free(l);
}
void prometheus_destroy_sub_metric(prometheus_sub_metric* sm);
void prometheus_destroy_metric(prometheus_metric* m){

    prometheus_item * item = NULL, *item_old;
    item = m->labels;
    while(item!=NULL){
        item_old = item;
        prometheus_destroy_label((prometheus_label*)item->data);
        item = item->next;
        free(item_old);
    }
    item = m->sub_metrics;
    while(item!=NULL){
        item_old = item;
        prometheus_destroy_sub_metric((prometheus_sub_metric*)item->data);
        item = item->next;
        free(item_old);
    }

    pthread_mutexattr_destroy(&m->rw_lock_attr);
    pthread_mutex_destroy(&m->rw_lock);
    free(m);
}
void prometheus_destroy_sub_metric(prometheus_sub_metric* sm){
    free(sm);
}

void prometheus_destroy_context(prometheus_context * c){
    prometheus_item * item = NULL, *item_old;

    item = c->metrics;
    while(item!=NULL){
        item_old = item;
        prometheus_destroy_metric((prometheus_metric*)item->data);
        item = item->next;
        free(item_old);
    }

    pthread_mutexattr_destroy(&c->w_lock_attr);
    pthread_mutex_destroy(&c->w_lock);
    free(c);
}

prometheus_metric* prometheus_register_metric(prometheus_context* c, char name[255]){
    prometheus_metric* ret = calloc(1,sizeof(prometheus_metric));
    strncpy(ret->name, name, 255);
    ret->time_ms = 0;
    ret->context = c;
    pthread_mutexattr_init(&ret->rw_lock_attr);
    pthread_mutexattr_settype(&ret->rw_lock_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&ret->rw_lock, &ret->rw_lock_attr);

    prometheus_item* n_item = calloc(1,sizeof(prometheus_item));
    if(pthread_mutex_lock(&c->w_lock)==0){
        n_item->next = c->metrics;
        n_item->data = ret;
        c->metrics = n_item;
        pthread_mutex_unlock(&c->w_lock);
    }

    return ret;
}

prometheus_metric* prometheus_register_sub_metric_time(prometheus_metric* base, uint16_t interval_sec){
    prometheus_sub_metric* ret = calloc(1,sizeof(prometheus_sub_metric));
    ret->type = prometheus_sub_metric_type_time;
    ret->time.interval_ms = interval_sec*(uint64_t)1000;
    ret->time.last_value = base->value;

    char new_name[255];
    snprintf(new_name,255,"%s_per_secs", base->name);
    new_name[254]='\0';
    ret->self = prometheus_register_metric(base->context, new_name);
    prometheus_label label_interval = { .name="interval" };
    snprintf(label_interval.value, 255,"%"PRIu16, interval_sec);
    prometheus_metric_add_label(ret->self, label_interval);

    // Copy other labels
    prometheus_item* label_iterator = base->labels;
    while(label_iterator != NULL){
        prometheus_metric_add_label(ret->self, *(prometheus_label*)label_iterator->data);
        label_iterator = label_iterator->next;
    }

    prometheus_item* n_item = calloc(1,sizeof(prometheus_item));
    n_item->next = base->sub_metrics;
    n_item->data = ret;
    base->sub_metrics = n_item;

    return ret->self;
}

void prometheus_metric_add_label(prometheus_metric* self, prometheus_label label){
    if(pthread_mutex_lock(&self->context->w_lock)==0) {

        prometheus_item* n_item = calloc(1,sizeof(prometheus_item));
        n_item->next = self->labels;
        n_item->data = calloc(1, sizeof(prometheus_label));
        memcpy(n_item->data, &label, sizeof(prometheus_label));
        self->labels = n_item;

        prometheus_item* sub_metric_iterator = self->sub_metrics;
        while(sub_metric_iterator != NULL){
            prometheus_metric_add_label(((prometheus_sub_metric*)sub_metric_iterator->data)->self, label);
            sub_metric_iterator = sub_metric_iterator->next;
        }
        pthread_mutex_unlock(&self->context->w_lock);
    }
}
void prometheus_metric_replace_label(prometheus_metric* self, prometheus_label label){
    if(pthread_mutex_lock(&self->context->w_lock)==0) {
        bool replaced = false;
        prometheus_item* n_item = self->labels;
        while(n_item != NULL){
            prometheus_label* item = n_item->data;
            if(strcmp(label.name, item->name)==0) {
                strncpy(item->value, label.value, 255);
                replaced = true;
            }
            n_item = n_item->next;
        }
        if(!replaced){
            prometheus_metric_add_label(self, label);
        }else{
            prometheus_item* sub_metric_iterator = self->sub_metrics;
            while(sub_metric_iterator != NULL){
                prometheus_metric_replace_label(((prometheus_sub_metric*)sub_metric_iterator->data)->self, label);
                sub_metric_iterator = sub_metric_iterator->next;
            }
        }
        pthread_mutex_unlock(&self->context->w_lock);
    }
}

void __prometheus_metric_update_sub_metrics(prometheus_metric* self, uint64_t now){
    prometheus_item* n_item = self->sub_metrics;
    while(n_item != NULL) {
        prometheus_sub_metric* sub_metric = n_item->data;
        if(sub_metric->type == prometheus_sub_metric_type_time && self->context->time != NULL) {
            if((sub_metric->time.last_update + sub_metric->time.interval_ms) <= now) {
                float value_diff = self->value - sub_metric->time.last_value;
                float timeframe = now - sub_metric->time.last_update;
                float per_interval_avg = value_diff / (timeframe / (sub_metric->time.interval_ms));

                prometheus_metric_set(sub_metric->self, per_interval_avg);
                sub_metric->time.last_update = now;
                sub_metric->time.last_value = self->value;
            }
        }
        n_item = n_item->next;
    }
}

void prometheus_metric_inc(prometheus_metric* self, float value){
    if(pthread_mutex_lock(&self->rw_lock)==0){
        self->value += value;
        if(self->context->time != NULL) {
            self->time_ms = self->context->time();
        }
        __prometheus_metric_update_sub_metrics(self,self->time_ms);
        pthread_mutex_unlock(&self->rw_lock);
    }
}

void prometheus_metric_set(prometheus_metric* self, float value) {
    if(pthread_mutex_lock(&self->rw_lock)==0){
        self->value = value;
        if(self->context->time != NULL) {
            self->time_ms = self->context->time();
        }
        __prometheus_metric_update_sub_metrics(self,self->time_ms);
        pthread_mutex_unlock(&self->rw_lock);
    }
}

float prometheus_metric_get(prometheus_metric* self) {
    float ret = 0;
    if(pthread_mutex_lock(&self->rw_lock)==0) {
        __prometheus_metric_update_sub_metrics(self,self->context->time());
        ret = self->value;
        pthread_mutex_unlock(&self->rw_lock);
    }
    return ret;
}

char* prometheus_format(prometheus_context* c) {
    char* ret = NULL;
    if(pthread_mutex_lock(&c->w_lock)==0){

        /*
            Format:
            metric_name[{label_name="label_value",...}] metric_value [timestamp]
        */
        // Calculate size of return string
        uint32_t size = 1; /*NULL TERMINATOR*/
        prometheus_item *metric_iterator, *label_iterator;
        prometheus_metric* metric;
        prometheus_label* label;
        metric_iterator = c->metrics;

        while(metric_iterator != NULL){
            metric = (prometheus_metric*) metric_iterator->data;

            size += strnlen(metric->name,255);
            size += 21; // value size + space

            if(metric->time_ms != 0)
                size += 14; // timestamp size

            label_iterator = metric->labels;
            if(label_iterator != NULL){
                size += 2; // {}
            }
            while(label_iterator != NULL){
                label = (prometheus_label*) label_iterator->data;

                size += strnlen(label->name,255);
                size += 3; // =""
                size += strnlen(label->value,255);

                label_iterator = label_iterator->next;
                if(label_iterator != NULL)
                    size += 1; // ,
            }
            size += 1; // newline
            metric_iterator = metric_iterator->next;
        }
        ret = malloc(size);
        uint32_t ret_pointer = 0;

        metric_iterator = c->metrics;

        while(metric_iterator != NULL){
            metric = (prometheus_metric*) metric_iterator->data;

            ret_pointer += sprintf(ret+ret_pointer, "%s", metric->name);

            label_iterator = metric->labels;
            bool has_label = label_iterator != NULL;
            if(has_label) {
                ret_pointer += sprintf(ret+ret_pointer, "%c", '{');
            }
            while(label_iterator != NULL) {
                label = (prometheus_label*) label_iterator->data;

                ret_pointer += sprintf(ret+ret_pointer, "%s=\"%s\"", label->name, label->value);

                label_iterator = label_iterator->next;
                if(label_iterator != NULL)
                    ret_pointer += sprintf(ret+ret_pointer, "%c", ',');
            }
            if(has_label){
                ret_pointer += sprintf(ret+ret_pointer, "%s", "}");
            }

            pthread_mutex_lock(&metric->rw_lock);
            ret_pointer += sprintf(ret+ret_pointer, " %f", metric->value);
            if(metric->time_ms != 0)
                ret_pointer += sprintf(ret+ret_pointer," %"PRIu64, metric->time_ms);
            pthread_mutex_unlock(&metric->rw_lock);

            ret_pointer += sprintf(ret+ret_pointer, "%c", '\n');
            metric_iterator = metric_iterator->next;
        }
        ret[size-1] = 0; // for sanity
        pthread_mutex_unlock(&c->w_lock);
    }

    return ret;
}
