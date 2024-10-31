//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_statistics.h"

#include <inttypes.h>
#include <math.h>
#include <stdint.h>

#include "prometheus/prometheus.h"

#include "../framework/http/np_http.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_scache.h"
#include "util/np_tree.h"

#include "np_jobqueue.h"
#include "np_key.h"
#include "np_legacy.h"
#include "np_message.h"
#include "np_route.h"
#include "np_threads.h"
#include "np_types.h"
#include "np_util.h"

struct np_statistics_element_s {
  bool watch_receive;
  bool watch_send;

  uint32_t total_received;
  uint32_t total_send;
  uint32_t last_total_received;
  uint32_t last_total_send;

  uint32_t last_min_received;
  uint32_t last_min_send;
  uint32_t last_total_min_received;
  uint32_t last_total_min_send;
  double   last_mindiff_received;
  double   last_mindiff_send;
  double   last_min_check;

  uint32_t last_sec_received;
  uint32_t last_sec_send;
  uint32_t last_total_sec_received;
  uint32_t last_total_sec_send;
  double   last_secdiff_received;
  double   last_secdiff_send;
  double   last_sec_check;

  double first_check;
};

typedef struct np_statistics_element_s np_statistics_element_t;

bool _np_statistics_receive_msg_on_watched(np_state_t     *context,
                                           np_util_event_t event) {
  NP_CAST(event.user_data, struct np_e2e_message_s, msg);

  np_statistics_element_t *value = NULL;
  if (np_simple_cache_get(context,
                          &np_module(statistics)->__cache,
                          msg->subject,
                          &value)) {
    value->total_received += 1;
  }
  return true;
}

/*
 * ggT berechnet den groessten gemeinsamen Teiler
 * zweier natuerlicher Zahlen nach Euklid.
 */
size_t ggT(size_t a, size_t b) {
  size_t c;
  do {
    c = a % b; /* Rest der ganzzahligen Division */
    a = b;
    b = c; /* Vertauschen der Werte */
  } while (c != 0);

  return a;
}

/*
 * kgV berechnet das kleinste gemeinsamen Vielfache
 * zweier natuerlicher Zahlen mittels ggT.
 */
size_t kgV(size_t a, size_t b) { return a * b / ggT(a, b); }

bool _np_statistics_send_msg_on_watched(np_state_t     *context,
                                        np_util_event_t event) {
  NP_CAST(event.user_data, struct np_e2e_message_s, msg);

  np_statistics_element_t *value = NULL;
  if (np_simple_cache_get(context,
                          &np_module(statistics)->__cache,
                          msg->subject,
                          &value)) {
    value->total_send += 1;
  }

  return true;
}

uint64_t get_timestamp() { return (uint64_t)_np_time_now(NULL) * 1000; }

bool __np_statistics_gather_data_clb(np_state_t               *context,
                                     NP_UNUSED np_util_event_t event) {
  np_module_var(statistics);
  prometheus_metric_set(
      _module->_prometheus_metrics[np_prometheus_exposed_metrics_job_count],
      np_jobqueue_count(context));
  prometheus_metric_set(
      _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
      get_timestamp() - ((uint64_t)_module->startup_time * 1000));
  prometheus_metric_set(
      _module->_prometheus_metrics
          [np_prometheus_exposed_metrics_routing_neighbor_count],
      _np_route_my_key_count_neighbors(context, NULL, NULL));
  prometheus_metric_set(_module->_prometheus_metrics
                            [np_prometheus_exposed_metrics_routing_route_count],
                        _np_route_my_key_count_routes(context));

  return true;
}
int _np_http_handle_metrics(ht_request_t  *request,
                            ht_response_t *ret,
                            void          *context) {
  ret->ht_body   = np_statistics_prometheus_export(context);
  ret->ht_status = HTTP_CODE_OK;
  np_tree_insert_str(ret->ht_header,
                     "Content-Type",
                     np_treeval_new_s("text/plain; version=0.0.4"));
  return ret->ht_status;
}
bool _np_statistics_init(np_state_t *context) {

  if (!np_module_initiated(statistics)) {
    np_module_malloc(statistics);

    uint32_t cache_size = SIMPLE_CACHE_NR_BUCKETS;
    char     random_seed[crypto_shorthash_KEYBYTES];
    randombytes_buf(random_seed, crypto_shorthash_KEYBYTES);

    np_cache_init(context, &_module->__cache, cache_size, random_seed);

    sll_init(np_dhkey_t, _module->__watched_subjects);

    _module->_per_subject_metrics = np_tree_create();
    _module->_per_dhkey_metrics   = np_tree_create();
    _module->startup_time         = np_time_now();

    _module->_prometheus_context = prometheus_create_context(get_timestamp);
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX "uptime");

    _module->_prometheus_metrics[np_prometheus_exposed_metrics_forwarded_msgs] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "forwarded_msgs_sum");
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_received_msgs] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "received_msgs_sum");
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_send_msgs] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "send_msgs_sum");
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_job_count] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "jobs_count");
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_network_in] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "network_in_bytes");
    _module->_prometheus_metrics[np_prometheus_exposed_metrics_network_out] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "network_out_bytes");
    _module->_prometheus_metrics
        [np_prometheus_exposed_metrics_routing_neighbor_count] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "routing_neighbor_count");
    _module->_prometheus_metrics
        [np_prometheus_exposed_metrics_routing_route_count] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "routing_route_count");
    _module
        ->_prometheus_metrics[np_prometheus_exposed_metrics_pheromones_inhale] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "pheromones_inhale");
    _module
        ->_prometheus_metrics[np_prometheus_exposed_metrics_pheromones_exhale] =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX
                                   "pheromones_exhale");

    _module->_prometheus_metrics
        [np_prometheus_exposed_metrics_network_in_per_sec] =
        prometheus_register_sub_metric_time(
            _module
                ->_prometheus_metrics[np_prometheus_exposed_metrics_network_in],
            1);
    _module->_prometheus_metrics
        [np_prometheus_exposed_metrics_network_out_per_sec] =
        prometheus_register_sub_metric_time(
            _module->_prometheus_metrics
                [np_prometheus_exposed_metrics_network_out],
            1);

    prometheus_label label;
    strncpy(label.name, "version", 255);
    strncpy(label.value, NEUROPIL_RELEASE, 255);
    prometheus_metric_add_label(
        _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
        label);
    strncpy(label.name, "application", 255);
    strncpy(label.value, "neuropil_exporter", 255);
    prometheus_metric_add_label(
        _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
        label);
    strncpy(label.name, "description", 255);
    strncpy(label.value, "None", 255);
    prometheus_metric_add_label(
        _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
        label);
    prometheus_metric_set(
        _module->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
        0);
    _np_statistics_update_prometheus_labels(context, NULL);
#ifdef DEBUG_CALLBACKS
    sll_init(void_ptr, _module->__np_debug_statistics);
#endif
#ifdef NP_BENCHMARKING
    for (int container_idx = 0;
         container_idx < np_statistics_performance_point_END;
         container_idx++) {
      np_statistics_performance_point_t *container =
          &_module->performance_points[container_idx];
      container->durations_idx   = 0;
      container->durations_count = 0;
      container->hit_count       = 0;
      char mutex_str[64];
      snprintf(mutex_str,
               63,
               "urn:np:statistics:%s:%s",
               "perfpoint",
               np_statistics_performance_point_str[container_idx]);
      _np_threads_mutex_init(context, &container->access, mutex_str);
      container->name = np_statistics_performance_point_str[container_idx];
    }
#endif
    _np_add_http_callback(context,
                          "metrics",
                          htp_method_GET,
                          context,
                          _np_http_handle_metrics);
  }
  return true;
}
void _np_statistics_update(np_state_t *context) {
  _np_statistics_update_prometheus_labels(context, NULL);
}
bool _np_statistics_enable(np_state_t *context) {

  np_jobqueue_submit_event_periodic(
      context,
      NP_PRIORITY_LOWEST,
      0.,
      NP_STATISTICS_PROMETHEUS_DATA_GATHERING_INTERVAL,
      __np_statistics_gather_data_clb,
      "__np_statistics_gather_data_clb");

  return true;
}
typedef struct np_statistics_per_subject_metrics_s {
  prometheus_metric *received_msgs;
  prometheus_metric *send_msgs;
} np_statistics_per_subject_metrics;

np_statistics_per_subject_metrics *
__np_statistics_get_subject_metrics(np_state_t *context,
                                    np_dhkey_t  subject_dhkey) {
  np_statistics_per_subject_metrics *ret;

  np_module_var(statistics);
  np_tree_elem_t *element =
      np_tree_find_dhkey(_module->_per_subject_metrics, subject_dhkey);

  if (element == NULL) {
    prometheus_label label;
    strncpy(label.name, "subject", 255);
    sodium_bin2hex(label.value, 65, &subject_dhkey, 32);
    ret = calloc(1, sizeof(np_statistics_per_subject_metrics));

    ret->received_msgs = prometheus_register_metric(
        _module->_prometheus_context,
        NP_STATISTICS_PROMETHEUS_PREFIX "received_msgs");
    prometheus_metric_add_label(ret->received_msgs, label);
    _np_statistics_update_prometheus_labels(context, ret->received_msgs);

    ret->send_msgs =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX "send_msgs");
    prometheus_metric_add_label(ret->send_msgs, label);
    _np_statistics_update_prometheus_labels(context, ret->send_msgs);

    np_tree_insert_dhkey(np_module(statistics)->_per_subject_metrics,
                         subject_dhkey,
                         np_treeval_new_v(ret));
  } else {
    ret = element->val.value.v;
  }

  return ret;
}

typedef struct np_statistics_per_dhkey_metrics_s {
  prometheus_metric *latency;
  prometheus_metric *success_avg;
} np_statistics_per_dhkey_metrics;

np_statistics_per_dhkey_metrics *
__np_statistics_get_dhkey_metrics(np_state_t *context, np_dhkey_t id) {
  np_statistics_per_dhkey_metrics *ret;

  np_module_var(statistics);
  np_tree_elem_t *element = np_tree_find_dhkey(_module->_per_dhkey_metrics, id);

  if (element == NULL) {
    prometheus_label label;
    strncpy(label.name, "target", 255);
    _np_dhkey_str(&id, label.value);
    ret = calloc(1, sizeof(np_statistics_per_dhkey_metrics));

    ret->latency =
        prometheus_register_metric(_module->_prometheus_context,
                                   NP_STATISTICS_PROMETHEUS_PREFIX "latency");
    prometheus_metric_add_label(ret->latency, label);
    _np_statistics_update_prometheus_labels(context, ret->latency);

    ret->success_avg = prometheus_register_metric(
        _module->_prometheus_context,
        NP_STATISTICS_PROMETHEUS_PREFIX "success_avg");
    prometheus_metric_add_label(ret->success_avg, label);
    _np_statistics_update_prometheus_labels(context, ret->success_avg);

    np_tree_insert_dhkey(np_module(statistics)->_per_dhkey_metrics,
                         id,
                         np_treeval_new_v(ret));
  } else {
    ret = element->val.value.v;
  }

  return ret;
}

void _np_statistics_update_prometheus_labels(np_state_t        *context,
                                             prometheus_metric *metric) {
  if (np_module_initiated(statistics)) {
    np_module_var(statistics);

    prometheus_label node_label     = {0};
    prometheus_label ident_label    = {0};
    prometheus_label instance_label = {0};
    strncpy(node_label.name, "node", 255);
    strncpy(instance_label.name, "instance", 255);
    strncpy(ident_label.name, "identity", 255);
    if (context->my_node_key != NULL) {
      _np_dhkey_str(&context->my_node_key->dhkey, node_label.value);
      if (_np_key_get_node(context->my_node_key))
        snprintf(instance_label.value,
                 254,
                 "%s:%s",
                 _np_key_get_node(context->my_node_key)->ip_string,
                 _np_key_get_node(context->my_node_key)->port);
    }
    if (context->my_identity != NULL)
      _np_dhkey_str(&context->my_identity->dhkey, ident_label.value);

    if (metric == NULL) {
      for (int i = 0; i < np_prometheus_exposed_metrics_END; i++) {
        prometheus_metric_replace_label(_module->_prometheus_metrics[i],
                                        node_label);
        prometheus_metric_replace_label(_module->_prometheus_metrics[i],
                                        ident_label);
        prometheus_metric_replace_label(_module->_prometheus_metrics[i],
                                        instance_label);
      }
    } else {
      prometheus_metric_replace_label(metric, node_label);
      prometheus_metric_replace_label(metric, ident_label);
      prometheus_metric_replace_label(metric, instance_label);
    }
  }
}

void np_statistics_set_node_description(np_context *ac, char description[255]) {
  np_ctx_cast(ac);
  prometheus_label label;
  strncpy(label.name, "description", 255);
  strncpy(label.value, description, 255);
  prometheus_metric_replace_label(
      np_module(statistics)
          ->_prometheus_metrics[np_prometheus_exposed_metrics_uptime],
      label);
}

void _np_statistics_destroy(np_state_t *context) {
  if (np_module_initiated(statistics)) {
    np_module_var(statistics);

    sll_iterator(np_dhkey_t) __watched_subjects_item =
        sll_first(_module->__watched_subjects);
    while (__watched_subjects_item != NULL) {
      np_statistics_element_t *value = NULL;
      if (np_simple_cache_get(context,
                              &np_module(statistics)->__cache,
                              &__watched_subjects_item->val,
                              &value)) {
        free(value);
      }
      sll_next(__watched_subjects_item);
    }
    np_cache_destroy(context, &np_module(statistics)->__cache);

#ifdef DEBUG_CALLBACKS
    sll_iterator(void_ptr) __np_debug_statistics_item =
        sll_first(_module->__np_debug_statistics);
    while (__np_debug_statistics_item != NULL) {
      _np_statistics_debug_ele_destroy(context,
                                       __np_debug_statistics_item->val);
      sll_next(__np_debug_statistics_item);
    }
    sll_free(void_ptr, _module->__np_debug_statistics);
#endif

    sll_free(np_dhkey_t, np_module(statistics)->__watched_subjects);

    prometheus_destroy_context(_module->_prometheus_context);

    np_tree_elem_t *tmp = NULL;

    RB_FOREACH (tmp, np_tree_s, _module->_per_dhkey_metrics) {
      free(tmp->val.value.v);
    }

    RB_FOREACH (tmp, np_tree_s, _module->_per_subject_metrics) {
      free(tmp->val.value.v);
    }

    np_tree_free(_module->_per_dhkey_metrics);
    np_tree_free(_module->_per_subject_metrics);

    np_module_free(statistics);
  }
}

char *np_statistics_prometheus_export(np_context *ac) {
  np_ctx_cast(ac);

  return prometheus_format(np_module(statistics)->_prometheus_context);
}

void np_statistics_add_watch(np_state_t *context, np_subject subject) {
  np_dhkey_t subject_dhkey = {
      0}; // _np_msgproperty_dhkey(OUTBOUND, subject_id);
  memcpy(&subject_dhkey, subject, NP_FINGERPRINT_BYTES);

  bool addtolist = true;
  sll_iterator(np_dhkey_t) iter_subjects =
      sll_first(np_module(statistics)->__watched_subjects);
  while (iter_subjects != NULL) {
    if (_np_dhkey_equal(&iter_subjects->val, &subject_dhkey)) {
      addtolist = false;
      break;
    }
    sll_next(iter_subjects);
  }

  // const char* key = (char*) subject;
  np_statistics_element_t *value = NULL;
  if (addtolist == true) {
    // char* key_dup = strndup(subject, strlen(subject) );
    sll_append(np_dhkey_t,
               np_module(statistics)->__watched_subjects,
               subject_dhkey);
    value = calloc(1, sizeof(np_statistics_element_t));
    np_simple_cache_add(context,
                        &np_module(statistics)->__cache,
                        subject,
                        value);
  }

  if (np_simple_cache_get(context,
                          &np_module(statistics)->__cache,
                          subject,
                          &value)) {
    if (addtolist == true) {
      value->last_sec_check = value->last_min_check = value->first_check =
          np_time_now();
    }

    if (false == value->watch_receive &&
        _np_msgproperty_run_get(context, INBOUND, subject_dhkey) != NULL) {
      np_msgproperty_run_t *prop =
          _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
      sll_append(np_evt_callback_t,
                 prop->callbacks,
                 _np_statistics_receive_msg_on_watched);
      value->watch_receive = true;
    }

    if (false == value->watch_send &&
        _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey) != NULL) {
      np_msgproperty_run_t *prop =
          _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
      sll_append(np_evt_callback_t,
                 prop->callbacks,
                 _np_statistics_send_msg_on_watched);
      value->watch_send = true;
    }
  }
}

void np_statistics_add_watch_internals(np_state_t *context) {
  // np_statistics_add_watch(context, _DEFAULT);
  np_subject subject_id = {0};
  np_generate_subject(&subject_id, _NP_MSG_ACK, strnlen(_NP_MSG_ACK, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_HANDSHAKE,
                      strnlen(_NP_MSG_HANDSHAKE, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_JOIN_REQUEST,
                      strnlen(_NP_MSG_JOIN_REQUEST, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_LEAVE_REQUEST,
                      strnlen(_NP_MSG_LEAVE_REQUEST, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_PING_REQUEST,
                      strnlen(_NP_MSG_PING_REQUEST, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_PIGGY_REQUEST,
                      strnlen(_NP_MSG_PIGGY_REQUEST, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_UPDATE_REQUEST,
                      strnlen(_NP_MSG_UPDATE_REQUEST, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_AVAILABLE_RECEIVER,
                      strnlen(_NP_MSG_AVAILABLE_RECEIVER, 256));
  np_statistics_add_watch(context, subject_id);
  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_AVAILABLE_SENDER,
                      strnlen(_NP_MSG_AVAILABLE_SENDER, 256));
  np_statistics_add_watch(context, subject_id);

  memset(subject_id, 0, NP_FINGERPRINT_BYTES);
  np_generate_subject(&subject_id,
                      _NP_MSG_PHEROMONE_UPDATE,
                      strnlen(_NP_MSG_PHEROMONE_UPDATE, 256));
  np_statistics_add_watch(context, subject_id);

  if (context->enable_realm_server || context->enable_realm_client) {
    /*
            np_statistics_add_watch(context, _NP_MSG_REALM_REGISTRATION);
            np_statistics_add_watch(context, _NP_MSG_AUTHENTICATION_REQUEST);
            np_statistics_add_watch(context, _NP_MSG_AUTHORIZATION_REQUEST);
            np_statistics_add_watch(context, _NP_MSG_ACCOUNTING_REQUEST);
    */
  }
}

char *np_statistics_print(np_state_t *context, bool asOneLine) {
  if (!np_module_initiated(statistics)) {
    return strdup("statistics not initiated\n");
  }

  char *ret = NULL;

  char *new_line = "\n";
  if (asOneLine == true) {
    new_line = "    ";
  }
  ret = np_str_concatAndFree(ret, "-%s", new_line);

  sll_iterator(np_dhkey_t) iter_subjects =
      sll_first(np_module(statistics)->__watched_subjects);

  double sec_since_start;

  double current_min_send;
  double current_min_received;
  double min_since_last_print;

  double current_sec_send;
  double current_sec_received;
  double sec_since_last_print;

  double now = np_time_now();

  uint32_t all_total_send = 0, all_total_received = 0;

  while (iter_subjects != NULL) {
    np_statistics_element_t *container = NULL;
    if (np_simple_cache_get(context,
                            &np_module(statistics)->__cache,
                            &iter_subjects->val,
                            &container)) {
      sec_since_start = (now - container->first_check);

      // per Min calc
      min_since_last_print = (now - container->last_min_check) / 60;

      if (min_since_last_print > 1) {
        current_min_received =
            (container->total_received - container->last_total_min_received) /
            min_since_last_print;
        current_min_send =
            (container->total_send - container->last_total_min_send) /
            min_since_last_print;

        container->last_mindiff_received =
            current_min_received - container->last_min_received;
        container->last_mindiff_send =
            current_min_send - container->last_min_send;

        container->last_min_received       = current_min_received;
        container->last_min_send           = current_min_send;
        container->last_min_check          = now;
        container->last_total_min_received = container->total_received;
        container->last_total_min_send     = container->total_send;
      } else if ((sec_since_start / 60) < 1) {
        current_min_received = container->total_received;
        current_min_send     = container->total_send;

        container->last_mindiff_received = current_min_received;
        container->last_mindiff_send     = current_min_send;
      } else {
        current_min_received = container->last_min_received;
        current_min_send     = container->last_min_send;
      }
      // per Min calc end

      // per Sec calc
      sec_since_last_print = (now - container->last_sec_check);

      if (sec_since_last_print > 1) {
        current_sec_received =
            (container->total_received - container->last_total_sec_received) /
            sec_since_last_print;
        current_sec_send =
            (container->total_send - container->last_total_sec_send) /
            sec_since_last_print;

        container->last_secdiff_received =
            current_sec_received - container->last_sec_received;
        container->last_secdiff_send =
            current_sec_send - container->last_sec_send;

        container->last_sec_received       = current_sec_received;
        container->last_sec_send           = current_sec_send;
        container->last_sec_check          = now;
        container->last_total_sec_received = container->total_received;
        container->last_total_sec_send     = container->total_send;
      } else {
        current_sec_received = container->last_sec_received;
        current_sec_send     = container->last_sec_send;
      }
      char subject_buffer[65] = {0};
      np_regenerate_subject(context, subject_buffer, 65, &iter_subjects->val);

      // per sec calc end
      if (container->watch_receive) {
        all_total_received += container->total_received;
        ret = np_str_concatAndFree(
            ret,
            "received total: %7" PRIu32
            " (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
            container->total_received,
            current_sec_received,
            container->last_secdiff_received,
            current_min_received,
            container->last_mindiff_received,
            subject_buffer,
            new_line);
      }

      if (container->watch_send) {
        all_total_send += container->total_send;
        ret = np_str_concatAndFree(
            ret,
            "send     total: %7" PRIu32
            " (%5.1f[%+5.1f] per sec) (%7.1f[%+7.1f] per min) %s%s",
            container->total_send,
            current_sec_send,
            container->last_secdiff_send,
            current_min_send,
            container->last_mindiff_send,
            subject_buffer,
            new_line);
      }
      container->last_total_received = container->total_received;
      container->last_total_send     = container->total_send;
    }
    sll_next(iter_subjects);
  }

  char *details = ret;
  ret           = NULL;

  uint32_t routes = _np_route_my_key_count_routes(context);

  uint32_t tenth           = 1;
  char     tmp_format[512] = {0};
  uint32_t minimize[]      = {routes, all_total_received + all_total_send};
  char     s[32];

  for (uint32_t i = 0; i < (sizeof(minimize) / sizeof(uint32_t)); i++) {
    snprintf(s, 32, "%d", minimize[i]);
    tenth = fmax(tenth, strlen(s));
  }

  snprintf(tmp_format,
           512,
           "%-17s %%%" PRId32 "" PRIu32 " Node:     %%s%%s",
           "received total:",
           tenth);
  ret = np_str_concatAndFree(ret,
                             tmp_format,
                             all_total_received,
                             _np_key_as_str(context->my_node_key),
                             new_line);
  snprintf(tmp_format,
           512,
           "%-17s %%%" PRId32 "" PRIu32 " Identity: %%s%%s",
           "send     total:",
           tenth);
  ret = np_str_concatAndFree(ret,
                             tmp_format,
                             all_total_send,
                             ((context->my_identity == NULL)
                                  ? "-"
                                  : _np_key_as_str(context->my_identity)),
                             new_line);

  snprintf(tmp_format,
           512,
           "%-17s %%%" PRId32 "" PRIu32 " Jobs:     %%4" PRIu32
           " Forwarded Msgs: %%8.0f Pheromones inhale: %%8.0f exhale: %%8.0f "
           "(%%3.1f:%%-3.1f)%%s",
           "total:",
           tenth);

  double __fw_counter_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics[np_prometheus_exposed_metrics_forwarded_msgs]);
  double __pheromones_inhale_counter_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics
              [np_prometheus_exposed_metrics_pheromones_inhale]);
  double __pheromones_exhale_counter_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics
              [np_prometheus_exposed_metrics_pheromones_exhale]);

  size_t __pheromones_ggt           = 1;
  double __pheromones_factor_inhale = 0;
  double __pheromones_factor_exhale = 0;
  if (__pheromones_inhale_counter_r > 0 && __pheromones_exhale_counter_r > 0) {
    //__pheromones_ggt = ggT(__pheromones_inhale_counter_r,
    //__pheromones_exhale_counter_r);
    double __pheromones_factor =
        MIN(__pheromones_exhale_counter_r, __pheromones_inhale_counter_r);
    __pheromones_factor_exhale =
        (__pheromones_exhale_counter_r / __pheromones_factor);
    __pheromones_factor_inhale =
        (__pheromones_inhale_counter_r / __pheromones_factor);
  }

  ret = np_str_concatAndFree(ret,
                             tmp_format,
                             all_total_send + all_total_received,
                             np_jobqueue_count(context),
                             __fw_counter_r,
                             __pheromones_inhale_counter_r,
                             __pheromones_exhale_counter_r,
                             __pheromones_factor_inhale,
                             __pheromones_factor_exhale,
                             new_line);

  snprintf(tmp_format, 512, "%-17s %%" PRIu32 "%%s", "Reachable nodes:");
  ret = np_str_concatAndFree(ret, tmp_format, routes, /*new_line*/ "  ");
  snprintf(tmp_format,
           512,
           "%-17s %%" PRIu32 " (:= %%" PRIu32 "|%%" PRIu32 ") ",
           "Neighbours nodes:");
  uint32_t l, r;
  uint32_t c = _np_route_my_key_count_neighbors(context, &l, &r);
  ret        = np_str_concatAndFree(ret, tmp_format, c, l, r);

  snprintf(tmp_format, 512, "In: %8%s(%5%s) Out: %8%s(%5%s)%%s");
  float __network_send_bytes_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics[np_prometheus_exposed_metrics_network_out]);
  float __network_send_bytes_per_sec_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics
              [np_prometheus_exposed_metrics_network_out_per_sec]);
  float __network_received_bytes_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics[np_prometheus_exposed_metrics_network_in]);
  float __network_received_bytes_per_sec_r = prometheus_metric_get(
      np_module(statistics)
          ->_prometheus_metrics
              [np_prometheus_exposed_metrics_network_in_per_sec]);

  char b1[255], b2[255], b3[255], b4[255];
  ret = np_str_concatAndFree(
      ret,
      tmp_format,
      np_util_stringify_pretty(np_util_stringify_bytes,
                               &__network_received_bytes_r,
                               b1),
      np_util_stringify_pretty(np_util_stringify_bytes_per_sec,
                               &__network_received_bytes_per_sec_r,
                               b3),
      np_util_stringify_pretty(np_util_stringify_bytes,
                               &__network_send_bytes_r,
                               b2),
      np_util_stringify_pretty(np_util_stringify_bytes_per_sec,
                               &__network_send_bytes_per_sec_r,
                               b4),
      new_line);

  ret = np_str_concatAndFree(ret, "%s-%s", details, new_line);
  free(details);

  return ret;
}

#ifdef NP_STATISTICS_COUNTER
void __np_statistics_set_latency(np_state_t *context,
                                 np_dhkey_t  id,
                                 float       value) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_set(
        __np_statistics_get_dhkey_metrics(context, id)->latency,
        value);
  }
}
void __np_statistics_set_success_avg(np_state_t *context,
                                     np_dhkey_t  id,
                                     float       value) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_set(
        __np_statistics_get_dhkey_metrics(context, id)->success_avg,
        value);
  }
}

void __np_increment_forwarding_counter(np_state_t          *context,
                                       NP_UNUSED np_dhkey_t subject) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics[np_prometheus_exposed_metrics_forwarded_msgs],
        1);
  }
}

void __np_statistics_increment_pheromones_inhale(np_state_t *context) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics
                [np_prometheus_exposed_metrics_pheromones_inhale],
        1);
  }
}

void __np_statistics_increment_pheromones_exhale(np_state_t *context) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics
                [np_prometheus_exposed_metrics_pheromones_exhale],
        1);
  }
}

void __np_increment_received_msgs_counter(np_state_t *context,
                                          np_dhkey_t  subject) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics[np_prometheus_exposed_metrics_received_msgs],
        1);
    prometheus_metric_inc(
        __np_statistics_get_subject_metrics(context, subject)->received_msgs,
        1);
  }
}

void __np_increment_send_msgs_counter(np_state_t *context, np_dhkey_t subject) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics[np_prometheus_exposed_metrics_send_msgs],
        1);
    prometheus_metric_inc(
        __np_statistics_get_subject_metrics(context, subject)->send_msgs,
        1);
  }
}

void __np_statistics_add_send_bytes(np_state_t *context, uint32_t add) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics[np_prometheus_exposed_metrics_network_out],
        add);
  }
}

void __np_statistics_add_received_bytes(np_state_t *context, uint32_t add) {
  if (np_module_initiated(statistics)) {
    prometheus_metric_inc(
        np_module(statistics)
            ->_prometheus_metrics[np_prometheus_exposed_metrics_network_in],
        add);
  }
}
#endif

#ifdef DEBUG_CALLBACKS
_np_statistics_debug_t *__np_statistics_debug_get(np_state_t *context,
                                                  char       *key) {
  _np_statistics_debug_t *ret = NULL;
  assert(np_module(statistics) != NULL);
  assert(np_module(statistics)->__np_debug_statistics != NULL);
  sll_iterator(void_ptr) iter =
      sll_first(np_module(statistics)->__np_debug_statistics);

  while (iter != NULL) {
    _np_statistics_debug_t *item = (_np_statistics_debug_t *)iter->val;
    if (strncmp(item->key, key, 255) == 0) {
      ret = item;
      break;
    }
    sll_next(iter);
  }
  return ret;
}

char *__np_statistics_debug_print(np_state_t *context) {
  char *ret = NULL;
  if (np_module_initiated(statistics)) {
    _LOCK_MODULE(np_utilstatistics_t) {
      sll_iterator(void_ptr) iter =
          sll_first(np_module(statistics)->__np_debug_statistics);

      ret = np_str_concatAndFree(ret,
                                 "%-10s %89s --> %8s / %8s / %8s / %10s \n",
                                 "(generic)",
                                 "name",
                                 "min",
                                 "avg",
                                 "max",
                                 "hits");
      while (iter != NULL) {
        _np_statistics_debug_t *item = (_np_statistics_debug_t *)iter->val;
        ret                          = np_str_concatAndFree(
            ret,
            "%100.255s --> %8.6f / %8.6f / %8.6f / %10" PRIu32 "\n",
            item->key,
            item->min,
            item->avg,
            item->max,
            item->count);
        sll_next(iter);
      }
    }
  }
  return ret;
}

void _np_statistics_debug_ele_destroy(np_state_t *context, void *item) {
  _np_statistics_debug_t *ele = (_np_statistics_debug_t *)item;
  _np_threads_mutex_destroy(context, &ele->lock);
  free(ele);
}

_np_statistics_debug_t *
_np_statistics_debug_add(np_state_t *context, char *key, double value) {

  _np_statistics_debug_t *item = NULL;

  _LOCK_MODULE(np_utilstatistics_t) {
    item = __np_statistics_debug_get(context, key);
    if (item == NULL) {
      item =
          (_np_statistics_debug_t *)calloc(1, sizeof(_np_statistics_debug_t));
      item->min = DBL_MAX;
      item->max = 0;
      item->avg = 0;
      ASSERT(key != NULL, "Statistics key cannot be NULL");
      strncpy(item->key, key, 254);
      char mutex_str[64];
      snprintf(mutex_str, 63, "%s", "urn:np:statistics:access");
      _np_threads_mutex_init(context, &item->lock, mutex_str);

      sll_append(void_ptr,
                 np_module(statistics)->__np_debug_statistics,
                 (void_ptr)item);
    }
  }

  if (item != NULL) {
    _LOCK_ACCESS(&item->lock) {
      item->avg = (item->avg * item->count + value) / (item->count + 1);
      item->count++;

      item->max = fmax(value, item->max);
      item->min = fmin(value, item->min);
    }
  }

  return item;
}

void _np_statistics_debug_destroy(np_state_t *context) {
  _LOCK_MODULE(np_utilstatistics_t) {
    sll_iterator(void_ptr) iter_np_debug_statistics =
        sll_first(np_module(statistics)->__np_debug_statistics);
    while (iter_np_debug_statistics != NULL) {
      _np_statistics_debug_ele_destroy(context,
                                       (void *)iter_np_debug_statistics->val);
      sll_next(iter_np_debug_statistics);
    }
    sll_free(void_ptr, np_module(statistics)->__np_debug_statistics);
  }
}
#endif
