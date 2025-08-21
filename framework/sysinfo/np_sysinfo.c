//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "sysinfo/np_sysinfo.h"

#include <inttypes.h>
#include <stdlib.h>

#include "../framework/http/urldecode.h"
#include "inttypes.h"
#include "parson/parson.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "http/np_http.h"
#include "util/np_event.h"
#include "util/np_pcg_rng.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_constants.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_node.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_types.h"

#define _NP_SYSINFO_MY_NODE            "node"
#define _NP_SYSINFO_MY_NODE_TIMESTAMP  "timestamp"
#define _NP_SYSINFO_MY_NODE_STARTUP_AT "startup_at"

#define _NP_SYSINFO_MY_NEIGHBOURS "neighbour_nodes"
#define _NP_SYSINFO_MY_ROUTES     "routing_nodes"
#define _NP_SYSINFO_CONNECT       "connect_string"

#define _NP_SYSINFO_SOURCE "source_hash"
#define _NP_SYSINFO_TARGET "target_hash"

#ifdef np_context
typedef np_context np_state_t *
#endif

np_module_struct(sysinfo) {
  np_state_t *context;
  np_tree_t  *_cache;
  double      startup_at;
};

void _np_sysinfo_init_cache(np_state_t *context) {
  _LOCK_MODULE(np_sysinfo_t) {
    if (!np_module_initiated(sysinfo)) {
      np_module_malloc(sysinfo);
      _module->_cache     = np_tree_create();
      _module->startup_at = np_time_now();
    }
  }
}

void _np_sysinfo_destroy_cache(np_state_t *context) {
  _LOCK_MODULE(np_sysinfo_t) {
    if (np_module_initiated(sysinfo)) {
      np_module_var(sysinfo);
      np_tree_free(_module->_cache);
      np_module_free(sysinfo);
    }
  }
}

bool _np_sysinfo_client_send_cb(np_state_t               *context,
                                NP_UNUSED np_util_event_t args) {
  _np_sysinfo_init_cache(context);

  np_subject sysinfo_subject = {0};
  np_generate_subject(&sysinfo_subject,
                      _NP_SYSINFO_DATA,
                      strnlen(_NP_SYSINFO_DATA, 256));

  if (np_has_receiver_for(context, sysinfo_subject)) {
    np_tree_t *payload = np_sysinfo_get_my_info(context);

    // build properties
    np_tree_insert_str(payload,
                       _NP_SYSINFO_SOURCE,
                       np_treeval_new_s(_np_key_as_str(context->my_node_key)));
    // send msg
    log_info(LOG_SYSINFO,
             NULL,
             "sending sysinfo proactive (size: %" PRIsizet ")",
             payload->size);

    size_t data_length = np_tree_get_byte_size(payload);
    // np_serializer_add_map_bytesize(payload, &data_length);
    unsigned char buffer[data_length];
    np_tree2buffer(context, payload, buffer);

    np_send(context, sysinfo_subject, buffer, data_length);

    np_tree_free(payload);
  } else {
    log_debug(LOG_SYSINFO, NULL, "no receiver token for %s", _NP_SYSINFO_DATA);
  }
  return true;
}

void np_sysinfo_enable_client(np_state_t *context) {

  struct np_mx_properties sysinfo_properties = {
      .role                = NP_MX_PROVIDER,
      .reply_id            = {0},
      .ackmode             = NP_MX_ACK_DESTINATION,
      .message_ttl         = 20.0,
      .max_retry           = 2,
      .max_parallel        = 1,
      .cache_policy        = NP_MX_FIFO_PURGE,
      .cache_size          = 1,
      .intent_ttl          = SYSINFO_MAX_TTL,
      .intent_update_after = SYSINFO_MIN_TTL,
  };

  np_subject sysinfo_subject = {0};
  np_generate_subject(&sysinfo_subject,
                      _NP_SYSINFO_DATA,
                      strnlen(_NP_SYSINFO_DATA, 256));

  np_set_mx_properties(context, sysinfo_subject, sysinfo_properties);

  double first_delay =
      np_global_rng_next_bounded(SYSINFO_PROACTIVE_SEND_IN_SEC) / 1.;
  log_msg(LOG_INFO, NULL, "initial delay for sysinfo: %f", first_delay);

  np_jobqueue_submit_event_periodic(context,
                                    PRIORITY_MOD_USER_DEFAULT,
                                    first_delay / 1.,
                                    // sysinfo_response_props->msg_ttl /
                                    // sysinfo_response_props->max_threshold,
                                    SYSINFO_PROACTIVE_SEND_IN_SEC + .0,
                                    _np_sysinfo_client_send_cb,
                                    "sysinfo_client_send_cb");
}

int _np_http_handle_sysinfo_hash(ht_request_t  *request,
                                 ht_response_t *ret,
                                 void          *context);
int _np_http_handle_sysinfo_all(ht_request_t  *request,
                                ht_response_t *ret,
                                void          *context);

void np_sysinfo_enable_local(np_state_t *context) {
  _np_sysinfo_init_cache(context);

  if (np_module_initiated(http)) {
    _np_add_http_callback(context,
                          "sysinfo",
                          htp_method_GET,
                          context,
                          _np_http_handle_sysinfo_all);

    char my_sysinfo[9 + 64 + 1];
    snprintf(my_sysinfo,
             9 + 64 + 1,
             "sysinfo/%s",
             _np_key_as_str(context->my_node_key));
    _np_add_http_callback(context,
                          my_sysinfo,
                          htp_method_GET,
                          context,
                          _np_http_handle_sysinfo_hash);
  }
}

void np_sysinfo_enable_server(np_state_t *context) {
  _np_sysinfo_init_cache(context);

  struct np_mx_properties sysinfo_properties = {
      .role         = NP_MX_CONSUMER,
      .reply_id     = {0},
      .ackmode      = NP_MX_ACK_DESTINATION,
      .message_ttl  = 20.0,
      .max_retry    = 2,
      .max_parallel = 8,
      .cache_policy = NP_MX_FIFO_PURGE,
      .cache_size   = 32 * (SYSINFO_MAX_TTL / SYSINFO_PROACTIVE_SEND_IN_SEC),
      .intent_ttl   = SYSINFO_MAX_TTL,
      .intent_update_after = SYSINFO_MIN_TTL,
  };

  np_subject sysinfo_subject = {0};
  np_generate_subject(&sysinfo_subject,
                      _NP_SYSINFO_DATA,
                      strnlen(_NP_SYSINFO_DATA, 256));

  np_set_mx_properties(context, sysinfo_subject, sysinfo_properties);
  np_add_receive_cb(context, sysinfo_subject, _np_in_sysinfo);

  if (np_module_initiated(http)) {
    _np_add_http_callback(context,
                          "sysinfo",
                          htp_method_GET,
                          context,
                          _np_http_handle_sysinfo_all);

    char my_sysinfo[9 + 64 + 1];
    snprintf(my_sysinfo,
             9 + 64 + 1,
             "sysinfo/%s",
             _np_key_as_str(context->my_node_key));
    _np_add_http_callback(context,
                          my_sysinfo,
                          htp_method_GET,
                          context,
                          _np_http_handle_sysinfo_hash);
  }
}

bool _np_in_sysinfo(void *ac, struct np_message *msg) {

  np_state_t *context = ac;

  log_msg(LOG_INFO | LOG_SYSINFO, msg->uuid, "received sysinfo");

  np_tree_t payload = {0}; // np_tree_create();
  np_buffer2tree(context, msg->data, msg->data_length, &payload);

  np_tree_elem_t *source = np_tree_find_str(&payload, _NP_SYSINFO_SOURCE);
  if (NULL == source) {
    log_warn(LOG_SYSINFO,
             NULL,
             "received sysinfo request w/o source key information.");
    return false;
  }
  bool   source_str_free = false;
  size_t source_val_len  = 0;
  char  *source_val =
      np_treeval_to_str(source->val, &source_val_len, &source_str_free);

  log_debug(LOG_SYSINFO,
            NULL,
            "caching content for key %s (size: %" PRIsizet
            ", byte_size: %" PRIsizet ")",
            source_val,
            payload.size,
            payload.byte_size);

  // insert / replace cache item
  _LOCK_MODULE(np_sysinfo_t) {
    np_tree_elem_t *item =
        np_tree_find_str(np_module(sysinfo)->_cache, source_val);
    // only insert if the data is newer
    if (NULL != item && item->val.value.tree != NULL) {
      np_tree_elem_t *new_check =
          np_tree_find_str(&payload, _NP_SYSINFO_MY_NODE_TIMESTAMP);
      np_tree_elem_t *old_check =
          np_tree_find_str(item->val.value.tree, _NP_SYSINFO_MY_NODE_TIMESTAMP);

      if (NULL != new_check && NULL != old_check &&
          new_check->val.value.d > old_check->val.value.d) {
        log_debug(LOG_SYSINFO,
                  msg->uuid,
                  "removing old sysinfo for newer data");
        np_tree_replace_str(np_module(sysinfo)->_cache,
                            source_val,
                            np_treeval_new_tree(&payload));
      } else {
        log_debug(LOG_SYSINFO,
                  msg->uuid,
                  "ignoring sysinfo due to newer data in cache");
      }
    } else {
      log_debug(LOG_SYSINFO, msg->uuid, "got sysinfo for a new node");
      np_tree_replace_str(np_module(sysinfo)->_cache,
                          source_val,
                          np_treeval_new_tree(&payload));

      char new_sysinfo[9 + 64 + 1];
      snprintf(new_sysinfo, 9 + 64 + 1, "sysinfo/%s", source_val);
      _np_add_http_callback(context,
                            new_sysinfo,
                            htp_method_GET,
                            context,
                            _np_http_handle_sysinfo_hash);
    }
  }
  if (source_str_free == true) {
    free(source_val);
  }
  np_tree_clear(&payload);
  return true;
}

// HTTP callback functions
np_tree_t *np_sysinfo_get_info(np_state_t       *context,
                               const char *const hash_of_target) {

  char *my_key = _np_key_as_str(context->my_node_key);

  np_tree_t *ret = NULL;
  if (strncmp(hash_of_target, my_key, 64) == 0) {
    log_debug(LOG_SYSINFO, NULL, "Requesting sysinfo for myself");
    // If i request myself i can answer instantly
    ret = np_sysinfo_get_my_info(context);

    // I may anticipate the one requesting my information wants to request
    // others as well
  } else {
    log_debug(LOG_SYSINFO,
              NULL,
              "Requesting sysinfo for node %s",
              hash_of_target);
    ret = _np_sysinfo_get_from_cache(context, hash_of_target, -1);
  }
  return ret;
}

np_tree_t *np_sysinfo_get_my_info(np_state_t *context) {
  np_tree_t *ret = np_tree_create();

  np_tree_insert_str(ret,
                     _NP_SYSINFO_MY_NODE_TIMESTAMP,
                     np_treeval_new_d(np_time_now()));
  np_tree_insert_str(ret,
                     _NP_SYSINFO_MY_NODE_STARTUP_AT,
                     np_treeval_new_d(np_module(sysinfo)->startup_at));

  // build local node with correct interface
  np_tree_t *local_node = np_tree_create();

  np_tree_insert_str(local_node,
                     NP_SERIALISATION_NODE_KEY,
                     np_treeval_new_s(_np_key_as_str(context->my_node_key)));

  np_key_t *my_interface =
      _np_keycache_find_interface(context, context->main_ip, NULL);

  _np_node_encode_to_jrb(local_node, my_interface, true);

  np_unref_obj(np_key_t, my_interface, "_np_keycache_find_interface");

  np_tree_insert_str(ret, _NP_SYSINFO_MY_NODE, np_treeval_new_tree(local_node));
  log_debug(LOG_SYSINFO, NULL, "my sysinfo object has a node");
  np_tree_free(local_node);

  // build neighbours list
  np_tree_t *neighbours                 = np_tree_create();
  np_sll_t(np_key_ptr, neighbour_table) = _np_route_neighbors(context);
  if (NULL != neighbour_table && 0 < sll_size(neighbour_table)) {
    _np_node_encode_multiple_to_jrb(neighbours, neighbour_table, true);
  }
  log_debug(LOG_SYSINFO,
            NULL,
            "my sysinfo object has %" PRIu32 " neighbours",
            sll_size(neighbour_table));

  np_tree_insert_str(ret,
                     _NP_SYSINFO_MY_NEIGHBOURS "_count",
                     np_treeval_new_ul(sll_size(neighbour_table)));
  np_tree_insert_str(ret,
                     _NP_SYSINFO_MY_NEIGHBOURS,
                     np_treeval_new_tree(neighbours));

  np_key_unref_list(neighbour_table, "_np_route_neighbors");
  sll_free(np_key_ptr, neighbour_table);
  np_tree_free(neighbours);

  // build routing list
  np_tree_t *routes                   = np_tree_create();
  np_sll_t(np_key_ptr, routing_table) = _np_route_get_table(context);

  uint32_t routes_counter = 0;
  if (NULL != routing_table && 0 < sll_size(routing_table)) {
    _np_node_encode_multiple_to_jrb(routes, routing_table, true);
  }
  log_debug(LOG_SYSINFO,
            NULL,
            "my sysinfo object has %" PRIu32 " routing table entries",
            sll_size(routing_table));

  np_tree_insert_str(ret,
                     _NP_SYSINFO_MY_ROUTES "_count",
                     np_treeval_new_ul(sll_size(routing_table)));
  np_tree_insert_str(ret, _NP_SYSINFO_MY_ROUTES, np_treeval_new_tree(routes));

  np_key_unref_list(routing_table, "_np_route_get_table");
  sll_free(np_key_ptr, routing_table);
  np_tree_free(routes);

  return ret;
}

np_tree_t *_np_sysinfo_get_from_cache(np_state_t       *context,
                                      const char *const hash_of_target,
                                      uint16_t          max_cache_ttl) {
  _np_sysinfo_init_cache(context);

  np_tree_t *ret = NULL;
  _LOCK_MODULE(np_sysinfo_t) {
    np_tree_elem_t *item =
        np_tree_find_str(np_module(sysinfo)->_cache, hash_of_target);
    if (NULL != item && item->val.value.tree != NULL) {
      np_tree_t *tmp = item->val.value.tree;
      ret            = np_tree_clone(tmp);
    }
  }
  // we may need to reset the found item to prevent the output of a dummy
  if (NULL != ret && max_cache_ttl != ((uint16_t)-1)) {
    if (NULL == np_tree_find_str(ret, _NP_SYSINFO_MY_NODE)) {
      np_tree_free(ret);
      ret = NULL;
    }
  }

  if (NULL == ret) {
    log_debug(LOG_SYSINFO, NULL, "sysinfo reply data received: no");
  } else {
    log_debug(LOG_SYSINFO,
              NULL,
              "sysinfo reply data received: yes (size: %" PRIsizet
              ", byte_size: %" PRIsizet ")",
              ret->size,
              ret->byte_size);
  }

  return ret;
}

void _np_sysinfo_cache_interval(np_state_t *context) {
  bool clean = false;
  _LOCK_MODULE(np_sysinfo_t) {
    do {
      clean                = false;
      np_tree_elem_t *iter = RB_MIN(np_tree_s, np_module(sysinfo)->_cache);
      while (iter != NULL) {
        if (iter->val.value.tree != NULL) {
          np_tree_elem_t *ts = np_tree_find_str(iter->val.value.tree,
                                                _NP_SYSINFO_MY_NODE_TIMESTAMP);
          if (np_time_now() >
              (ts->val.value.d + (SYSINFO_PROACTIVE_SEND_IN_SEC * 3))) {
            RB_REMOVE(np_tree_s, np_module(sysinfo)->_cache, iter);
            clean = true;
            break;
          }
        }
        iter = RB_NEXT(np_tree_s, np_module(sysinfo)->_cache, iter);
      }
    } while (clean);
  }
}

np_tree_t *np_sysinfo_get_all(np_state_t *context) {

  np_tree_t *ret   = np_tree_create();
  int16_t    count = 0;

  np_tree_t *tmp = np_sysinfo_get_my_info(context);

  np_tree_insert_int(ret, count++, np_treeval_new_tree(tmp));
  np_tree_free(tmp);

  _np_sysinfo_cache_interval(context);

  _LOCK_MODULE(np_sysinfo_t) {
    np_tree_elem_t *iter = RB_MIN(np_tree_s, np_module(sysinfo)->_cache);
    while (iter != NULL) {
      if (iter->val.value.tree != NULL) {
        np_tree_insert_int(ret,
                           count++,
                           np_treeval_new_tree(iter->val.value.tree));
      }
      iter = RB_NEXT(np_tree_s, np_module(sysinfo)->_cache, iter);
    }
  }

  return ret;
}

JSON_Value *_np_generate_error_json(const char *error, const char *details) {
  JSON_Value *ret = json_value_init_object();

  json_object_set_string(json_object(ret), "error", error);
  json_object_set_string(json_object(ret), "details", details);

  return ret;
}

int _np_http_handle_sysinfo_hash(ht_request_t  *request,
                                 ht_response_t *ret,
                                 void          *context) {

  char        target_hash[65];
  int         http_status = HTTP_CODE_BAD_REQUEST; // HTTP_CODE_OK
  char       *response;
  JSON_Value *json_obj;
  np_key_t   *key = NULL;

  log_debug(LOG_SYSINFO, NULL, "parse arguments of %s", request->ht_path);

  if (NULL != request->ht_path) {
    log_debug(LOG_SYSINFO, NULL, "request has arguments");

    char *to_parse = NULL, *ht_path_dup = NULL;
    ht_path_dup = to_parse = strndup(request->ht_path, 9 + 64 + 1);
    char *path             = strsep(&to_parse, "/"); // strip leading "/""
    path                   = strsep(&to_parse, "/"); // sysinfo
    char *tmp_target_hash  = strsep(&to_parse, "/"); // target_hash

    log_debug(LOG_SYSINFO,
              NULL,
              "parse path arguments of %s / %s",
              path,
              tmp_target_hash);

    if (NULL != tmp_target_hash) {
      if (strnlen(tmp_target_hash, 65) == 64) {
        snprintf(target_hash, 65, "%s", tmp_target_hash);
      } else {
        json_obj = _np_generate_error_json("provided key invalid.",
                                           "length is not 64 characters");
        free(ht_path_dup);
        goto __json_return__;
      }
    }
    free(ht_path_dup);
  } else {
    log_debug(LOG_SYSINFO, NULL, "no arguments provided");
    json_obj = _np_generate_error_json("no path arguments found",
                                       "expected length is 64 characters");
    goto __json_return__;
  }

  char *my_key = _np_key_as_str(((np_state_t *)context)->my_node_key);

  np_tree_t *sysinfo = np_sysinfo_get_info(context, target_hash);
  if (NULL == sysinfo) {
    log_debug(LOG_SYSINFO, NULL, "Could not find system informations");
    http_status = HTTP_CODE_ACCEPTED;
    json_obj    = _np_generate_error_json("key not found.",
                                       "update request is send. please wait.");
  } else {
    log_debug(LOG_SYSINFO,
              NULL,
              "sysinfo response tree (byte_size: %" PRIsizet,
              sysinfo->byte_size);
    log_debug(LOG_SYSINFO,
              NULL,
              "sysinfo response tree (size: %" PRIsizet,
              sysinfo->size);
    log_debug(LOG_SYSINFO, NULL, "Convert sysinfo to json");
    http_status = HTTP_CODE_OK;
    json_obj    = np_tree2json(context, sysinfo);
    log_debug(LOG_SYSINFO, NULL, "cleanup");
  }
  np_tree_free(sysinfo);

__json_return__:

  log_debug(LOG_SYSINFO, NULL, "serialise json response");

  if (NULL == json_obj) {
    log_warn(LOG_SYSINFO,
             NULL,
             "HTTP return is not defined for this code path");
    http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
    json_obj = _np_generate_error_json("Unknown Error", "no response defined");
  }
  response       = np_json2char(json_obj, false);
  ret->ht_length = json_serialization_size_pretty(json_obj);
  json_value_free(json_obj);

  log_debug(LOG_SYSINFO, NULL, "write to body");

  ret->ht_status = http_status;
  ret->ht_body   = response;

  return http_status;
}

int _np_http_handle_sysinfo_all(ht_request_t  *request,
                                ht_response_t *ret,
                                void          *context) {
  log_debug(LOG_SYSINFO, NULL, "Requesting sysinfo");

  char target_hash[65];

  bool        usedefault  = true;
  int         http_status = HTTP_CODE_BAD_REQUEST;
  char       *response;
  JSON_Value *json_obj;

  /**
   * Default behavior if no argument is given: display own node informations
   */
  log_msg(LOG_INFO, NULL, "parse path arguments of %s", request->ht_path);

  if (NULL != request->ht_query_args) {
    log_msg(LOG_INFO,
            NULL,
            "have %" PRIsizet " query argument(s)",
            request->ht_query_args->size);
    np_tree_elem_t *new_join =
        np_tree_find_str(request->ht_query_args, _NP_SYSINFO_CONNECT);
    if (new_join != NULL) {
      char *url = urlDecode(new_join->val.value.s, new_join->val.size);
      log_msg(LOG_INFO, NULL, "user requested to join: %s", url);
      np_join(context, url);
      free(url);
    }
  }

  np_tree_t *sysinfo = NULL;
  if (NULL != request->ht_path) {
    if (0 == strncmp(request->ht_path, "/sysinfo", 8)) {
      sysinfo = np_sysinfo_get_all(context);
    } else {
      json_obj = _np_generate_error_json("provided key invalid.",
                                         "length is not 64 characters");
      goto __json_return__;
    }
  }

  if (NULL == sysinfo) {
    log_debug(LOG_SYSINFO, NULL, "Could not find system informations");
    http_status = HTTP_CODE_ACCEPTED;
    json_obj =
        _np_generate_error_json("path not found",
                                "only \"/sysinfo\" accepted at this point");
  } else {
    log_debug(LOG_SYSINFO,
              NULL,
              "sysinfo response tree (byte_size: %" PRIsizet,
              sysinfo->byte_size);
    log_debug(LOG_SYSINFO,
              NULL,
              "sysinfo response tree (size: %" PRIsizet,
              sysinfo->size);

    log_debug(LOG_SYSINFO, NULL, "Convert sysinfo to json");
    json_obj = np_tree2json(context, sysinfo);

    http_status = HTTP_CODE_OK;
  }
  np_tree_free(sysinfo);

__json_return__:

  log_debug(LOG_SYSINFO, NULL, "serialise json response");
  if (NULL == json_obj) {
    log_msg(LOG_ERROR, NULL, "HTTP return is not defined for this code path");
    http_status = HTTP_CODE_INTERNAL_SERVER_ERROR;
    json_obj = _np_generate_error_json("Unknown Error", "no response defined");
  }

  response       = np_json2char(json_obj, false);
  ret->ht_length = json_serialization_size_pretty(json_obj);

  json_value_free(json_obj);

  log_debug(LOG_SYSINFO, NULL, "write to body");
  ret->ht_status = http_status;
  ret->ht_body   = response;

  return http_status;
}
