//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "neuropil.h"

#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include "sodium.h"

#include "neuropil_attributes.h"
#include "neuropil_data.h"
#include "neuropil_log.h"

#include "core/np_comp_intent.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_pcg_rng.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_attributes.h"
#include "np_data.h"
#include "np_dhkey.h"
#include "np_eventqueue.h"
#include "np_evloop.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_pheromones.h"
#include "np_route.h"
#include "np_shutdown.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_time.h"
#include "np_token_factory.h"
#include "np_types.h"
#include "np_util.h"

static const char *error_strings[] = {
    "",
    "operation failed",
    "unknown error cause",
    "operation is not implemented",
    "could not init network",
    "argument is invalid",
    "operation is currently invalid",
    "insufficient memory",
    "startup error. See log for more details"};

const char *np_error_str(enum np_return e) {
  if (e > 0) return error_strings[e];
  else return NULL;
}

// split into hash
void np_get_id(np_id(*id), const char *string, size_t length) {
  // np_ctx_cast(ac);
  np_dhkey_t dhkey = _np_dhkey_generate_hash(string, length);
  memcpy(id, &dhkey, NP_FINGERPRINT_BYTES);
}

/**
 * @brief Tries to reverse the subject generation.
 *
 * @param[in] context The context to work in
 * @param[out] subject_buffer has to be at least 64 characters long.
 * @param[in] buffer_length The buffer length provided
 * @param[in] subject the subject to regenerate
 * @return enum np_return
 */
enum np_return np_regenerate_subject(NP_UNUSED np_context *ac,
                                     char                 *subject_buffer,
                                     size_t                buffer_length,
                                     const np_subject      subject) {
  if (buffer_length < 64 || subject_buffer == NULL) {
    return np_invalid_argument;
  }
  bool is_known = false;

  const char       *known_subjects[]           = {_NP_MSG_ACK,
                                                  _NP_MSG_HANDSHAKE,
                                                  _NP_MSG_JOIN_REQUEST,
                                                  _NP_MSG_LEAVE_REQUEST,
                                                  _NP_MSG_PING_REQUEST,
                                                  _NP_MSG_PIGGY_REQUEST,
                                                  _NP_MSG_UPDATE_REQUEST,
                                                  _NP_MSG_PHEROMONE_UPDATE,
                                                  _NP_MSG_AVAILABLE_RECEIVER,
                                                  _NP_MSG_AVAILABLE_SENDER,
                                                  _NP_MSG_AUTHENTICATION_REQUEST,
                                                  _NP_MSG_AUTHENTICATION_REPLY,
                                                  _NP_MSG_AUTHORIZATION_REQUEST,
                                                  _NP_MSG_AUTHORIZATION_REPLY,
                                                  _NP_MSG_ACCOUNTING_REQUEST,
                                                  "_NP.SYSINFO.DATA"};
  static bool       bin_subjects_are_generated = false;
  static np_subject known_bin_subjects[16];
  if (!bin_subjects_are_generated) {
    for (int i = 0; i < 16; i++) {
      np_generate_subject(&known_bin_subjects[i],
                          known_subjects[i],
                          strnlen(known_subjects[i], 256));
    }
    bin_subjects_are_generated = true;
  }

  for (int i = 0; i < 16; i++) {
    if (memcmp(subject, &known_bin_subjects[i], NP_FINGERPRINT_BYTES) == 0) {
      strncpy(subject_buffer, known_subjects[i], buffer_length);
      is_known = true;
      break;
    }
  }
  if (!is_known) {
    np_id_str(subject_buffer, subject);
    return np_not_implemented;
  }
  return np_ok;
}

enum np_return np_generate_subject(np_subject(*subject_id),
                                   const char *subject,
                                   size_t      length) {
  np_dhkey_t dhkey = _np_dhkey_generate_hash(subject, length);
  _np_dhkey_xor((np_dhkey_t *)subject_id, &dhkey, (np_dhkey_t *)subject_id);

  return np_ok;
}

struct np_settings *np_default_settings(struct np_settings *settings) {
  struct np_settings *ret;
  if (settings == NULL) {
    ret = malloc(sizeof(struct np_settings));
  } else {
    ret = settings;
  }
  ret->n_threads = 5;
  snprintf(ret->log_file, 256, "%.0f_neuropil.log", _np_time_now(NULL) * 100);
  ret->log_level = LOG_ERROR;
  ret->log_level |= LOG_WARNING;
  ret->log_level |= LOG_INFO;

  ret->leafset_size     = NP_LEAFSET_MAX_ENTRIES;
  ret->jobqueue_size    = JOBQUEUE_MAX_SIZE;
  ret->log_write_fn     = NULL;
  ret->max_msgs_per_sec = 0;

#ifdef DEBUG
  ret->log_level |= LOG_DEBUG
                    // | LOG_VERBOSE
                    // | LOG_TRACE
                    // | LOG_MUTEX
                    | LOG_ROUTING
                    // | LOG_HTTP
                    // | LOG_KEY
                    | LOG_NETWORK
                    //| LOG_HANDSHAKE
                    | LOG_AAATOKEN |
                    LOG_MSGPROPERTY
                    //| LOG_SYSINFO
                    | LOG_MESSAGE
                    // | LOG_SERIALIZATION
                    // | LOG_MEMORY
                    | LOG_PHEROMONE |
                    LOG_MISC
                    // | LOG_EVENT
                    // | LOG_THREADS
                    // | LOG_JOBS
                    | LOG_GLOBAL;
#endif

  return ret;
}

np_context *np_new_context(struct np_settings *settings_in) {
  enum np_return status  = np_ok;
  np_state_t    *context = NULL;

  struct np_settings *settings = settings_in;
  if (settings_in == NULL) {
    settings = np_default_settings(NULL);
  }

  // TODO: check settings for bad configuration
  context = (np_state_t *)calloc(1, sizeof(np_state_t));
  CHECK_MALLOC(context);
  TSP_INITD(context->_shutdown_started, false);
  context->settings = settings;

  MAP(np_module_init_null, NP_CTX_MODULES);

  np_global_rng_init();

  if (sodium_init() == -1) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init crypto library");
  } else if (_np_threads_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init threading mutexes");
  } else if (_np_statistics_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init statistics");
  } else if (_np_event_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init event system");
  } else if (_np_log_init(context, settings->log_file, settings->log_level) ==
             false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init logging");
  } else if (_np_memory_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init memory");
  } else if (_np_time_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not init time cache");
  } else if (_np_dhkey_init(context) == false) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: could not init distributed hash table");
  } else if (_np_keycache_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: _np_keycache_init failed");
  } else if (_np_msgproperty_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: _np_msgproperty_init failed");
  } else if (_np_attributes_init(context) == false) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: _np_attributes_init failed");
  } else if (_np_jobqueue_init(context) == false) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: _np_jobqueue_init failed: %s",
            strerror(errno));

  } else if (!_np_network_module_init(context)) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: could not enable general networking");

  } else if (!_np_statistics_enable(context)) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not enable statistics");
  } else {
    np_thread_t *new_thread =
        __np_createThread(context, NULL, false, np_thread_type_main);
    new_thread->id = (size_t)getpid();
    _np_threads_set_self(new_thread);

    // set default aaa functions
    np_set_authorize_cb(context, _np_default_authorizefunc);
    np_set_accounting_cb(context, _np_default_accountingfunc);
    np_set_authenticate_cb(context, _np_default_authenticatefunc);

    context->enable_realm_client = false;
    context->enable_realm_server = false;

    // initialize message part handling cache
    context->msg_part_cache = np_tree_create();

    struct np_bloom_optable_s decaying_op = {
        .add_cb   = _np_decaying_bloom_add,
        .check_cb = _np_decaying_bloom_check,
        .clear_cb = _np_standard_bloom_clear,
    };
    context->msg_part_filter =
        _np_decaying_bloom_create(NP_MSG_PART_FILTER_SIZE, 16, 1);
    context->msg_part_filter->op = decaying_op;
  }

  np_aaatoken_t *node_token = _np_token_factory_new_node_token(context);
  _np_set_identity(context, node_token);

  // initialize routing table
  if (_np_route_init(context, context->my_node_key) == false) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: route_init failed: %s",
            strerror(errno));
  }

  TSP_INITD(context->status, np_stopped);
  return ((np_context *)context);
}

enum np_return np_listen(np_context *ac,
                         const char *protocol,
                         const char *host,
                         uint16_t    port) {
  assert(host != NULL);
  assert(protocol != NULL);

  char *safe_protocol   = protocol ? strndup(protocol, 5) : NULL;
  char *safe_host       = host ? strndup(host, 255) : NULL;
  char  safe_service[8] = {0};

  snprintf(safe_service, 7, "%" PRIu16, port);

  enum np_return ret =
      _np_listen_safe(ac, safe_protocol, safe_host, safe_service);
  free(safe_host);
  free(safe_protocol);
  return ret;
}

// secret_key is nullable
struct np_token
np_new_identity(np_context *ac,
                double      expires_at,
                unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]) {
  np_ctx_cast(ac);

  struct np_token           ret = {0};
  np_ident_private_token_t *new_token =
      np_token_factory_new_identity_token(context, expires_at, secret_key);
  np_aaatoken4user(&ret, new_token, true);

#ifdef DEBUG
  char       tmp[65] = {0};
  np_dhkey_t d       = np_aaatoken_get_fingerprint(new_token, false);
  np_id_str(tmp, *(np_id *)&d);
  log_debug(LOG_AAATOKEN,
            new_token->uuid,
            "created new ident token (fp:%s)",
            tmp);
#endif

  np_unref_obj(np_aaatoken_t, new_token, "np_token_factory_new_identity_token");
  return ret;
}

enum np_return np_node_fingerprint(np_context *ac, np_id(*id)) {
  np_ctx_cast(ac);
  enum np_return ret = np_ok;

  if (id == NULL) {
    ret = np_invalid_argument;
  } else {
    np_dhkey_t fp = dhkey_zero;
    if (context->my_node_key != NULL)
      fp = np_aaatoken_get_fingerprint(_np_key_get_token(context->my_node_key),
                                       false);
    memcpy(id, &fp, NP_FINGERPRINT_BYTES);
  }
  return ret;
}

enum np_return
np_sign_identity(np_context *ac, struct np_token *identity, bool self_sign) {
  np_ctx_cast(ac);

  if (identity == NULL) {
    return (np_invalid_argument);
  }
  // check for empty signature
  char empty_sk[NP_SECRET_KEY_BYTES] = {0};
  if (self_sign &&
      0 == memcmp(empty_sk, identity->secret_key, NP_SECRET_KEY_BYTES)) {
    return (np_invalid_argument);
  }

  enum np_return            ret      = np_ok;
  np_ident_private_token_t *id_token = NULL;

  if (self_sign) {
    id_token = np_token_factory_new_identity_token(context,
                                                   identity->expires_at,
                                                   &identity->secret_key);
    np_user4aaatoken(id_token, identity);
    _np_aaatoken_set_signature(id_token, NULL);
    _np_aaatoken_update_attributes_signature(id_token);

  } else {
    id_token = np_token_factory_new_identity_token(context, 20.0, NULL);
    np_user4aaatoken(id_token, identity);
    _np_aaatoken_set_signature(id_token,
                               _np_key_get_token(context->my_identity));
  }
  np_aaatoken4user(identity, id_token, self_sign);

  np_unref_obj(np_aaatoken_t, id_token, "np_token_factory_new_identity_token");

  return ret;
}

enum np_return np_verify_issuer(np_context     *ac,
                                struct np_token identity,
                                struct np_token issuer) {
  np_ctx_cast(ac);

  enum np_return ret = np_operation_failed;

  np_ident_public_token_t *identity_token =
      np_token_factory_new_identity_token(context, identity.expires_at, NULL);
  np_user4aaatoken(identity_token, &identity);
  identity_token->state = AAA_AUTHENTICATED | AAA_VALID;
  _np_aaatoken_get_hash(identity_token);
  log_msg(LOG_DEBUG, NULL, "have identity token");

  np_ident_public_token_t *issuer_token =
      np_token_factory_new_identity_token(context, issuer.expires_at, NULL);
  np_user4aaatoken(issuer_token, &issuer);
  issuer_token->state = AAA_AUTHENTICATED | AAA_VALID;
  _np_aaatoken_get_hash(issuer_token);
  log_msg(LOG_DEBUG, NULL, "have issuer token");

  ret = _np_aaatoken_verify_signature(identity_token, issuer_token);

  np_unref_obj(np_aaatoken_t,
               identity_token,
               "np_token_factory_new_identity_token");
  np_unref_obj(np_aaatoken_t,
               issuer_token,
               "np_token_factory_new_identity_token");

  return (ret);
}

enum np_return np_token_fingerprint(np_context     *ac,
                                    struct np_token identity,
                                    bool            include_attributes,
                                    np_id(*id)) {
  np_ctx_cast(ac);

  enum np_return ret = np_ok;
  if (id == NULL) {
    ret = np_invalid_argument;
  } else {
    // np_ident_private_token_t* imported_token =
    // np_token_factory_new_identity_token(ac,  identity.expires_at,
    // &identity.secret_key);
    np_ident_private_token_t *imported_token =
        np_token_factory_new_identity_token(ac, identity.expires_at, NULL);
    np_user4aaatoken(imported_token, &identity);

    np_dhkey_t fp =
        np_aaatoken_get_fingerprint(imported_token, include_attributes);

    memcpy(id, &fp, NP_FINGERPRINT_BYTES);
    np_unref_obj(np_aaatoken_t,
                 imported_token,
                 "np_token_factory_new_identity_token");
  }

  return ret;
}

enum np_return np_use_token(np_context *ac, struct np_token token) {
  np_ctx_cast(ac);

  // TSP_GET(enum np_status, context->status, state);
  // if (state != np_running) return np_invalid_operation;

  log_debug(LOG_AAATOKEN, token.uuid, "importing ident token");
  np_aaatoken_t *imported_token = NULL;
  np_new_obj(np_aaatoken_t, imported_token, FUNC);

  np_user4aaatoken(imported_token, &token);
  if (!_np_aaatoken_is_valid(context, imported_token, imported_token->type))
    return np_invalid_argument;

  // the user told us to import the token, meaning it is
  // pre-authenticated pre-authorized by the user
  imported_token->state = AAA_AUTHENTICATED | AAA_AUTHORIZED;

  np_dhkey_t search_key = {0};
  if (imported_token->type == np_aaatoken_type_identity ||
      imported_token->type == np_aaatoken_type_node)
    search_key = np_aaatoken_get_fingerprint(imported_token, false);
  else if (imported_token->type == np_aaatoken_type_message_intent)
    np_str_id((np_id *)&search_key, imported_token->subject);
  else if (imported_token->type == np_aaatoken_type_accounting) {
    // TODO: noop as of now
    np_str_id((np_id *)&search_key, imported_token->subject);
  } else {
    return np_invalid_argument;
  }

  // here for the side effect: creating an entity in our internal table
  _np_keycache_find_or_create(context, search_key);

  np_util_event_t ev = {.type         = (evt_internal | evt_token),
                        .user_data    = imported_token,
                        .target_dhkey = search_key};
  _np_event_runtime_start_with_event(context, search_key, ev);

  log_msg(LOG_INFO,
          imported_token->uuid,
          "neuropil successfully inported token of type %d",
          imported_token->type);
  return np_ok;
}

enum np_return np_use_identity(np_context *ac, struct np_token identity) {
  np_ctx_cast(ac);

  TSP_GET(enum np_status, context->status, state);
  if (state == np_running) return np_invalid_operation;

  log_debug(LOG_AAATOKEN, identity.uuid, "importing ident token");

  np_ident_private_token_t *imported_token =
      np_token_factory_new_identity_token(ac,
                                          identity.expires_at,
                                          &identity.secret_key);

  np_user4aaatoken(imported_token, &identity);
  _np_aaatoken_set_signature(imported_token, NULL);

  _np_set_identity(context, imported_token);
  _np_aaatoken_update_attributes_signature(imported_token);
  log_msg(LOG_INFO,
          NULL,
          "neuropil successfully initialized: id:   %s",
          _np_key_as_str(context->my_identity));
  return np_ok;
}

enum np_return np_get_address(np_context *ac, char *address, uint32_t max) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  np_key_t *main_itf_key =
      _np_keycache_find_interface(context, context->main_ip, NULL);

  if (main_itf_key == NULL) return np_operation_failed;

  char *str = np_get_connection_string_from(main_itf_key, true);
  log_msg(LOG_DEBUG, NULL, "str: %s", str);
  if (strlen(str) > max) {
    ret = np_invalid_argument;
  } else {
    strncpy(address, str, max);
  }
  free(str);

  return ret;
}

bool np_has_joined(np_context *ac) {
  assert(ac != NULL);
  bool ret = false;

  np_ctx_cast(ac);
  TSP_GET(enum np_status, context->status, context_status);
  if (context_status != np_running) return ret;

  if (_np_route_has_connection(context) && context->my_node_key != NULL) {
    ret = true;
  }

  return ret;
}

bool np_has_receiver_for(np_context *ac, np_subject subject) {
  assert(ac != NULL);
  assert(subject != NULL);

  np_ctx_cast(ac);
  bool ret = false;

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject, NP_FINGERPRINT_BYTES);
  np_dhkey_t out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);

  char buff[100] = {0};
  np_regenerate_subject(context, buff, 100, &out_dhkey);

  log_info(LOG_MISC,
           NULL,
           "user requests info for availibility of subject %s",
           buff);

  np_dhkey_t prop_dhkey =
      _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);
  np_key_t *prop_key = _np_keycache_find(context, prop_dhkey);

  if (prop_key == NULL) return false;

  np_sll_t(np_aaatoken_ptr, receiver_list);
  sll_init(np_aaatoken_ptr, receiver_list);

  np_dhkey_t null_dhkey = {0};
  _LOCK_ACCESS(&prop_key->key_lock) {
    _np_intent_get_all_receiver(prop_key, null_dhkey, &receiver_list);
  }
  if (sll_size(receiver_list) > 0) ret = true;

  np_aaatoken_unref_list(receiver_list, "_np_intent_get_all_receiver");
  sll_free(np_aaatoken_ptr, receiver_list);
  np_unref_obj(np_key_t, prop_key, "_np_keycache_find");

  return ret;
}

uint16_t np_get_route_count(np_context *ac) {
  np_ctx_cast(ac);
  TSP_GET(enum np_status, context->status, context_status);
  if (context_status != np_running) return 0;

  return _np_get_route_count(context);
}

enum np_return np_join(np_context *ac, const char *address) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);
  TSP_GET(enum np_status, context->status, context_status);

  if (address == NULL) return np_invalid_argument;
  if (strnlen(address, 500) <= 10) return np_invalid_argument;
  if (strnlen(address, 500) >= 500) return np_invalid_argument;
  if (context_status != np_running) return np_invalid_operation;

  // char *nts = memchr(address,'\0', strnlen(address, 500));
  // if (nts == NULL) return np_invalid_argument;
  char *safe_address = strndup(address, 500);
  np_send_join(context, safe_address);
  free(safe_address);

  return ret;
}

enum np_return np_send(np_context          *ac,
                       np_subject           subject_id,
                       const unsigned char *message,
                       size_t               length) {

  if (subject_id == NULL) return np_invalid_argument;
  // if (strnlen(subject,500) == 0) return np_invalid_argument;

  // char* safe_subject = strndup(subject_id,255);
  enum np_return ret = np_send_to(ac, subject_id, message, length, NULL);

  // free(safe_subject);
  return ret;
}

enum np_return np_send_to(np_context          *ac,
                          np_subject           subject_id,
                          const unsigned char *message_body,
                          size_t               length,
                          np_id(*target)) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  np_dhkey_t subject_dhkey = {0};
  // _np_msgproperty_dhkey(OUTBOUND, subject_id);
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  // make sure that an outbound msgproperty exists, function call is here for
  // the side effect
  np_msgproperty_conf_t *property_conf =
      _np_msgproperty_get_or_create(ac, OUTBOUND, subject_dhkey);
  if (property_conf->audience_type == NP_MX_AUD_VIRTUAL)
    return np_invalid_operation;

  np_msgproperty_register(property_conf);

  np_msgproperty_run_t *property_run =
      _np_msgproperty_run_get(ac, OUTBOUND, subject_dhkey);

  np_tree_t *body = np_tree_create();
  np_tree_insert_str(body,
                     NP_SERIALISATION_USERDATA,
                     np_treeval_new_bin((void *)message_body, length));

  np_attributes_t tmp_msg_attr;

  if (np_ok == np_init_datablock(tmp_msg_attr, sizeof(tmp_msg_attr))) {
    struct np_data_conf from_config = {.type      = NP_DATA_TYPE_BIN,
                                       .data_size = NP_FINGERPRINT_BYTES};
    strncpy(from_config.key, _NP_MSG_HEADER_FROM, 255);
    np_data_value from_value = {.bin = &context->my_identity->dhkey};
    np_set_data(tmp_msg_attr, from_config, from_value);

    np_merge_data(tmp_msg_attr,
                  _np_get_attributes_cache(context, NP_ATTR_USER_MSG));
    np_merge_data(
        tmp_msg_attr,
        _np_get_attributes_cache(context, NP_ATTR_IDENTITY_AND_USER_MSG));
    np_merge_data(
        tmp_msg_attr,
        _np_get_attributes_cache(context, NP_ATTR_INTENT_AND_USER_MSG));

    size_t attributes_size;
    if (np_ok == np_get_data_size(tmp_msg_attr, &attributes_size) &&
        attributes_size > 0) {
      np_tree_insert_str(body,
                         NP_SERIALISATION_ATTRIBUTES,
                         np_treeval_new_bin(tmp_msg_attr, attributes_size));
    }
  }

  // target_dhkey is used as a selector for the crypto session ->
  np_dhkey_t target_dhkey = {0};

  if (target != NULL) {
    _np_dhkey_assign(&target_dhkey, target);
  } else {
    _np_dhkey_assign(&target_dhkey, &property_run->current_fp);
  }
  np_dhkey_t out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);

  struct np_e2e_message_s *msg_out = NULL;
  np_new_obj(np_message_t, msg_out);

  _np_message_create(msg_out,
                     target_dhkey,
                     context->my_identity->dhkey,
                     subject_dhkey,
                     body);

  log_info(LOG_MESSAGE | LOG_EXPERIMENT | LOG_ROUTING,
           msg_out->uuid,
           "user sending message (size: %" PRIsizet ")",
           length);

  np_util_event_t send_event = {.type         = (evt_internal | evt_message),
                                .user_data    = msg_out,
                                .target_dhkey = target_dhkey};

  if (!np_jobqueue_submit_event(context,
                                0.0,
                                out_dhkey,
                                send_event,
                                "event: userspace message delivery request")) {
    log_msg(LOG_WARNING,
            msg_out->uuid,
            "rejecting sending of message, please check jobqueue settings!");
  }
  np_tree_free(body);
  np_unref_obj(np_message_t, msg_out, ref_obj_creation);

  return ret;
}

bool __np_receive_callback_converter(void                                *ac,
                                     const struct np_e2e_message_s *const msg,
                                     np_tree_t                           *body,
                                     void *localdata) {
  np_ctx_cast(ac);
  bool                ret      = true;
  np_receive_callback callback = localdata;
  np_tree_elem_t *userdata = np_tree_find_str(body, NP_SERIALISATION_USERDATA);

  if (userdata != NULL) {
    struct np_message message = {0};
    memcpy(message.uuid, msg->uuid, NP_UUID_BYTES);
    memcpy(&message.subject, msg->subject, NP_FINGERPRINT_BYTES);

    message.received_at = np_time_now(); // todo get from network
    // message.send_at = msg.             // todo get from msg
    message.data        = userdata->val.value.bin;
    message.data_length = userdata->val.size;

    np_tree_elem_t *msg_attributes =
        np_tree_find_str(body, NP_SERIALISATION_ATTRIBUTES);

    if (msg_attributes == NULL) {
      np_init_datablock(message.attributes, sizeof(message.attributes));
    } else {
      np_datablock_t *dt = msg_attributes->val.value.bin;
      // size_t attr_size;
      if (sizeof(message.attributes) >= msg_attributes->val.size) {
        memcpy(message.attributes, dt, msg_attributes->val.size);
      }
    }
    struct np_data_conf from_config = {0};
    strncpy(from_config.key, _NP_MSG_HEADER_FROM, 255);
    np_data_value from_value = {0};
    if (np_data_ok == np_get_data(message.attributes,
                                  _NP_MSG_HEADER_FROM,
                                  &from_config,
                                  &from_value)) {
      assert(from_config.data_size == NP_FINGERPRINT_BYTES);
      memcpy(message.from, from_value.bin, NP_FINGERPRINT_BYTES);
      log_debug(LOG_MESSAGE, msg->uuid, "extracted from value from attributes");
    } else {
      // TODO: pull in sender id from intent token
    }

    log_debug(LOG_MESSAGE, msg->uuid, "calling user function.");
    callback(context, &message);

  } else {
    log_info(LOG_MESSAGE | LOG_ROUTING, msg->uuid, "contained no user data");
  }
  log_info(LOG_MESSAGE | LOG_EXPERIMENT, msg->uuid, "message send to user");
  return ret;
}

enum np_return np_add_receive_cb(np_context         *ac,
                                 np_subject          subject_id,
                                 np_receive_callback callback) {
  enum np_return ret = np_ok;
  // np_ctx_cast(ac);

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_add_receive_listener(ac,
                          __np_receive_callback_converter,
                          callback,
                          subject_dhkey);
  return ret;
}

enum np_return np_set_authenticate_cb(np_context     *ac,
                                      np_aaa_callback callback) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  context->authenticate_func = callback;

  return ret;
}

enum np_return np_set_authorize_cb(np_context *ac, np_aaa_callback callback) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  context->authorize_func = callback;

  return ret;
}

enum np_return np_set_accounting_cb(np_context *ac, np_aaa_callback callback) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  context->accounting_func = callback;

  return ret;
}

struct np_mx_properties np_get_mx_properties(np_context      *ac,
                                             const np_subject subject_id) {
  np_ctx_cast(ac);
  struct np_mx_properties ret = {0};

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_msgproperty_conf_t *property =
      _np_msgproperty_conf_get(context, DEFAULT_MODE, subject_dhkey);
  if (property != NULL) np_msgproperty4user(&ret, property);

  return ret;
}

enum np_return np_set_mx_authorize_cb(np_context      *ac,
                                      const np_subject subject_id,
                                      np_aaa_callback  callback) {
  np_ctx_cast(ac);
  enum np_return ret = np_invalid_operation;

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_msgproperty_run_t *property = NULL;

  property = _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
  if (property != NULL && property->authorize_func == NULL) {
    property->authorize_func = callback;
    ret                      = np_ok;
    log_debug(LOG_INFO,
              NULL,
              "set authorization callback on inbound subject (%08" PRIx32
              ":%08" PRIx32 ") level",
              subject_dhkey.t[0],
              subject_dhkey.t[1]);
  } else {
    log_debug(LOG_WARNING,
              NULL,
              "cannot set authorization callback on inbound subject (%08" PRIx32
              ":%08" PRIx32
              ") level, as it is already set or it doesn't exists",
              subject_dhkey.t[0],
              subject_dhkey.t[1]);
  }

  property = _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
  if (property != NULL && property->authorize_func == NULL) {
    property->authorize_func = callback;
    ret                      = np_ok;
    log_debug(LOG_INFO,
              NULL,
              "set authorization callback on outbound subject (%08" PRIx32
              ":%08" PRIx32 ") level",
              subject_dhkey.t[0],
              subject_dhkey.t[1]);
  } else {
    log_debug(
        LOG_WARNING,
        NULL,
        "cannot set authorization callback on outbound subject (%08" PRIx32
        ":%08" PRIx32 ") level, as it is already set or it doesn't exists",
        subject_dhkey.t[0],
        subject_dhkey.t[1]);
  }

  return ret;
}

enum np_return np_set_mx_properties(np_context             *ac,
                                    const np_subject        subject_id,
                                    struct np_mx_properties user_property) {
  np_ctx_cast(ac);
  enum np_return ret = np_ok;

  // TODO: validate user_property
  struct np_mx_properties safe_user_property = user_property;
  // safe_user_property.reply_id[254] = 0;

  np_dhkey_t subject_dhkey = {0};

  // check if the audience field has been set for protected data channels
  if (user_property.audience_type == NP_MX_AUD_PROTECTED &&
      _np_dhkey_equal(&user_property.audience_id, &subject_dhkey))
    return np_invalid_operation;

  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_msgproperty_conf_t *property =
      _np_msgproperty_get_or_create(context, DEFAULT_MODE, subject_dhkey);
  np_msgproperty_from_user(context, property, &safe_user_property);
  property->unique_uuids_check = true;
  np_msgproperty_register(property);
  log_msg(LOG_INFO, NULL, "msgproperty setup complete");
  return ret;
}

enum np_return np_mx_properties_enable(np_context      *ac,
                                       const np_subject subject_id) {
  np_ctx_cast(ac);
  enum np_return ret = np_ok;

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_dhkey_t in_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND, subject_dhkey);
  np_util_event_t enable_event = {
      .type         = (evt_enable | evt_internal | evt_property),
      .target_dhkey = subject_dhkey};
  if (_np_keycache_exists(context, in_dhkey, NULL)) {
    np_msgproperty_run_t *property =
        _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
    // np_dhkey_t property_dhkey = _np_msgproperty_dhkey(DEFAULT_MODE,
    // subject_id);
    enable_event.user_data = property;
    _np_event_runtime_start_with_event(ac, subject_dhkey, enable_event);
  }
  np_dhkey_t out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);
  if (_np_keycache_exists(context, out_dhkey, NULL)) {
    np_msgproperty_run_t *property =
        _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
    enable_event.user_data = property;
    _np_event_runtime_start_with_event(ac, out_dhkey, enable_event);
  }
  return ret;
}

enum np_return np_mx_properties_disable(np_context      *ac,
                                        const np_subject subject_id) {
  np_ctx_cast(ac);
  enum np_return ret = np_ok;

  np_dhkey_t subject_dhkey = {0};
  memcpy(&subject_dhkey, subject_id, NP_FINGERPRINT_BYTES);

  np_dhkey_t in_dhkey = _np_msgproperty_tweaked_dhkey(INBOUND, subject_dhkey);
  np_util_event_t disable_event = {
      .type         = (evt_disable | evt_internal | evt_property),
      .target_dhkey = subject_dhkey};

  if (_np_keycache_exists(context, in_dhkey, NULL)) {
    np_msgproperty_conf_t *property =
        _np_msgproperty_run_get(context, INBOUND, subject_dhkey);
    disable_event.user_data = property;
    _np_event_runtime_start_with_event(ac, subject_dhkey, disable_event);
  }

  np_dhkey_t out_dhkey = _np_msgproperty_tweaked_dhkey(OUTBOUND, subject_dhkey);
  if (_np_keycache_exists(context, out_dhkey, NULL)) {
    np_msgproperty_run_t *property =
        _np_msgproperty_run_get(context, OUTBOUND, subject_dhkey);
    disable_event.user_data = property;
    _np_event_runtime_start_with_event(ac, out_dhkey, disable_event);
  }

  return ret;
}

enum np_return np_run(np_context *ac, double duration) {
  np_ctx_cast(ac);
  enum np_return ret    = np_ok;
  np_thread_t   *thread = _np_threads_get_self(context);

  if (context->main_ip == NULL) {
    ret = np_listen(ac,
                    _np_network_get_protocol_string(context, PASSIVE | IPv4),
                    "localhost",
                    31415);
  }

  TSP_SCOPE(context->status) {
    if (context->status == np_stopped) {

      _np_shutdown_init(context);
      np_threads_start_workers(context, context->settings->n_threads);

      log_info(LOG_MISC,
               NULL,
               "neuropil successfully initialized: id:   %s",
               _np_key_as_str(context->my_identity));
      log_info(LOG_MISC,
               NULL,
               "neuropil successfully initialized: node: %s",
               _np_key_as_str(context->my_node_key));
      log_info(LOG_EXPERIMENT,
               NULL,
               "node: %s / id: %s",
               _np_key_as_str(context->my_node_key),
               _np_key_as_str(context->my_identity));
      _np_log_fflush(context, true);
    }
    ret = np_ok;
  }

  TSP_GET(enum np_status, context->status, context_status);
  if (context_status == np_shutdown) ret = np_invalid_operation;

  if (ret == np_ok) {
    TSP_SET(context->status, np_running);

    if (duration <= 0) {
      np_threads_busyness(context, thread, true);
      __np_jobqueue_run_jobs_once(context, thread);
      np_threads_busyness(context, thread, false);
    } else {
      np_jobqueue_run_jobs_for(context, thread, duration);
    }
  }
  return ret;
}

enum np_return np_add_shutdown_cb(np_context *ac, np_callback callback) {
  // np_ctx_cast(ac);
  np_shutdown_add_callback(ac, (np_destroycallback_t)callback);

  return np_ok;
}

void np_set_userdata(np_context *ac, void *userdata) {
  np_ctx_cast(ac);
  context->userdata = userdata;
}

void *np_get_userdata(np_context *ac) {
  np_ctx_cast(ac);
  return context->userdata;
}

enum np_status np_get_status(np_context *ac) {
  np_ctx_cast(ac);
  TSP_GET(enum np_status, context->status, ret);
  return ret;
}

char *np_id_str(char str[65], const np_id id) {
  sodium_bin2hex(str, NP_FINGERPRINT_BYTES * 2 + 1, id, NP_FINGERPRINT_BYTES);
  // ASSERT(r==0, "could not convert np_id to str code: %"PRId32, r);
  str[64] = '\0';
  return str;
}

void np_str_id(np_id(*id), const char str[65]) {
  // TODO: this is dangerous, encoding could be different between systems,
  // encoding has to be send over the wire to be sure ...
  // for now: all tests on the same system
  // assert (64 == strnlen((char*) str,65));
  int r = sodium_hex2bin(*id,
                         NP_FINGERPRINT_BYTES,
                         str,
                         NP_FINGERPRINT_BYTES * 2,
                         NULL,
                         NULL,
                         NULL);
  ASSERT(r == 0, "could not convert str to np_id  code: %" PRId32, r);
}

void np_destroy(np_context *ac, bool gracefully) {

  np_ctx_cast(ac);

  // Do not allow to call np_destroy more than one time one one context
  bool cancel = false;
  TSP_SCOPE(context->_shutdown_started) {
    cancel                     = context->_shutdown_started;
    context->_shutdown_started = true;
  }
  if (cancel) return;

  if (gracefully) {
    np_shutdown_add_callback(context, _np_shutdown_notify_others);
  }
  _np_shutdown_run_callbacks(context);

  np_util_event_t shutdown_event = {.type      = (evt_shutdown | evt_internal),
                                    .user_data = NULL};
  if (context->my_node_key != NULL) {
    shutdown_event.target_dhkey = context->my_node_key->dhkey;
    _np_event_runtime_start_with_event(context,
                                       context->my_node_key->dhkey,
                                       shutdown_event);
  }
  if (context->my_identity != NULL &&
      context->my_identity != context->my_node_key) {
    shutdown_event.target_dhkey = context->my_identity->dhkey;
    _np_event_runtime_start_with_event(context,
                                       context->my_identity->dhkey,
                                       shutdown_event);
  }
  _np_log_fflush(context, true);

  // verify all threads are stopped
  TSP_SET(context->status, np_shutdown);
  np_threads_shutdown_workers(context);

  // destroy modules
  // _np_sysinfo_destroy_cache(context);
  _np_shutdown_destroy(context);

  _np_jobqueue_destroy(context);
  _np_time_destroy(context);

  // sodium_destroy() /* not available */
  _np_route_destroy(context);
  // _np_keycache_destroy(context);
  _np_dhkey_destroy(context);
  _np_msgproperty_destroy(context);
  _np_statistics_destroy(context);
  _np_network_module_destroy(context);
  _np_threads_destroy(context);
  _np_log_destroy(context);
  _np_event_destroy(context);
  _np_memory_destroy(context);

  np_tree_free(context->msg_part_cache);
  TSP_DESTROY(context->status);
  free(context);
#ifdef CONSOLE_BACKUP_LOG
  fflush(NULL);
#endif
}

bool np_id_equals(np_id first, np_id second) {
  return memcmp(first, second, sizeof(np_id)) == 0;
}
