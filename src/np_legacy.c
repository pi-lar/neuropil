//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_legacy.h"

#include <assert.h>
#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "dtime.h"
#include "event/ev.h"
#include "sodium.h"

#include "neuropil.h"
#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_event.h"
#include "util/np_list.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_constants.h"
#include "np_dendrit.h"
#include "np_dhkey.h"
#include "np_eventqueue.h"
#include "np_evloop.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_keycache.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_node.h"
#include "np_route.h"
#include "np_settings.h"
#include "np_shutdown.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_token_factory.h"
#include "np_types.h"
#include "np_util.h"

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_usercallback_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_usercallback_ptr);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_evt_callback_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_evt_callback_t);

/**
 * The default authorize function, allows no authorizations and generates
 * warnings
 * @param token
 * @return
 */
bool _np_default_authorizefunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);
  log_msg(
      LOG_WARNING,
      NULL,
      "using default handler (authorize none) to reject authorization for: %s",
      token->subject);
  // log_msg(LOG_WARNING, NULL, "do you really want the default authorize
  // handler (allow all) ???");

  return (false);
}
/**
 * The default realm client authorize function. Forwards the authorization
 * request to the realm server
 * @param token
 * @return
 */
bool _np_aaa_authorizefunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);

  log_debug(LOG_DEBUG,
            token->uuid,
            "realm authorization request for subject: %s",
            token->subject);

  return (false);
}

/**
 * The default authenticate function, allows all authorizations and generates
 * warnings
 * @param token
 * @return
 */
bool _np_default_authenticatefunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);
  log_msg(LOG_WARNING,
          NULL,
          "using default handler (authn all) to authenticate %s",
          token->subject);
  // log_msg(LOG_WARNING, NULL, "do you really want the default authenticate
  // handler (trust all) ???");

  return (true);
}

/**
 * The default realm client authenticate function. Forwards the authenticate
 * request to the realm server
 * @param token
 * @return
 */
bool _np_aaa_authenticatefunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);

  //	log_debug(LOG_DEBUG, NULL, "realm             : %s", token->realm);
  //	log_debug(LOG_DEBUG, NULL, "issuer            : %s", token->issuer);
  //	log_debug(LOG_DEBUG, NULL, "subject           : %s", token->subject);
  //	log_debug(LOG_DEBUG, NULL, "audience          : %s", token->audience);
  //	log_debug(LOG_DEBUG, NULL, "uuid              : %s", token->uuid);
  log_debug(LOG_DEBUG,
            token->uuid,
            "realm authentication request for subject: %s",
            token->subject);

  return (false);
}

/**
 * The default accounting function, allows no authorizations and generates
 * warnings
 * @param token
 * @return
 */
bool _np_default_accountingfunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);
  log_msg(LOG_WARNING,
          NULL,
          "using default handler to deny accounting for: %s",
          token->subject);
  // log_msg(LOG_WARNING, NULL, "do you really want the default accounting
  // handler (account nothing) ???");

  return (false);
}

/**
 * The default realm client accounting function. Forwards the accounting request
 * to the realm server
 * @param token
 * @return
 */
bool _np_aaa_accountingfunc(np_context *ac, struct np_token *token) {
  np_ctx_cast(ac);

  log_debug(LOG_DEBUG,
            token->uuid,
            "realm accounting request for subject: %s",
            token->subject);
  return (false);
}

/**
 * Sets the realm name of the node.
 * RECONFIGURES THE NODE HASH! The old node hash will be forgotten.
 * @param realm_name
 */
void np_set_realm_name(np_context *ac, const char *realm_name) {
  np_ctx_cast(ac);

  memset(context->realm_id, 0, 256);
  strncat(context->realm_id, realm_name, 256);

  /*
  // create a new token
  np_dhkey_t my_dhkey = np_aaatoken_get_fingerprint(auth_token, false); //
  np_dhkey_create_from_hostport( my_node->dns_name, my_node->port); np_key_t*
  new_node_key = _np_keycache_find_or_create(context, my_dhkey);

  new_node_key->network = context->my_node_key->network;
  np_ref_obj(np_network_t, new_node_key->network, ref_key_network);

  context->my_node_key->network = NULL;

  _np_network_set_key(new_node_key->network, new_node_key);

  new_node_key->node = context->my_node_key->node;
  np_ref_obj(np_node_t, new_node_key->node, ref_key_node);

  context->my_node_key->node = NULL;

  np_ref_switch(np_aaatoken_t, new_node_key->aaa_token, ref_key_aaa_token,
  auth_token);

  // re-initialize routing table
  _np_route_set_key (new_node_key);

  // set and ref additional identity
  // TODO: use _np_set_identity
  if (_np_key_cmp(context->my_identity, context->my_node_key) == 0)
  {
      np_ref_switch(np_key_t, context->my_identity, ref_state_identitykey,
  new_node_key);
  }

  // context->my_identity->aaa_token->type = np_aaatoken_type_identity;
  context->my_node_key = new_node_key;

  log_msg(LOG_INFO, NULL, "neuropil realm successfully set, node hash now: %s",
  _np_key_as_str(context->my_node_key));

  np_unref_obj(np_key_t, new_node_key,"_np_keycache_find_or_create");
  */
}
/**
 * Enables this node as realm client.
 * The node will forward all aaa requests to the realm server
 */
void np_enable_realm_client(np_context *ac) {
  np_ctx_cast(ac);

  np_set_authorize_cb(ac, _np_aaa_authorizefunc);
  np_set_authenticate_cb(ac, _np_aaa_authenticatefunc);
  np_set_accounting_cb(ac, _np_aaa_accountingfunc);

  context->enable_realm_server = false;
  context->enable_realm_client = true;
}

/**
 * Enables this node as realm server.
 */
void np_enable_realm_server(np_context *ac) {
  np_ctx_cast(ac);
  if (NULL == context->realm_id) {
    return;
  }

  np_msgproperty_conf_t *prop     = NULL;
  np_dhkey_t             _subject = {0};
  // turn msg handlers for aaa to inbound msg as well
  np_generate_subject(&_subject, _NP_MSG_AUTHENTICATION_REQUEST, 24);
  np_generate_subject(&_subject,
                      context->realm_id,
                      strnlen(context->realm_id, 256));
  prop = _np_msgproperty_conf_get(context, OUTBOUND, _subject);
  if (_np_dhkey_equal(&dhkey_zero, &prop->audience_id)) {
    // _np_dhkey_assign(&prop->audience_id, &context->realm_id);
    prop->audience_type = NP_MX_AUD_PROTECTED;
  }

  np_generate_subject(&_subject, _NP_MSG_AUTHORIZATION_REQUEST, 21);
  np_generate_subject(&_subject,
                      context->realm_id,
                      strnlen(context->realm_id, 256));
  prop = _np_msgproperty_conf_get(context, OUTBOUND, _subject);
  if (_np_dhkey_equal(&dhkey_zero, &prop->audience_id)) {
    // _np_dhkey_assign(&prop->audience_id, &context->realm_id);
    prop->audience_type = NP_MX_AUD_PROTECTED;
  }

  np_generate_subject(&_subject, _NP_MSG_ACCOUNTING_REQUEST, 19);
  np_generate_subject(&_subject,
                      context->realm_id,
                      strnlen(context->realm_id, 256));
  prop = _np_msgproperty_conf_get(context, OUTBOUND, _subject);
  if (_np_dhkey_equal(&dhkey_zero, &prop->audience_id)) {
    // _np_dhkey_assign(&prop->audience_id, &context->realm_id);
    prop->audience_type = NP_MX_AUD_PROTECTED;
  }

  context->enable_realm_server = true;
  context->enable_realm_client = false;
}

/**
 * Waits till this node is connected to a network.
 * WARNING! Blocks the current thread and does not have a timeout!
 */
void np_waitforjoin(np_context *ac) {
  np_ctx_cast(ac);
  while (false == _np_route_my_key_has_connection(context)) {
    np_time_sleep(0.0);
  }
}

/**
 * Sets a callback for a given msg subject.
 * Each msg for the given subject may invoke this handler.
 * @param msg_handler
 * @param subject
 */
void np_add_receive_listener(np_context               *ac,
                             np_usercallbackfunction_t msg_handler_fn,
                             void                     *msg_handler_localdata,
                             np_dhkey_t                subject) {
  np_ctx_cast(ac);
  // check whether an handler already exists
  np_msgproperty_conf_t *mx_conf =
      _np_msgproperty_get_or_create(context, INBOUND, subject);
  np_msgproperty_register(mx_conf);

  if (mx_conf != NULL && mx_conf->audience_type != NP_MX_AUD_VIRTUAL) {
    np_msgproperty_run_t *mx_run =
        _np_msgproperty_run_get(context, INBOUND, subject);
    if (mx_run != NULL) {
      log_debug(LOG_MISC,
                NULL,
                "adding recv listener on subject %08" PRIx32 ":%08" PRIx32
                " / property %p",
                subject.t[0],
                subject.t[1],
                mx_run);
      np_usercallback_t *msg_handler = malloc(sizeof(np_usercallback_t));
      msg_handler->data              = msg_handler_localdata;
      msg_handler->fn                = msg_handler_fn;

      // hand it over to the userspace
      sll_append(np_usercallback_ptr, mx_run->user_callbacks, msg_handler);
    }
  }
}

/**
 * Sets a callback for a given msg subject.
 * Each msg for the given subject may invoke this handler.
 * @param msg_handler
 * @param subject
 */
void np_add_send_listener(np_context               *ac,
                          np_usercallbackfunction_t msg_handler_fn,
                          void                     *msg_handler_localdata,
                          np_dhkey_t                subject) {
  np_ctx_cast(ac);
  // check whether an handler already exists
  np_msgproperty_run_t *msg_prop =
      _np_msgproperty_run_get(context, OUTBOUND, subject);
  if (msg_prop != NULL /*&& msg_prop->is_internal == false*/) {
    log_debug(LOG_MISC,
              NULL,
              "adding send listener on subject %08" PRIx32 ":%08" PRIx32
              " / property %p",
              subject.t[0],
              subject.t[1],
              msg_prop);
    np_usercallback_t *msg_handler = malloc(sizeof(np_usercallback_t));
    msg_handler->data              = msg_handler_localdata;
    msg_handler->fn                = msg_handler_fn;
    sll_append(np_usercallback_ptr, msg_prop->user_callbacks, msg_handler);
  }
}

/**
 * Sets the identity of the node.
 * @param identity
 */
void _np_set_identity(np_context *ac, np_aaatoken_t *identity) {
  np_ctx_cast(ac);

  np_dhkey_t search_key      = np_aaatoken_get_fingerprint(identity, false);
  np_key_t  *my_identity_key = _np_keycache_find_or_create(context, search_key);

  np_util_event_t ev = {.type         = (evt_internal | evt_token),
                        .user_data    = identity,
                        .target_dhkey = search_key};
  _np_event_runtime_start_with_event(context, search_key, ev);
  _np_statistics_update(context);

  np_unref_obj(np_key_t, my_identity_key, "_np_keycache_find_or_create");
}

void _np_add_interface(np_context *ac, np_aaatoken_t *hs_token) {

  np_ctx_cast(ac);

  assert(context->my_node_key != NULL);

  np_dhkey_t search_key      = np_aaatoken_get_fingerprint(hs_token, false);
  np_key_t *my_interface_key = _np_keycache_find_or_create(context, search_key);

  np_util_event_t ev = {.type         = (evt_internal | evt_token),
                        .user_data    = hs_token,
                        .target_dhkey = search_key};
  _np_event_runtime_start_with_event(context, search_key, ev);
  _np_statistics_update(context);

  np_unref_obj(np_key_t, my_interface_key, "_np_keycache_find_or_create");
}

void np_send_response_msg(np_context   *ac,
                          np_message_t *original,
                          np_tree_t    *body) {
  // np_ctx_cast(ac);
  // np_dhkey_t* sender = _np_message_get_sessionid(original);
  /*
  np_message_t* msg = _np_prepare_msg(context,
  original->msg_property->rep_subject, body, sender);

  np_tree_replace_str( msg->instructions, _NP_MSG_INST_RESPONSE_UUID,
  np_treeval_new_s(original->uuid));

  _np_send_msg(msg->msg_property->msg_subject, msg, msg->msg_property, sender);

  np_unref_obj(np_message_t, msg, ref_obj_creation);
  */
}

char *np_get_connection_string(np_context *ac) {
  np_ctx_cast(ac);

  np_key_t *main_itf_key =
      _np_keycache_find_interface(context, context->main_ip, NULL);

  if (main_itf_key) {
    return np_get_connection_string_from(main_itf_key, true);
  }
  return NULL;
}

char *np_get_connection_string_from(np_key_t *node_key, bool includeHash) {
  np_ctx_memory(node_key);

  // can only extract connection string from node, wildcard or interface.
  if (!(FLAG_CMP(node_key->type, np_key_type_node) ||
        FLAG_CMP(node_key->type, np_key_type_wildcard) ||
        FLAG_CMP(node_key->type, np_key_type_interface)))
    return NULL;

  np_node_t *node_data = _np_key_get_node(node_key);
  if (node_data) {

    log_msg(LOG_DEBUG, NULL, "node_data->host_key: %s", node_data->host_key);

    return (np_build_connection_string(
        includeHash == true ? node_data->host_key : NULL,
        _np_network_get_protocol_string(context, node_data->protocol),
        node_data->ip_string,
        node_data->port,
        includeHash));
  }
  return NULL;
}

enum np_return
_np_listen_safe(np_context *ac, char *protocol, char *host, char *port) {
  enum np_return ret = np_ok;
  np_ctx_cast(ac);

  char        safe_hostname[256];
  char        local_ip[255];
  socket_type np_proto = UDP | IPv6;

  // verify requested protocol
  if (NULL != protocol) {
    np_proto = _np_network_parse_protocol_string(protocol);
    if (np_proto == UNKNOWN_PROTO) {
      log_msg(LOG_WARNING,
              NULL,
              "neuropil_init: could not parse protocol string %s",
              protocol);
      return (np_invalid_argument);
    }
  }

  // get local hostname and local ip
  if (host == NULL) {
    gethostname(safe_hostname, 255);
  } else {
    strncpy(safe_hostname, host, 255);
  }
  if (np_ok !=
      _np_network_get_local_ip(NULL, safe_hostname, np_proto, local_ip)) {
    log_msg(LOG_WARNING,
            NULL,
            "neuropil_init: could not get local ip for hostname %s",
            host);
    return (np_invalid_argument);
  }

  // check if we are already listening on this ip
  if (context->main_ip != NULL &&
      strncmp(context->main_ip, local_ip, 50) == 0) {
    log_msg(LOG_INFO,
            NULL,
            "neuropil_init: already listening on hostname %s (%s)",
            safe_hostname,
            local_ip);
    return (np_ok);
  }

  log_debug(LOG_NETWORK,
            NULL,
            "now initializing networking for %x:%s:%s",
            np_proto,
            local_ip,
            port);

  log_debug(LOG_NETWORK, NULL, "building network base structure");

  // create listening interface
  np_aaatoken_t *hs_token =
      _np_token_factory_new_handshake_token(context, np_proto, local_ip, port);
  _np_add_interface(context, hs_token);

  if (context->main_ip == NULL) {
    context->main_ip = strndup(local_ip, 50);
  }
  np_unref_obj(np_aaatoken_t,
               hs_token,
               "_np_token_factory_new_handshake_token");

  if (_np_jobqueue_init(context) == false) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: _np_jobqueue_init failed: %s",
            strerror(errno));
    ret = np_startup;

  } else if (!_np_network_module_init(context)) {
    log_msg(LOG_ERROR,
            NULL,
            "neuropil_init: could not enable general networking");
    ret = np_startup;

  } else if (!_np_statistics_enable(context)) {
    log_msg(LOG_ERROR, NULL, "neuropil_init: could not enable statistics");
    ret = np_startup;
  }

  if (ret != np_ok) {
    TSP_SET(context->status, np_error);
  }

  return ret;
}

char *np_build_connection_string(
    char *hash, char *protocol, char *hostname, char *port, bool includeHash) {
  char *connection_str;
  if (true == includeHash) {
    asprintf(&connection_str, "%s:%s:%s:%s", hash, protocol, hostname, port);
  } else {
    asprintf(&connection_str, "%s:%s:%s", protocol, hostname, port);
  }

  return connection_str;
}

/**
 * Sends a JOIN request to the given node string.
 * Please see @np_get_connection_string() for the node_string definition
 * @param node_string
    @deprecated
 */
void np_send_join(np_context *ac, const char *node_string) {
  np_ctx_cast(ac);

  np_node_t *new_node = _np_node_decode_from_str(context, node_string);
  if (new_node == NULL) return;

  // node_string could not contain a valid ip address, so we need to resolve it
  char ip_buffer[64] = {0};
  _np_network_get_remote_ip(ac,
                            new_node->ip_string,
                            new_node->protocol,
                            ip_buffer);
  free(new_node->ip_string);
  new_node->ip_string = strndup(ip_buffer, 64);

  memset(ip_buffer, 0, 64);
  snprintf(ip_buffer, 64, "%s:%s", new_node->ip_string, new_node->port);
  // now lookup existing connection based on the resolved ip address
  np_key_t *existing_connection = _np_keycache_find_by_details(context,
                                                               ip_buffer,
                                                               true,
                                                               0,
                                                               false,
                                                               true,
                                                               true,
                                                               false);

  if (existing_connection != NULL) {
    np_unref_obj(np_key_t, existing_connection, "_np_keycache_find_by_details");
    return;
  }

  // check whether we have already an interface setup for the remote address
  char local_ip[64] = {0};
  if (np_ok != _np_network_get_outgoing_ip(NULL,
                                           new_node->ip_string,
                                           new_node->protocol,
                                           local_ip)) {
    np_unref_obj(np_key_t, existing_connection, "_np_keycache_find_by_details");
    return; // np_invalid_operation;
  }

  np_key_t *interface_key =
      _np_keycache_find_interface(context, local_ip, NULL);
  // if no interface exists, try to setup a new passive interface because the
  // user explicitly requested this np_join() command
  if (interface_key == NULL &&
      np_ok != _np_listen_safe(context,
                               _np_network_get_protocol_string(
                                   context,
                                   new_node->protocol | PASSIVE),
                               local_ip,
                               "31415")) {
    np_unref_obj(np_key_t, existing_connection, "_np_keycache_find_by_details");
    return; // np_invalid_operation;
  }

  np_unref_obj(np_key_t, existing_connection, "_np_keycache_find_by_details");
  np_unref_obj(np_key_t, interface_key, "_np_keycache_find_interface");

  np_dhkey_t search_key = {0};
  if (new_node->host_key[0] == '*') {
    search_key = np_dhkey_create_from_hostport("*", node_string + 2);
  } else if (strnlen(new_node->host_key, 64) == 64) {
    search_key = np_dhkey_create_from_hash(node_string);
  } else {
    np_unref_obj(np_node_t, new_node, "_np_node_decode_from_str");
    return;
  }

  char search_key_str[65] = {0};
  np_id_str(search_key_str, &search_key);

  if (FLAG_CMP(new_node->protocol, PASSIVE)) {
    log_msg(LOG_WARNING,
            NULL,
            "user requests to join passive node at %u:%s:%s!",
            new_node->protocol,
            new_node->ip_string,
            new_node->port);
    np_unref_obj(np_node_t, new_node, "_np_node_decode_from_str");
    return;
  } else {
    log_msg(LOG_INFO,
            NULL,
            "user request to join %u:%s:%s",
            new_node->protocol,
            new_node->ip_string,
            new_node->port);
  }

  np_key_t *node_key = _np_keycache_find_or_create(context, search_key);

  np_util_event_t new_node_evt = {.type         = (evt_internal),
                                  .user_data    = new_node,
                                  .target_dhkey = search_key};
  _np_event_runtime_start_with_event(context, search_key, new_node_evt);

  np_unref_obj(np_node_t, new_node, "_np_node_decode_from_str");
  np_unref_obj(np_key_t, node_key, "_np_keycache_find_or_create");
}
