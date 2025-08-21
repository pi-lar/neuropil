//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "np_token_factory.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include "dtime.h"
#include "event/ev.h"
#include "sodium.h"

#include "neuropil_attributes.h"
#include "neuropil_data.h"
#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "util/np_pcg_rng.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_attributes.h"
#include "np_constants.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_settings.h"
#include "np_statistics.h"
#include "np_threads.h"
#include "np_util.h"

// create a new aaa token
np_aaatoken_t *
__np_token_factory_new(np_state_t *context,
                       char        issuer[64],
                       double      expires_at,
                       unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]) {
  np_aaatoken_t *ret = NULL;
  np_new_obj(np_aaatoken_t, ret, FUNC);

  char uuid_hex[2 * NP_UUID_BYTES + 1];
  sodium_bin2hex(uuid_hex, 2 * NP_UUID_BYTES + 1, ret->uuid, NP_UUID_BYTES);
  snprintf(ret->subject, 254, _NP_URN_IDENTITY_PREFIX ":%s", uuid_hex);

  // create token
  if (NULL != context->realm_id) {
    strncpy(ret->realm, context->realm_id, 255);
  }
  strncpy(ret->issuer, issuer, 65);
  // strncpy(ret->audience, (char*)
  // _np_key_as_str(context->my_identity->aaa_token->realm), 255);

  ret->not_before = np_time_now();
  ret->expires_at = expires_at;

  if (secret_key != NULL) {
    np_cryptofactory_by_secret(context, &ret->crypto, *secret_key);
  } else {
    np_cryptofactory_new(context, &ret->crypto);
  }

  ret->private_key_is_set = true;
  ret->scope              = np_aaatoken_scope_private;
  ret->issuer_token       = ret;

  return ret;
}

np_aaatoken_t *__np_token_factory_derive(np_aaatoken_t         *source,
                                         enum np_aaatoken_scope scope) {
  np_ctx_memory(source);
  np_aaatoken_t *ret = NULL;

  log_debug(LOG_AAATOKEN, source->uuid, "deriving new token");

  /// contract begin
  ASSERT(source != NULL, "source token cannot be NULL");

  switch (scope) {
  case np_aaatoken_scope_private:
    ASSERT(source->scope == np_aaatoken_scope_private,
           "Can only derive a private token from another private token. "
           "current token scope: %" PRIu8,
           source->scope);
    ASSERT(FLAG_CMP(source->type, np_aaatoken_type_identity) ||
               FLAG_CMP(source->type, np_aaatoken_type_node),
           "Can only derive a private token from a node or identity token. "
           "current token type: %" PRIu8,
           source->type);
    break;
  case np_aaatoken_scope_private_available:
    ASSERT(source->scope <= np_aaatoken_scope_private,
           "Can only derive a protected token from a private token. current "
           "token scope: %" PRIu8,
           source->scope);
    break;
  case np_aaatoken_scope_public:
    ASSERT(source->scope <= np_aaatoken_scope_private_available,
           "Can only derive a public token from a protected or private token. "
           "current token scope: %" PRIu8,
           source->scope);
    break;
  default:
    log_msg(LOG_ERROR,
            source->uuid,
            "scope to derive token to is unknown. scope: %" PRIu8,
            scope);
    ABORT("scope to derive token to is unknown. scope: %" PRIu8, scope);
    break;
  }
  /// end of contract

  // create token
  np_new_obj(np_aaatoken_t, ret, FUNC);

  strncpy(ret->realm, source->realm, 255);
  strncpy(ret->issuer, source->issuer, 65);
  strncpy(ret->subject, source->subject, 255);
  strncpy(ret->audience, source->audience, 255);

  ret->not_before = source->not_before;
  ret->expires_at = source->expires_at;
  ret->issued_at  = source->issued_at;
  ret->version    = source->version;
  ret->state      = source->state;

  if (scope != np_aaatoken_scope_private) {
    assert(NULL !=
           np_cryptofactory_by_public(context,
                                      &ret->crypto,
                                      source->crypto.ed25519_public_key));
  } else {
    assert(NULL !=
           np_cryptofactory_by_secret(context,
                                      &ret->crypto,
                                      source->crypto.ed25519_secret_key));
  }

  ret->scope = scope;
  ret->type  = source->type;
  if (source->private_key_is_set &&
      scope == np_aaatoken_scope_private_available) {
    ret->issuer_token = source;
  }

  memcpy(ret->attributes, source->attributes, sizeof(source->attributes));

  return (ret);
}

np_ident_public_token_t *
np_token_factory_get_public_ident_token(np_aaatoken_t *source) {
  np_ctx_memory(source);
  np_ident_public_token_t *ret = NULL;

  ASSERT(FLAG_CMP(source->type, np_aaatoken_type_identity),
         "Can only directly derive ident token from ident token. current token "
         "type: %" PRIu8,
         source->type);

  ret = __np_token_factory_derive(source, np_aaatoken_scope_private_available);
  memcpy(ret->uuid, source->uuid, NP_UUID_BYTES);

  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context, NP_ATTR_IDENTITY));
  np_merge_data(ret->attributes,
                (np_datablock_t *)_np_get_attributes_cache(
                    context,
                    NP_ATTR_IDENTITY_AND_USER_MSG));
  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context,
                                                 NP_ATTR_INTENT_AND_IDENTITY));
  _np_aaatoken_set_signature(ret, NULL);
  _np_aaatoken_update_attributes_signature(ret);

  log_debug(LOG_AAATOKEN, ret->uuid, "generating public ident token");

  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", FUNC);
  return ret;
}

np_node_public_token_t *
np_token_factory_get_public_node_token(np_aaatoken_t *source) {
  np_ctx_memory(source);
  np_node_public_token_t *ret = NULL;

  ASSERT(FLAG_CMP(source->type, np_aaatoken_type_node),
         "Can only directly derive node token from node token. current token "
         "type: %" PRIu8,
         source->type);

  ret = __np_token_factory_derive(source, np_aaatoken_scope_public);
  _np_aaatoken_set_signature(ret, NULL);

  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", FUNC);
  _np_aaatoken_trace_info("build_node", ret);
  return ret;
}

np_message_intent_public_token_t *
_np_token_factory_new_message_intent_token(np_msgproperty_conf_t *msg_request) {

  np_ctx_memory(msg_request);
  np_message_intent_public_token_t *ret = NULL;

  ASSERT(msg_request != NULL, "source messageproperty cannot be NULL");

  np_aaatoken_t *identity_token = _np_key_get_token(context->my_identity);

  ret = __np_token_factory_derive(identity_token,
                                  np_aaatoken_scope_private_available);
  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", FUNC);
  ret->type = np_aaatoken_type_message_intent;
  np_init_datablock(ret->attributes, sizeof(ret->attributes));

  // fill in token metadata for message identification
  char msg_id_subject[255];
  snprintf(msg_id_subject,
           255,
           _NP_URN_MSG_PREFIX "%s",
           msg_request->msg_subject);
  strncpy(ret->subject, msg_id_subject, 255);

  strncpy(ret->issuer, (char *)_np_key_as_str(context->my_identity), 65);
  if (msg_request->audience_type == NP_MX_AUD_PROTECTED) {
    char hex[65] = {0};
    sodium_bin2hex(hex, 65, &msg_request->audience_id, NP_FINGERPRINT_BYTES);
    memcpy(ret->audience, hex, 64);
  }
  // TODO: how to allow the possible transmit jitter ?
  ret->not_before = np_time_now();
  ret->expires_at = ret->not_before + msg_request->token_max_ttl;
  if (identity_token->expires_at < ret->expires_at) {
    ret->expires_at = identity_token->expires_at;
  }
  log_debug(LOG_MESSAGE | LOG_AAATOKEN | LOG_DEBUG,
            NULL,
            "setting msg token EXPIRY to: %f (now: %f diff: %f)",
            ret->expires_at,
            np_time_now(),
            ret->expires_at - np_time_now());
  // fingerprinting and signing the token
  _np_aaatoken_set_signature(ret, NULL);
  _np_aaatoken_set_signature(ret, identity_token);

  // add e2e encryption details for sender
  // memcpy((char*)ret->crypto.ed25519_public_key,
  //        (char*)identity_token->crypto.ed25519_public_key,
  //        crypto_sign_PUBLICKEYBYTES);
  enum np_data_return tmp;
  tmp = np_set_data(ret->attributes,
                    (struct np_data_conf){.key  = "mep_type",
                                          .type = NP_DATA_TYPE_UNSIGNED_INT},
                    (np_data_value){.unsigned_integer = msg_request->mep_type});
  ASSERT(np_ok == tmp, "Could not set \"mep_type\" data %" PRIu32, tmp);
  tmp = np_set_data(ret->attributes,
                    (struct np_data_conf){.key  = "ack_mode",
                                          .type = NP_DATA_TYPE_UNSIGNED_INT},
                    (np_data_value){.unsigned_integer = msg_request->ack_mode});
  ASSERT(np_ok == tmp, "Could not set \"ack_mode\" data %" PRIu32, tmp);
  tmp = np_set_data(
      ret->attributes,
      (struct np_data_conf){.key  = "max_threshold",
                            .type = NP_DATA_TYPE_UNSIGNED_INT},
      (np_data_value){.unsigned_integer = msg_request->max_threshold});
  ASSERT(np_ok == tmp, "Could not set \"max_threshold\" data %" PRIu32, tmp);
  tmp = np_set_data(ret->attributes,
                    (struct np_data_conf){.key  = "msg_threshold",
                                          .type = NP_DATA_TYPE_UNSIGNED_INT},
                    (np_data_value){.unsigned_integer = 0});
  ASSERT(np_ok == tmp, "Could not set \"msg_threshold\" data %" PRIu32, tmp);

  ret->state = AAA_AUTHORIZED | AAA_AUTHENTICATED | AAA_VALID;

  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context, NP_ATTR_INTENT));
  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context,
                                                 NP_ATTR_INTENT_AND_USER_MSG));
  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context,
                                                 NP_ATTR_INTENT_AND_IDENTITY));

  // TODO: insert value based on msg properties / respect (sticky) reply
  np_aaatoken_set_partner_fp(ret, context->my_node_key->dhkey);
  // np_aaatoken_set_partner_fp calls
  // _np_aaatoken_update_attributes_signature(ret);

  _np_aaatoken_trace_info("build_intent", ret);

  return (ret);
}

np_handshake_token_t *
_np_token_factory_new_handshake_token(np_state_t *context,
                                      socket_type protocol,
                                      const char *local_ip,
                                      const char *port) {
  np_handshake_token_t *ret = NULL;

  _LOCK_ACCESS(&context->my_node_key->key_lock) {
    np_aaatoken_t *my_node_token = _np_key_get_token(context->my_node_key);
    log_debug(LOG_MISC,
              NULL,
              "context->my_node_key =  %p %p %d",
              context->my_node_key,
              my_node_token,
              my_node_token->type);

    ASSERT(FLAG_CMP(my_node_token->type, np_aaatoken_type_node),
           "Can only derive handshake token from node token. current token "
           "type: %" PRIu8,
           my_node_token->type);
    ASSERT(my_node_token->scope == np_aaatoken_scope_private,
           "Can only derive handshake token from private token. current token "
           "scope: %" PRIu8,
           my_node_token->scope);

    ret = __np_token_factory_derive(my_node_token,
                                    np_aaatoken_scope_private_available);

    np_init_datablock(ret->attributes, sizeof(ret->attributes));
    ret->type = np_aaatoken_type_handshake;

    np_dhkey_t node_dhkey = np_aaatoken_get_fingerprint(my_node_token, false);
    _np_dhkey_str(&node_dhkey, ret->issuer);
  }

  snprintf(ret->subject,
           254,
           _NP_URN_NODE_PREFIX ":%s:%s:%s",
           _np_network_get_protocol_string(context, protocol),
           local_ip,
           port);

  struct np_data_conf cfg;
  strncpy(cfg.key, NP_HS_PRIO, 255);
  cfg.type = NP_DATA_TYPE_UNSIGNED_INT;
  np_set_data(ret->attributes,
              cfg,
              (np_data_value){.unsigned_integer = np_global_rng_next()});

  _np_aaatoken_set_signature(ret, NULL);
  _np_aaatoken_update_attributes_signature(ret);

#ifdef DEBUG
  char       my_token_fp_s[65] = {0};
  np_dhkey_t my_token_fp       = np_aaatoken_get_fingerprint(ret, false);
  _np_dhkey_str(&my_token_fp, my_token_fp_s);
  log_debug(LOG_AAATOKEN | LOG_HANDSHAKE,
            ret->uuid,
            "new handshake token fp: %s from node: %s",
            my_token_fp_s,
            _np_key_as_str(context->my_node_key));
  // ASSERT(strcmp(my_token_fp_s, _np_key_as_str(my_node_key)) == 0, "Node key
  // and handshake partner key has to be the same");
#endif // DEBUG

#ifdef DEBUG
  bool valid = _np_aaatoken_is_valid(context, ret, np_aaatoken_type_handshake);
  char signature_hex[crypto_sign_BYTES * 2 + 1] = {0};
  sodium_bin2hex(signature_hex,
                 crypto_sign_BYTES * 2 + 1,
                 ret->signature,
                 crypto_sign_BYTES);

  char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = {0};
  sodium_bin2hex(pk_hex,
                 crypto_sign_PUBLICKEYBYTES * 2 + 1,
                 ret->crypto.ed25519_public_key,
                 crypto_sign_PUBLICKEYBYTES);

  log_debug(LOG_AAATOKEN,
            ret->uuid,
            "token signature is%s valid: (pk: 0x%s) sig: 0x%s = %p",
            (valid == true) ? "" : " not",
            pk_hex,
            signature_hex,
            ret);
#endif

  // np_unref_obj(np_aaatoken_t, my_node_token, FUNC);
  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_derive", FUNC);

  _np_aaatoken_trace_info("build_handshake", ret);

  // NP_PERFORMANCE_POINT_END(tokenfactory_new_handshake);

  return ret;
}

np_node_private_token_t *_np_token_factory_new_node_token(np_state_t *context) {

  // TODO: replace with pcg implementation
  int rand_interval =
      np_global_rng_next_bounded(NODE_MAX_TTL_SEC) + NODE_MIN_TTL_SEC;

  double expires_at = np_time_now() + rand_interval;

  char issuer[64] = {0};

  np_node_private_token_t *ret =
      __np_token_factory_new(context, issuer, expires_at, NULL);
  ret->type = np_aaatoken_type_node;

  char uuid_hex[2 * NP_UUID_BYTES + 1];
  sodium_bin2hex(uuid_hex, 2 * NP_UUID_BYTES + 1, ret->uuid, NP_UUID_BYTES);
  snprintf(ret->subject, 254, _NP_URN_NODE_PREFIX ":%s", uuid_hex);

  _np_aaatoken_set_signature(ret, NULL);
  _np_aaatoken_update_attributes_signature(ret);
  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_new", FUNC);
  _np_aaatoken_trace_info("build_node", ret);

  return (ret);
}

np_ident_private_token_t *np_token_factory_new_identity_token(
    np_state_t *context,
    double      expires_at,
    unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]) {
  char issuer[64] = {0};

  np_aaatoken_t *ret =
      __np_token_factory_new(context, issuer, expires_at, secret_key);
  ret->type = np_aaatoken_type_identity;

  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context, NP_ATTR_IDENTITY));
  np_merge_data(ret->attributes,
                (np_datablock_t *)_np_get_attributes_cache(
                    context,
                    NP_ATTR_IDENTITY_AND_USER_MSG));
  np_merge_data(
      ret->attributes,
      (np_datablock_t *)_np_get_attributes_cache(context,
                                                 NP_ATTR_INTENT_AND_IDENTITY));

  _np_aaatoken_set_signature(ret, NULL);
  _np_aaatoken_update_attributes_signature(ret);

#ifdef DEBUG
  char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES * 2 + 1];
  ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES * 2] = '\0';
  char curve25519_pk[crypto_scalarmult_curve25519_BYTES * 2 + 1];
  curve25519_pk[crypto_scalarmult_curve25519_BYTES * 2] = '\0';

  sodium_bin2hex(ed25519_pk,
                 crypto_sign_ed25519_PUBLICKEYBYTES * 2 + 1,
                 ret->crypto.ed25519_public_key,
                 crypto_sign_ed25519_PUBLICKEYBYTES);
  sodium_bin2hex(curve25519_pk,
                 crypto_scalarmult_curve25519_BYTES * 2 + 1,
                 ret->crypto.derived_kx_public_key,
                 crypto_scalarmult_curve25519_BYTES);

  log_debug(LOG_DEBUG | LOG_AAATOKEN,
            ret->uuid,
            "     identity token: my cu pk: %s ### my ed pk: %s\n",
            curve25519_pk,
            ed25519_pk);
#endif

  ref_replace_reason(np_aaatoken_t, ret, "__np_token_factory_new", FUNC);

  _np_aaatoken_trace_info("build_ident", ret);

  return ret;
}

np_aaatoken_t *np_token_factory_read_from_tree(np_state_t *context,
                                               np_tree_t  *tree) {
  np_aaatoken_t *ret = NULL;
  bool           ok  = false;
  np_new_obj(np_aaatoken_t, ret, FUNC);
  if (np_aaatoken_decode(tree, ret)) {
    log_debug(LOG_AAATOKEN,
              ret->uuid,
              "imported token (type: %" PRIu8 ") from tree %p",
              ret->type,
              tree);

    if (_np_aaatoken_is_valid(context, ret, np_aaatoken_type_undefined)) {
      ASSERT(strnlen(ret->subject, 255) > 1,
             "tokens (%s) subject string (\"%s\") has incorrect size",
             ret->uuid,
             ret->subject);
      ok = true;
    }
  }
  if (ok) {
    _np_aaatoken_trace_info("in_OK", ret);
  } else {
    _np_aaatoken_trace_info("in_NOK", ret);
    np_unref_obj(np_aaatoken_t, ret, FUNC);
    ret = NULL;
  }
  return ret;
}
