//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that
// an identity can have. It is included form np_key.c, therefore there are no
// extra #include directives.

#include "core/np_comp_intent.h"

#include <inttypes.h>

#include "neuropil.h"
#include "neuropil_data.h"

#include "util/np_event.h"
#include "util/np_statemachine.h"

#include "np_aaatoken.h"
#include "np_crypto.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"

struct __np_token_ledger {
  np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on
                                          // which this node is interested in
  np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on
                                          // which this node is interested in
};

static int8_t _np_intent_cmp(np_aaatoken_ptr first, np_aaatoken_ptr second) {
  int8_t ret_check = 0;

  if (first == second) return (0);

  if (first == NULL || second == NULL) return (-1);

  ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
  if (0 == ret_check) {
    return (ret_check);
  }
  ret_check = strncmp(first->issuer, second->issuer, 65);
  if (0 != ret_check) {
    return (ret_check);
  }

  ret_check =
      strncmp(first->subject, second->subject, strnlen(first->subject, 255));
  if (0 != ret_check) {
    return (ret_check);
  }

  ret_check = strncmp(first->realm, second->realm, strnlen(first->realm, 255));
  if (0 != ret_check) {
    return (ret_check);
  }

  return (0);
}

static int8_t _np_intent_cmp_exact(np_aaatoken_ptr first,
                                   np_aaatoken_ptr second) {
  int8_t ret_check = 0;

  if (first == second) return (0);

  if (first == NULL || second == NULL) return (-1);

  ret_check = sodium_memcmp(first->crypto.derived_kx_public_key,
                            second->crypto.derived_kx_public_key,
                            crypto_sign_PUBLICKEYBYTES);
  if (0 != ret_check) {
    return (ret_check);
  }

  ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
  if (0 != ret_check) {
    return (ret_check);
  }

  return _np_intent_cmp(first, second);
}

// update internal structure and return a interest if a matching pair has been
// found
np_aaatoken_t *_np_intent_add_sender(np_key_t      *subject_key,
                                     np_aaatoken_t *token) {
  assert(token != NULL);
  np_state_t *context = np_ctx_by_memory(token);

  NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

  np_aaatoken_t *ret = NULL;

  log_debug_msg(LOG_AAATOKEN,
                "update on global sender msg token structures ... %p (size %d)",
                property,
                pll_size(ledger->send_tokens));

  // insert new token
  // update #2 subject specific data
  struct np_data_conf conf;
  np_data_value       max_threshold = {0}, mep_type = {0}, ack_mode = {0};
  enum np_data_return get_data_ret;

  if ((get_data_ret =
           np_get_data(token->attributes, "mep_type", &conf, &mep_type)) !=
      np_ok) {
    mep_type.unsigned_integer = DEFAULT_TYPE;
    log_debug_msg(LOG_ERROR | LOG_AAATOKEN,
                  "token %s is missing key \"mep_type\" code: %" PRIu32,
                  token->uuid,
                  get_data_ret);
  }
  if ((get_data_ret =
           np_get_data(token->attributes, "ack_mode", &conf, &ack_mode)) !=
      np_ok) {
    ack_mode.unsigned_integer = ACK_NONE;
    log_debug_msg(LOG_ERROR | LOG_AAATOKEN,
                  "token %s is missing key \"ack_mode\" code: %" PRIu32,
                  token->uuid,
                  get_data_ret);
  }
  if ((get_data_ret = np_get_data(token->attributes,
                                  "max_threshold",
                                  &conf,
                                  &max_threshold)) != np_ok) {
    max_threshold.unsigned_integer = 0;
    log_debug_msg(LOG_ERROR | LOG_AAATOKEN,
                  "token %s is missing key \"max_threshold\" code: %" PRIu32,
                  token->uuid,
                  get_data_ret);
  }

  property->mep_type |= (mep_type.unsigned_integer & SENDER_MASK);
  property->ack_mode = ack_mode.unsigned_integer;

  if (max_threshold.unsigned_integer > 0) {
    log_debug_msg(LOG_AAATOKEN,
                  "adding sender token %p threshold %" PRIu32,
                  token,
                  max_threshold.unsigned_integer);
    np_msg_mep_type sender_mep_type = property->mep_type & SENDER_MASK;

    np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
    np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
    bool                           allow_dups           = true;

    if (FLAG_CMP(sender_mep_type, SINGLE_SENDER)) {
      cmp_aaatoken_replace = _np_intent_cmp;
      allow_dups           = false;
    }

    // update #1 key specific data
    np_ref_obj(np_aaatoken_t, token, ref_aaatoken_local_mx_tokens);
    ret = pll_replace(np_aaatoken_ptr,
                      ledger->send_tokens,
                      token,
                      cmp_aaatoken_replace);

    enum crud_op crud_mode = crud_update;
    if (NULL == ret) {
      crud_mode = crud_create;
      pll_insert(np_aaatoken_ptr,
                 ledger->send_tokens,
                 token,
                 allow_dups,
                 cmp_aaatoken_add);
    } else {
      token->state = ret->state;
    }

    if (IS_AUTHORIZED(token->state)) {
      _np_intent_update_sender_session(subject_key, token, crud_mode);
    }
    log_debug_msg(LOG_AAATOKEN,
                  "added new single sender token %s subject: %s",
                  token->uuid,
                  _np_key_as_str(subject_key));
  }

  return ret;
}

np_aaatoken_t *_np_intent_get_sender_token(np_key_t        *subject_key,
                                           const np_dhkey_t sender_dhkey) {
  np_ctx_memory(subject_key);
  log_debug_msg(LOG_AAATOKEN,
                "lookup in global sender msg token structures (%p)...",
                subject_key);

  // static np_dhkey_t empty_dhkey = {0};
  NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

  if (ledger == NULL) return NULL;
  // look up sources to see whether a sender already exists
  np_aaatoken_t *return_token = NULL;

#ifdef DEBUG
  char sender_dhkey_as_str[65];
  _np_dhkey_str(&sender_dhkey, sender_dhkey_as_str);
#endif

  log_debug_msg(LOG_AAATOKEN,
                ".step1._np_intent_get_sender_token %d / %s",
                pll_size(ledger->send_tokens),
                property->msg_subject);
  pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->send_tokens);
  while (NULL != iter) {
    return_token = iter->val;
    if (false == _np_aaatoken_is_valid(context,
                                       return_token,
                                       np_aaatoken_type_message_intent)) {
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring invalid sender token for issuer %s",
                    return_token->issuer);
      return_token = NULL;
      pll_next(iter);
      continue;
    }

    np_dhkey_t partner_token_dhkey = np_aaatoken_get_partner_fp(return_token);
    // only pick key from a list if the subject msg_treshold is bigger than zero
    // and we actually have the correct sender node in the list
    if (!_np_dhkey_equal(&sender_dhkey, &dhkey_zero) &&
        !_np_dhkey_equal(&partner_token_dhkey, &sender_dhkey)) {
#ifdef DEBUG
      char partner_token_dhkey_str[65];
      partner_token_dhkey_str[64] = '\0';
      _np_dhkey_str(&partner_token_dhkey, partner_token_dhkey_str);
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring sender token for issuer %s (partner node: %s) / "
                    "send_hk: %s (sender dhkey doesn't match)",
                    return_token->issuer,
                    partner_token_dhkey_str,
                    sender_dhkey_as_str);
#endif // DEBUG
      return_token = NULL;
      pll_next(iter);
      continue;
    }

    // last check: has the token received authn/authz already
    if (IS_AUTHORIZED(
            return_token
                ->state) /* && IS_AUTHENTICATED(return_token->state)*/) {
      log_debug_msg(LOG_AAATOKEN,
                    "found valid sender token (%s)",
                    return_token->issuer);
      np_ref_obj(np_aaatoken_t, return_token);
      break;
    }
    pll_next(iter);
    return_token = NULL;
  }
  log_debug_msg(LOG_AAATOKEN,
                ".step2._np_aaatoken_get_sender_token %d",
                pll_size(ledger->send_tokens));

  return (return_token);
}

// update internal structure and clean invalid tokens
np_aaatoken_t *_np_intent_add_receiver(np_key_t      *subject_key,
                                       np_aaatoken_t *token) {
  assert(token != NULL);
  np_state_t *context = np_ctx_by_memory(token);

  NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

  np_aaatoken_t *ret = NULL;

  log_debug_msg(
      LOG_AAATOKEN,
      "update on global receiving msg token (%s)  structures ... %p (size %d)",
      token->uuid,
      property,
      pll_size(ledger->recv_tokens));

  // insert new token
  log_debug_msg(LOG_AAATOKEN,
                ".step1._np_aaatoken_add_receiver %d / %s",
                pll_size(ledger->recv_tokens),
                token->subject);

  // update #2 subject specific data
  struct np_data_conf conf;
  np_data_value       max_threshold = {0}, mep_type = {0};
  enum np_data_return get_data_ret;

  if ((get_data_ret = np_get_data(token->attributes,
                                  "max_threshold",
                                  &conf,
                                  &max_threshold) != np_ok)) {
    max_threshold.unsigned_integer = 0;
    log_debug_msg(LOG_ERROR | LOG_AAATOKEN,
                  "token %s is missing key \"max_threshold\" code: %" PRIu32,
                  token->uuid,
                  get_data_ret);
  }
  if ((get_data_ret =
           np_get_data(token->attributes, "mep_type", &conf, &mep_type) !=
           np_ok)) {
    mep_type.unsigned_integer = DEFAULT_TYPE;
    log_debug_msg(LOG_ERROR | LOG_AAATOKEN,
                  "token %s is missing key \"mep_type\" code: %" PRIu32,
                  token->uuid,
                  get_data_ret);
  }

  property->mep_type |= (mep_type.unsigned_integer & RECEIVER_MASK);

  if (max_threshold.unsigned_integer > 0) {
    // only add if there are messages to receive
    log_debug_msg(LOG_AAATOKEN,
                  "adding receiver token %p threshold %" PRIu8,
                  token,
                  max_threshold);

    np_msg_mep_type receiver_mep_type = (property->mep_type & RECEIVER_MASK);

    np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
    np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
    bool                           allow_dups           = true;

    if (FLAG_CMP(receiver_mep_type, SINGLE_RECEIVER)) {
      cmp_aaatoken_replace = _np_intent_cmp;
      allow_dups           = false;
    }

    // update #1 key specific data
    np_ref_obj(np_aaatoken_t, token, ref_aaatoken_local_mx_tokens);
    ret = pll_replace(np_aaatoken_ptr,
                      ledger->recv_tokens,
                      token,
                      cmp_aaatoken_replace);

    enum crud_op crud_mode = crud_update;
    if (NULL == ret) {
      crud_mode = crud_create;
      pll_insert(np_aaatoken_ptr,
                 ledger->recv_tokens,
                 token,
                 allow_dups,
                 cmp_aaatoken_add);
    } else {
      token->state = ret->state;
    }

    if (IS_AUTHORIZED(token->state)) {
      _np_intent_update_receiver_session(subject_key, token, crud_mode);
    }
  }

  return ret;
}

np_aaatoken_t *_np_intent_get_receiver(np_key_t        *subject_key,
                                       const np_dhkey_t target) {
  np_ctx_memory(subject_key);
  log_trace_msg(LOG_TRACE | LOG_AAATOKEN,
                "start: np_aaatoken_t* _np_intent_get_receiver(...){");

  static np_dhkey_t empty_dhkey = {0};

  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

  np_aaatoken_t *return_token       = NULL;
  bool           found_return_token = false;

  pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->recv_tokens);
  while (NULL != iter && false == found_return_token) {
    log_debug_msg(LOG_AAATOKEN,
                  "checking receiver msg tokens %p/%p",
                  iter,
                  iter->val);
    return_token = iter->val;

    if (false == _np_aaatoken_is_valid(context,
                                       return_token,
                                       np_aaatoken_type_message_intent)) {
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring invalid receiver msg tokens %p",
                    return_token);
      pll_next(iter);
      return_token = NULL;
      continue;
    }

    np_dhkey_t recvtoken_issuer_key =
        np_dhkey_create_from_hash(return_token->issuer);

    if (_np_dhkey_equal(&recvtoken_issuer_key, &context->my_identity->dhkey) ||
        _np_dhkey_equal(
            &recvtoken_issuer_key,
            &context->my_node_key
                 ->dhkey)) { // only use the token if it is not from ourself (in
                             // case of IN/OUTBOUND on same subject)
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring token to send messages to myself %p",
                    return_token);
      pll_next(iter);
      return_token = NULL;
      continue;
    }

    if (!_np_dhkey_equal(&empty_dhkey, &target)) {
#ifdef DEBUG
      char targetnode_str[65];
      _np_dhkey_str(&target, targetnode_str);
      log_debug_msg(LOG_AAATOKEN,
                    "searching token for target %s ",
                    targetnode_str);
#endif
      if (!_np_dhkey_equal(&recvtoken_issuer_key, &target)) {
        log_debug_msg(LOG_AAATOKEN,
                      "ignoring %s receiver token for others nodes",
                      return_token->issuer);
        pll_next(iter);
        return_token = NULL;
        continue;
      }
    }

    // last check: has the token received authn/authz already
    if (IS_AUTHORIZED(
            return_token
                ->state) /* && IS_AUTHENTICATED(return_token->state)*/) {
      log_debug_msg(LOG_AAATOKEN,
                    "found valid receiver token (issuer: %s)",
                    return_token->issuer);
      // found_return_token = true;
      np_ref_obj(np_aaatoken_t, return_token);
      break;
    } else {
      pll_next(iter);
      return_token = NULL;
      continue;
    }
  }

  if (NULL == return_token) {
    log_debug_msg(LOG_AAATOKEN, "found no valid receiver token");
  }

  return (return_token);
}

void _np_intent_get_all_receiver(np_key_t  *subject_key,
                                 np_dhkey_t audience,
                                 np_sll_t(np_aaatoken_ptr, *tmp_token_list)) {
  np_ctx_memory(subject_key);

  np_sll_t(np_aaatoken_ptr, result_list = *tmp_token_list);
  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);
  NP_CAST_RAW(subject_key->entity_array[1], np_msgproperty_run_t, run_prop);

  pll_iterator(np_aaatoken_ptr) tmp = pll_first(ledger->recv_tokens);
  while (NULL != tmp) {
    if (false == _np_aaatoken_is_valid(context,
                                       tmp->val,
                                       np_aaatoken_type_message_intent)) {
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring receiver msg token as it is invalid");
    } else if (IS_NOT_AUTHORIZED(tmp->val->state)) {
      log_debug_msg(LOG_AAATOKEN,
                    "ignoring receiver msg token %s as it is not authorized",
                    tmp->val->uuid);
    } else {
      np_dhkey_t issuer         = np_dhkey_create_from_hash(tmp->val->issuer);
      np_dhkey_t token_audience = np_dhkey_create_from_hash(tmp->val->audience);
      bool       include_token  = false;

      include_token = _np_dhkey_equal(&audience, &issuer) ||
                      _np_dhkey_equal(&audience, &token_audience) ||
                      _np_dhkey_equal(&audience, &run_prop->current_fp);

      if (include_token == true) {
        log_debug_msg(LOG_ROUTING,
                      "found valid receiver token (issuer: %s uuid: %s)",
                      tmp->val->issuer,
                      tmp->val->uuid);
        np_ref_obj(np_aaatoken_t, tmp->val, FUNC);
        // only pick key from a list if the subject msg_treshold is bigger than
        // zero and the sending threshold is bigger than zero as well and we
        // actually have a receiver node in the list
        sll_append(np_aaatoken_ptr, result_list, tmp->val);
      } else {
        char buf[65] = {0};
        log_debug_msg(LOG_AAATOKEN,
                      "ignoring receiver token for issuer %s as it is not in "
                      "audience \"%s\"",
                      tmp->val->issuer,
                      np_id_str(buf, *(np_id *)&audience));
      }
    }

    pll_next(tmp);
  }
  log_trace_msg(LOG_TRACE,
                ".step2._np_aaatoken_get_all_receiver %u -> selected %u",
                pll_size(ledger->recv_tokens),
                sll_size(result_list));
}

bool __is_intent_authz(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);
  log_trace_msg(LOG_TRACE, "start: void __is_intent_authz(...){");

  bool ret = false;
  NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);

  if (!ret) ret = FLAG_CMP(event.type, evt_authz);
  if (ret)
    ret &=
        (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_token));
  if (ret)
    ret &=
        (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
  if (ret) {
    NP_CAST(event.user_data, np_aaatoken_t, token);
    ret &= FLAG_CMP(token->type, np_aaatoken_type_message_intent);
    ret &= _np_aaatoken_is_valid(statemachine->_context,
                                 token,
                                 np_aaatoken_type_message_intent);
  }
  return ret;
}

void __np_intent_check(np_util_statemachine_t *statemachine,
                       const np_util_event_t   event) {
  np_ctx_memory(statemachine->_user_data);

  NP_CAST(statemachine->_user_data, np_key_t, intent_key);
  if (intent_key->entity_array[0] == NULL) return;
  if (intent_key->entity_array[2] == NULL) return;

  NP_CAST(intent_key->entity_array[0], np_msgproperty_conf_t, property);
  NP_CAST_RAW(intent_key->entity_array[2], struct __np_token_ledger, ledger);

  log_debug_msg(LOG_AAATOKEN,
                "%s has intent token (recv: %u / send: %u)",
                property->msg_subject,
                sll_size(ledger->recv_tokens),
                sll_size(ledger->send_tokens));

  if (ledger == NULL) return;
  pll_iterator(np_aaatoken_ptr) iter = NULL;

  // check for outdated sender token
  iter = pll_first(ledger->send_tokens);
  while (NULL != iter) {
    np_aaatoken_t *tmp_token = iter->val;
    pll_next(iter);

    if (NULL != tmp_token &&
        false == _np_aaatoken_is_valid(statemachine->_context,
                                       tmp_token,
                                       np_aaatoken_type_message_intent)) {
      log_debug_msg(LOG_DEBUG,
                    "deleting old / invalid sender msg tokens %p",
                    tmp_token);
      _np_intent_update_sender_session(intent_key, tmp_token, crud_delete);
      pll_remove(np_aaatoken_ptr,
                 ledger->send_tokens,
                 tmp_token,
                 _np_intent_cmp_exact);
      np_unref_obj(np_aaatoken_t, tmp_token, ref_aaatoken_local_mx_tokens);
      break;
    }
  }

  // check for outdated receiver token
  iter = pll_first(ledger->recv_tokens);
  while (NULL != iter) {
    np_aaatoken_t *tmp_token = iter->val;
    pll_next(iter);

    if (NULL != tmp_token &&
        false == _np_aaatoken_is_valid(statemachine->_context,
                                       tmp_token,
                                       np_aaatoken_type_message_intent)) {
      log_debug_msg(LOG_DEBUG,
                    "deleting old / invalid receiver msg token %p",
                    tmp_token);
      _np_intent_update_receiver_session(intent_key, tmp_token, crud_delete);
      pll_remove(np_aaatoken_ptr,
                 ledger->recv_tokens,
                 tmp_token,
                 _np_intent_cmp_exact);
      np_unref_obj(np_aaatoken_t, tmp_token, ref_aaatoken_local_mx_tokens);
      break;
    }
  }
}

void __np_get_create_crypto_tree(np_key_t   *subject_key,
                                 np_tree_t **crypto_tree) {
  if (NULL == subject_key->entity_array[3]) {
    *crypto_tree                 = np_tree_create();
    subject_key->entity_array[3] = *crypto_tree;
  } else {
    *crypto_tree = (np_tree_t *)subject_key->entity_array[3];
  }
}

void __np_get_create_ack_tree(np_key_t *subject_key, np_tree_t **ack_tree) {

  if (NULL == subject_key->entity_array[4]) {
    *ack_tree                    = np_tree_create();
    subject_key->entity_array[4] = *ack_tree;
  } else {
    *ack_tree = (np_tree_t *)subject_key->entity_array[4];
  }
}

bool _np_intent_has_crypto_session(np_key_t  *subject_key,
                                   np_dhkey_t session_dhkey) {
  np_ctx_memory(subject_key);

  bool       ret         = false;
  np_tree_t *crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &crypto_tree);

  char buf[65];
  log_debug_msg(LOG_WARNING,
                "crypto_session for %s / %s available? --> %p ",
                _np_key_as_str(subject_key),
                np_id_str(buf, &session_dhkey),
                np_tree_find_dhkey(crypto_tree, session_dhkey));

  ret = np_tree_find_dhkey(crypto_tree, session_dhkey) != NULL;

  return ret;
}

bool _np_intent_get_ack_session(np_key_t   *subject_key,
                                np_dhkey_t  session_dhkey,
                                np_dhkey_t *ack_to_dhkey) {
  np_tree_t *ack_tree = NULL;
  __np_get_create_ack_tree(subject_key, &ack_tree);
  np_tree_elem_t *ack_to_elem = np_tree_find_dhkey(ack_tree, session_dhkey);
  if (ack_to_elem != NULL) {
    _np_dhkey_assign(ack_to_dhkey, &ack_to_elem->val.value.dhkey);
    return true;
  }
  np_ctx_memory(subject_key);
  char buf[65];
  log_msg(LOG_INFO,
          "e2e session ack %s for message not found",
          np_id_str(buf, &session_dhkey));
  return false;
}

bool _np_intent_get_crypto_session(np_key_t            *subject_key,
                                   np_dhkey_t           session_dhkey,
                                   np_crypto_session_t *crypto_session) {
  assert(crypto_session != NULL);

  np_ctx_memory(subject_key);

  bool       ret         = false;
  np_tree_t *crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &crypto_tree);

  np_crypto_session_t *stored_crypto_session =
      np_tree_find_dhkey(crypto_tree, session_dhkey) == NULL
          ? NULL
          : np_tree_find_dhkey(crypto_tree, session_dhkey)->val.value.v;

  if (NULL != stored_crypto_session) {
    memcpy(crypto_session->session_key_to_read,
           stored_crypto_session->session_key_to_read,
           crypto_kx_SESSIONKEYBYTES);
    memcpy(crypto_session->session_key_to_write,
           stored_crypto_session->session_key_to_write,
           crypto_kx_SESSIONKEYBYTES);
    crypto_session->session_key_to_read_is_set =
        stored_crypto_session->session_key_to_read_is_set;
    crypto_session->session_key_to_write_is_set =
        stored_crypto_session->session_key_to_write_is_set;
    crypto_session->session_type = stored_crypto_session->session_type;
    ret                          = true;
    log_debug_msg(LOG_WARNING,
                  "crypto_session for %s  (%p) available: %p %p",
                  _np_key_as_str(subject_key),
                  subject_key,
                  crypto_session->session_key_to_read,
                  crypto_session->session_key_to_write);
  } else {
    log_debug(LOG_WARNING,
              "no crypto_session for %s (%p) available",
              _np_key_as_str(subject_key),
              subject_key);
  }
  return ret;
}

// this code is executed at the receiver of messages
void _np_intent_update_sender_session(np_key_t      *subject_key,
                                      np_aaatoken_t *sender_token,
                                      enum crud_op   crud) {
  np_ctx_memory(subject_key);

  np_tree_t *crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &crypto_tree);
  np_tree_t *ack_tree = NULL;
  __np_get_create_ack_tree(subject_key, &ack_tree);

  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);
  NP_CAST_RAW(subject_key->entity_array[1], np_msgproperty_run_t, run_prop);

  np_aaatoken_t *my_receiver_token    = pll_first(ledger->recv_tokens)->val;
  np_dhkey_t     my_receiver_token_fp = run_prop->current_fp;

  np_dhkey_t sender_token_fp = np_aaatoken_get_fingerprint(sender_token, false);
  np_dhkey_t sender_node_fp  = np_aaatoken_get_partner_fp(sender_token);

  np_crypto_session_t *_crypto_session        = NULL;
  np_crypto_session_t *private_crypto_session = NULL;
  np_new_obj(np_crypto_session_t, private_crypto_session);
  np_crypto_session_t *initial_crypto_session = NULL;
  np_new_obj(np_crypto_session_t, initial_crypto_session);

  // create (at least) two identifier hash values, one for private (dhke) and
  // one for sessions (ephemeral key)
  np_dhkey_t private_session_fp = {0};
  _np_dhkey_add(&private_session_fp, &sender_token_fp, &my_receiver_token_fp);
  np_dhkey_t initial_session_fp = {0};
  _np_dhkey_xor(&initial_session_fp, &sender_token_fp, &my_receiver_token_fp);

  if (sender_token != my_receiver_token && crud_delete == crud) {
    _crypto_session =
        np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL
            ? NULL
            : np_tree_find_dhkey(crypto_tree, private_session_fp)->val.value.v;
    np_tree_del_dhkey(crypto_tree, private_session_fp);
    np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);

    _crypto_session =
        np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL
            ? NULL
            : np_tree_find_dhkey(crypto_tree, initial_session_fp)->val.value.v;
    np_tree_del_dhkey(crypto_tree, initial_session_fp);
    np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);
    log_debug_msg(LOG_INFO,
                  "crypto_session with %s removed",
                  sender_token->issuer);

    np_tree_del_dhkey(ack_tree, sender_token_fp);
    np_tree_del_dhkey(ack_tree, initial_session_fp);
    np_tree_del_dhkey(ack_tree, private_session_fp);

  } else if (my_receiver_token != sender_token) {
    bool update = false;
    int  i = 0, j = 0;
    if (np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL) {
      private_crypto_session->session_type = crypto_session_private;
      update                               = true;
      i                                    = np_crypto_session(context,
                            &my_receiver_token->issuer_token->crypto,
                            private_crypto_session,
                            &sender_token->crypto,
                            true);
    }

    if (np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL) {
      initial_crypto_session->session_type = crypto_session_initial;
      update                               = true;
      j                                    = np_crypto_session(context,
                            &my_receiver_token->issuer_token->crypto,
                            initial_crypto_session,
                            &sender_token->crypto,
                            false);
    }

    if (i != 0 || j != 0) {
      log_debug_msg(LOG_DEBUG,
                    "crypto_session with %s could not be established (%d / %d)",
                    sender_token->issuer,
                    i,
                    j);
      np_unref_obj(np_crypto_session_t,
                   private_crypto_session,
                   ref_obj_creation);
      np_unref_obj(np_crypto_session_t,
                   initial_crypto_session,
                   ref_obj_creation);
    } else if (true == update) {
      // register private session (standard dhkey exchange)
      _crypto_session =
          np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL
              ? NULL
              : np_tree_find_dhkey(crypto_tree, private_session_fp)
                    ->val.value.v;
      np_tree_replace_dhkey(crypto_tree,
                            private_session_fp,
                            np_treeval_new_v(private_crypto_session));
      if (NULL != _crypto_session)
        np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);

      // register initial session (only to exchange symmetric key material)
      _crypto_session =
          np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL
              ? NULL
              : np_tree_find_dhkey(crypto_tree, initial_session_fp)
                    ->val.value.v;
      np_tree_replace_dhkey(crypto_tree,
                            initial_session_fp,
                            np_treeval_new_v(initial_crypto_session));
      if (NULL != _crypto_session)
        np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);

      // insert acknowledgement keys
      np_tree_insert_dhkey(ack_tree,
                           sender_token_fp,
                           np_treeval_new_dhkey(sender_node_fp));
      np_tree_insert_dhkey(ack_tree,
                           initial_session_fp,
                           np_treeval_new_dhkey(sender_node_fp));
      np_tree_insert_dhkey(ack_tree,
                           private_session_fp,
                           np_treeval_new_dhkey(sender_node_fp));

    } else {
      log_debug_msg(LOG_DEBUG,
                    "crypto_session with %s already established for %s (%p)",
                    sender_token->issuer,
                    _np_key_as_str(subject_key),
                    subject_key);
      np_unref_obj(np_crypto_session_t,
                   private_crypto_session,
                   ref_obj_creation);
      np_unref_obj(np_crypto_session_t,
                   initial_crypto_session,
                   ref_obj_creation);
    }
  }
}

void _np_intent_import_session(np_key_t    *subject_key,
                               np_tree_t   *crypto_tree,
                               enum crud_op crud) {
  np_ctx_memory(subject_key);

  np_tree_t *local_crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &local_crypto_tree);

  np_tree_elem_t *iter = NULL;
  RB_FOREACH (iter, np_tree_s, crypto_tree) {
    np_dhkey_t _to_find = iter->key.value.dhkey;

    np_crypto_session_t *old_crypto_session =
        np_tree_find_dhkey(local_crypto_tree, _to_find) == NULL
            ? NULL
            : np_tree_find_dhkey(local_crypto_tree, _to_find)->val.value.v;

    // delete old session
    if (crud_delete == crud) {
      np_tree_del_dhkey(local_crypto_tree, _to_find);
      if (NULL != old_crypto_session)
        np_unref_obj(np_crypto_session_t, old_crypto_session, ref_obj_creation);
    } else {
      if (NULL == old_crypto_session) {
        np_crypto_session_t *new_crypto_session = NULL;
        np_new_obj(np_crypto_session_t, new_crypto_session, ref_obj_usage);
        memcpy(new_crypto_session->session_key_to_read,
               iter->val.value.bin,
               crypto_kx_SESSIONKEYBYTES);
        new_crypto_session->session_key_to_read_is_set = true;
        new_crypto_session->session_type               = crypto_session_shared;
        np_tree_insert_dhkey(local_crypto_tree,
                             _to_find,
                             np_treeval_new_v(new_crypto_session));
      } else {
        memcpy(old_crypto_session->session_key_to_read,
               iter->val.value.bin,
               crypto_kx_SESSIONKEYBYTES);
        old_crypto_session->session_type = crypto_session_shared;
      }
    }
  }
}

// this code is executed at the sender of messages
void _np_intent_update_receiver_session(np_key_t      *subject_key,
                                        np_aaatoken_t *receiver_token,
                                        enum crud_op   crud) {
  np_ctx_memory(subject_key);

  np_tree_t *crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &crypto_tree);

  NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);
  NP_CAST_RAW(subject_key->entity_array[1], np_msgproperty_run_t, run_prop);

  np_aaatoken_t *my_sender_token    = pll_first(ledger->send_tokens)->val;
  np_dhkey_t     my_sender_token_fp = run_prop->current_fp;

  // np_aaatoken_get_fingerprint(my_sender_token, false);
  np_dhkey_t receiver_token_fp =
      np_aaatoken_get_fingerprint(receiver_token, false);

  np_crypto_session_t *_crypto_session = NULL;
  // create two identifier hash values, one for private (dhke) and one for
  // sessions (ephemeral key)
  np_crypto_session_t *private_crypto_session = NULL;
  np_new_obj(np_crypto_session_t, private_crypto_session);
  np_crypto_session_t *initial_crypto_session = NULL;
  np_new_obj(np_crypto_session_t, initial_crypto_session);

  np_dhkey_t private_session_fp = {0};
  _np_dhkey_add(&private_session_fp, &my_sender_token_fp, &receiver_token_fp);
  np_dhkey_t initial_session_fp = {0};
  _np_dhkey_xor(&initial_session_fp, &my_sender_token_fp, &receiver_token_fp);

  bool send_update = false;
  if (!_np_dhkey_equal(&receiver_token_fp, &my_sender_token_fp) &&
      crud_delete == crud) {
    _crypto_session =
        np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL
            ? NULL
            : np_tree_find_dhkey(crypto_tree, private_session_fp)->val.value.v;
    np_tree_del_dhkey(crypto_tree, private_session_fp);
    np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);
    _crypto_session =
        np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL
            ? NULL
            : np_tree_find_dhkey(crypto_tree, initial_session_fp)->val.value.v;
    np_tree_del_dhkey(crypto_tree, initial_session_fp);
    np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);
    log_info(LOG_INFO,
             "crypto_session with %s removed",
             receiver_token->issuer);

  } else if (!_np_dhkey_equal(&receiver_token_fp, &my_sender_token_fp)) {
    // create the bi-literal message
    // exchange crypto session
    int i = 0, j = 0;
    if (np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL) {
      private_crypto_session->session_type = crypto_session_private;
      send_update                          = true;
      i                                    = np_crypto_session(context,
                            &my_sender_token->issuer_token->crypto,
                            private_crypto_session,
                            &receiver_token->crypto,
                            false);
    }
    if (np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL) {
      initial_crypto_session->session_type = crypto_session_initial;
      send_update                          = true;
      j                                    = np_crypto_session(context,
                            &my_sender_token->issuer_token->crypto,
                            initial_crypto_session,
                            &receiver_token->crypto,
                            true);
    }

    if (i != 0 || j != 0) {
      log_debug_msg(LOG_DEBUG,
                    "crypto_session with %s could not be established (%d / %d)",
                    receiver_token->issuer,
                    i,
                    j);
      np_unref_obj(np_crypto_session_t,
                   private_crypto_session,
                   ref_obj_creation);
      np_unref_obj(np_crypto_session_t,
                   initial_crypto_session,
                   ref_obj_creation);
      send_update = false;
    } else if (send_update) {
      log_debug_msg(LOG_DEBUG,
                    "crypto_session with %s established for %s (%p)",
                    receiver_token->issuer,
                    _np_key_as_str(subject_key),
                    subject_key);

      // register private session (standard dhkey exchange)
      _crypto_session =
          np_tree_find_dhkey(crypto_tree, private_session_fp) == NULL
              ? NULL
              : np_tree_find_dhkey(crypto_tree, private_session_fp)
                    ->val.value.v;
      np_tree_replace_dhkey(crypto_tree,
                            private_session_fp,
                            np_treeval_new_v(private_crypto_session));
      if (NULL != _crypto_session)
        np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);

      // register initial session (only to exchange symmetric key material)
      _crypto_session =
          np_tree_find_dhkey(crypto_tree, initial_session_fp) == NULL
              ? NULL
              : np_tree_find_dhkey(crypto_tree, initial_session_fp)
                    ->val.value.v;
      np_tree_replace_dhkey(crypto_tree,
                            initial_session_fp,
                            np_treeval_new_v(initial_crypto_session));
      if (NULL != _crypto_session)
        np_unref_obj(np_crypto_session_t, _crypto_session, ref_obj_creation);
    } else {
      log_debug_msg(LOG_DEBUG,
                    "crypto_session with %s already established for %s (%p)",
                    receiver_token->issuer,
                    _np_key_as_str(subject_key),
                    subject_key);
      np_unref_obj(np_crypto_session_t,
                   private_crypto_session,
                   ref_obj_creation);
      np_unref_obj(np_crypto_session_t,
                   initial_crypto_session,
                   ref_obj_creation);
    }
  }

  _crypto_session =
      (np_crypto_session_t *)np_tree_find_dhkey(crypto_tree,
                                                my_sender_token_fp) == NULL
          ? NULL
          : np_tree_find_dhkey(crypto_tree, my_sender_token_fp)->val.value.v;

  if (_crypto_session && true == send_update) {
    // send message with encrypted symmetric key over the pubsub channel
    np_message_t *update_msg = NULL;
    np_new_obj(np_message_t, update_msg);

    np_tree_t *update_msg_body = np_tree_create();
    // we added or deleted a receiver, so send the current key once again to
    // each participant
    // TODO: could be better, using the pubsub nature of neuropil. for now: for
    // each recipient one message. Privacy concern: not everybody should know
    // about authorization of a sender. If using "audience" field the receiver
    // group implicitly already knows each other, but without audience there is
    // no explicit agreement
    np_tree_insert_dhkey(
        update_msg_body,
        my_sender_token_fp,
        np_treeval_new_bin(_crypto_session->session_key_to_write,
                           crypto_kx_SESSIONKEYBYTES));

    NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);

    np_ref_obj(np_message_t, update_msg, ref_message_msg_property);
    _np_message_create(update_msg,
                       initial_session_fp,
                       context->my_identity->dhkey,
                       property->subject_dhkey,
                       np_tree_clone(update_msg_body));

    log_debug_msg(LOG_DEBUG,
                  "sending crypto_session established on subject %s (%p)",
                  _np_key_as_str(subject_key),
                  subject_key);

    np_util_event_t rekey_msg_event = {
        .target_dhkey = my_sender_token_fp,
        .type         = (evt_message | evt_internal | evt_userspace),
        .user_data    = update_msg};

    np_jobqueue_submit_event(context,
                             0.0,
                             subject_key->dhkey,
                             rekey_msg_event,
                             "urn:np:intent:update");
    // _np_keycache_execute_event(context, subject_key->dhkey, rekey_msg_event);

    np_unref_obj(np_message_t, update_msg, ref_obj_creation);
    np_tree_free(update_msg_body);
  }
}

void _np_intent_update_session(np_key_t              *subject_key,
                               np_aaatoken_t         *my_token,
                               bool                   for_receiver,
                               NP_UNUSED enum crud_op crud) {
  np_ctx_memory(subject_key);

  np_tree_t *crypto_tree = NULL;
  __np_get_create_crypto_tree(subject_key, &crypto_tree);

  // we need to send a message with encrypted symmetric key over the pubsub
  // channel
  np_tree_t *update_msg_body = np_tree_create();

  // TODO: re-factor token ledger to hold two own keys and a list of peer token
  np_dhkey_t my_token_fp = np_aaatoken_get_fingerprint(my_token, false);
  np_crypto_session_t *my_crypto_session = NULL;

  if (crud == crud_update || crud == crud_delete) {
    // find the old crypto session object
    my_crypto_session =
        np_tree_find_dhkey(crypto_tree, my_token_fp) == NULL
            ? NULL
            : np_tree_find_dhkey(crypto_tree, my_token_fp)->val.value.v;

    if (my_crypto_session == NULL) {
      log_msg(LOG_WARNING, "attempt to update/delete non-existing session");
      np_tree_free(update_msg_body);
      return;
    }

  } else if (crud == crud_create) {
    // create a new crypto session object
    np_new_obj(np_crypto_session_t, my_crypto_session);

    my_crypto_session->session_type = crypto_session_shared;

    randombytes_buf(my_crypto_session->session_key_to_write,
                    crypto_kx_SESSIONKEYBYTES);
    my_crypto_session->session_key_to_write_is_set = true;

    randombytes_buf(my_crypto_session->session_key_to_read,
                    crypto_kx_SESSIONKEYBYTES);
    my_crypto_session->session_key_to_read_is_set = true;

    np_tree_insert_dhkey(crypto_tree,
                         my_token_fp,
                         np_treeval_new_v(my_crypto_session));
    log_debug_msg(LOG_DEBUG,
                  "own crypto_session established on subject %s (%p)",
                  _np_key_as_str(subject_key),
                  subject_key);
  }

  if (crud == crud_delete) {
    np_tree_del_dhkey(crypto_tree, my_token_fp);
    memset(my_crypto_session->session_key_to_read, 0, NP_PUBLIC_KEY_BYTES);
    memset(my_crypto_session->session_key_to_write, 0, NP_PUBLIC_KEY_BYTES);
    np_unref_obj(np_crypto_session_t, my_crypto_session, ref_obj_creation);
    np_tree_free(update_msg_body);
    return;
  }

  // a) intent update for receiver dhkey means, do not send out messages
  // b) crud_update for now: nothing to do, for future: attributes of
  // token may change, changing the crypto session
  if (for_receiver == true || crud == crud_update) {
    np_tree_free(update_msg_body);
    return;
  }

  // we added or deleted a receiver, so send the current key once again to
  // each participant
  // TODO: could be better, using the pubsub nature of neuropil. for now: for
  // each recipient one message
  np_tree_insert_dhkey(
      update_msg_body,
      my_token_fp,
      np_treeval_new_bin(my_crypto_session->session_key_to_write,
                         crypto_kx_SESSIONKEYBYTES));

  NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);

  np_tree_elem_t *iter = NULL;
  RB_FOREACH (iter, np_tree_s, crypto_tree) {
    np_dhkey_t           msg_target_dhkey    = iter->key.value.dhkey;
    np_crypto_session_t *peer_crypto_session = iter->val.value.v;

    // np_dhkey_t token_fp = np_aaatoken_get_fingerprint(token, false);
    // _np_dhkey_sub(&token_fp, &token_fp, &my_token_fp);

    if (_np_dhkey_equal(&my_token_fp, &msg_target_dhkey)) {
      continue;
    }

    if (peer_crypto_session->session_type == crypto_session_initial) {

      np_message_t *update_msg = NULL;
      np_new_obj(np_message_t, update_msg);

      np_ref_obj(np_message_t, update_msg, ref_message_msg_property);
      _np_message_create(update_msg,
                         msg_target_dhkey,
                         context->my_identity->dhkey,
                         property->subject_dhkey,
                         np_tree_clone(update_msg_body));

      log_debug_msg(LOG_DEBUG,
                    "sending crypto_session established on subject %s (%p)",
                    _np_key_as_str(subject_key),
                    subject_key);

      np_util_event_t rekey_msg_event = {
          .target_dhkey = my_token_fp,
          .type         = (evt_message | evt_internal | evt_userspace),
          .user_data    = update_msg};

      // _np_event_runtime_add_event(context,
      //                             event.current_run,
      //                             subject_key->dhkey,
      //                             rekey_msg_event);
      // _np_keycache_execute_event(context, subject_key->dhkey,
      // rekey_msg_event);
      np_jobqueue_submit_event(context,
                               0.0,
                               subject_key->dhkey,
                               rekey_msg_event,
                               "urn:np:intent:update");
      np_unref_obj(np_message_t, update_msg, ref_obj_creation);
    }
  }

  np_tree_free(update_msg_body);
}

// TODO: send out intents if dht distance is not matching anymore
