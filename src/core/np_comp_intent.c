//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include <inttypes.h>

#include "core/np_comp_intent.h"

#include "neuropil.h"
#include "neuropil_data.h"

#include "np_aaatoken.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_legacy.h"
#include "util/np_event.h"
#include "util/np_statemachine.h"

struct __np_token_ledger {
	np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on which this node is interested in
	np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on which this node is interested in
};

static int8_t _np_intent_cmp (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
    int8_t ret_check = 0;

    if (first == second) return (0);

    if (first == NULL || second == NULL ) return (-1);

    ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
    if (0 == ret_check )
    {
        return (ret_check);
    }
    ret_check = strncmp(first->issuer, second->issuer, 65);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->subject, second->subject, strnlen(first->subject, 255) );
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->realm, second->realm, strnlen(first->realm, 255));
    if (0 != ret_check )
    {
        return (ret_check);
    }

    return (0);
}

static int8_t _np_intent_cmp_exact (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
    int8_t ret_check = 0;

    if (first == second) return (0);

    if (first == NULL || second == NULL ) return (-1);

    ret_check = sodium_memcmp(first->crypto.derived_kx_public_key, second->crypto.derived_kx_public_key, crypto_sign_PUBLICKEYBYTES);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->uuid, second->uuid, NP_UUID_BYTES);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    return _np_intent_cmp(first,second);
}

// update internal structure and return a interest if a matching pair has been found
np_aaatoken_t* _np_intent_add_sender(np_key_t* subject_key, np_aaatoken_t *token)
{
    assert(token != NULL);
    np_state_t* context = np_ctx_by_memory(token);

    NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
    NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

    np_aaatoken_t * ret = NULL;

    log_debug_msg(LOG_AAATOKEN, "update on global sender msg token structures ... %p (size %d)",
                             property, pll_size(ledger->send_tokens) );

    // insert new token
    // update #2 subject specific data
    struct np_data_conf conf;
    np_data_value max_threshold ={0}, mep_type ={0}, ack_mode ={0};
    enum np_data_return get_data_ret;

    if((get_data_ret = np_get_data(token->attributes, "mep_type", &conf, &mep_type)) != np_ok){
        mep_type.unsigned_integer = DEFAULT_TYPE;
        log_debug_msg(LOG_ERROR|LOG_AAATOKEN, "token %s is missing key \"mep_type\" code: %"PRIu32, token->uuid, get_data_ret);
    }
    if((get_data_ret = np_get_data(token->attributes, "ack_mode", &conf, &ack_mode)) != np_ok){
        ack_mode.unsigned_integer = ACK_NONE;
        log_debug_msg(LOG_ERROR|LOG_AAATOKEN, "token %s is missing key \"ack_mode\" code: %"PRIu32, token->uuid, get_data_ret);
    }
    if((get_data_ret = np_get_data(token->attributes, "max_threshold", &conf, &max_threshold)) != np_ok) {
        max_threshold.unsigned_integer = 0;
        log_debug_msg(LOG_ERROR|LOG_AAATOKEN, "token %s is missing key \"max_threshold\" code: %"PRIu32, token->uuid, get_data_ret);
    }

    property->mep_type |= (mep_type.unsigned_integer & SENDER_MASK);
    property->ack_mode = ack_mode.unsigned_integer;
    // property->last_update = np_time_now();

    if (max_threshold.unsigned_integer > 0)
    {
        log_debug_msg(LOG_AAATOKEN, "adding sender token %p threshold %"PRIu32, token, max_threshold.unsigned_integer);
        np_msg_mep_type sender_mep_type = property->mep_type & SENDER_MASK;

        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
        bool allow_dups = true;

        if (FLAG_CMP(sender_mep_type, SINGLE_SENDER))
        {
            cmp_aaatoken_replace   = _np_intent_cmp;
            allow_dups = false;
        }

        // update #1 key specific data
        np_ref_obj(np_aaatoken_t, token, ref_aaatoken_local_mx_tokens);
        ret = pll_replace(np_aaatoken_ptr, ledger->send_tokens, token, cmp_aaatoken_replace);
        if (NULL == ret)
        {
            pll_insert(np_aaatoken_ptr, ledger->send_tokens, token, allow_dups, cmp_aaatoken_add);
        }
        else
        {
            token->state = ret->state;
        }
        log_debug_msg(LOG_AAATOKEN, "added new single sender token %s subject: %s",token->uuid , _np_key_as_str(subject_key));
    }

    return ret;
}

np_aaatoken_t* _np_intent_get_sender_token(np_key_t* subject_key, const np_dhkey_t sender_dhkey)
{
    np_ctx_memory(subject_key);
    log_debug_msg(LOG_AAATOKEN, "lookup in global sender msg token structures (%p)...", subject_key);

    // static np_dhkey_t empty_dhkey = {0};
    NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
    NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

    // look up sources to see whether a sender already exists
    np_aaatoken_t* return_token = NULL;

#ifdef DEBUG
    char sender_dhkey_as_str[65];
    _np_dhkey_str(&sender_dhkey, sender_dhkey_as_str);
#endif

    log_debug_msg(LOG_AAATOKEN, ".step1._np_intent_get_sender_token %d / %s", pll_size(ledger->send_tokens), property->msg_subject);
    pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->send_tokens);
    while (NULL != iter)
    {
        return_token = iter->val;
        if (false == _np_aaatoken_is_valid(context, return_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN, "ignoring invalid sender token for issuer %s", return_token->issuer);
            return_token = NULL;
            pll_next(iter);
            continue;
        }

        np_dhkey_t partner_token_dhkey = np_aaatoken_get_partner_fp(return_token);
        // only pick key from a list if the subject msg_treshold is bigger than zero
        // and we actually have the correct sender node in the list
        if (!_np_dhkey_equal(&sender_dhkey, &dhkey_zero) && !_np_dhkey_equal(&partner_token_dhkey, &sender_dhkey))
        {
#ifdef DEBUG
            char partner_token_dhkey_str[65]; partner_token_dhkey_str[64] = '\0';
            _np_dhkey_str(&partner_token_dhkey, partner_token_dhkey_str);
            log_debug_msg(LOG_AAATOKEN,
                            "ignoring sender token for issuer %s (partner node: %s) / send_hk: %s (sender dhkey doesn't match)",
                            return_token->issuer, partner_token_dhkey_str, sender_dhkey_as_str);
#endif // DEBUG
            return_token = NULL;
            pll_next(iter);
            continue;
        }

        // last check: has the token received authn/authz already
        if (IS_AUTHORIZED(return_token->state) /* && IS_AUTHENTICATED(return_token->state)*/ )
        {
            log_debug_msg(LOG_AAATOKEN, "found valid sender token (%s)", return_token->issuer);
            np_ref_obj(np_aaatoken_t, return_token);
            break;
        } 
        pll_next(iter);
        return_token = NULL;
    }
    log_debug_msg(LOG_AAATOKEN, ".step2._np_aaatoken_get_sender_token %d", pll_size(ledger->send_tokens));

    return (return_token);
}

// update internal structure and clean invalid tokens
np_aaatoken_t* _np_intent_add_receiver(np_key_t* subject_key, np_aaatoken_t *token)
{
    assert(token != NULL);
    np_state_t* context = np_ctx_by_memory(token);

    NP_CAST(subject_key->entity_array[0], np_msgproperty_conf_t, property);
    NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

    np_aaatoken_t* ret = NULL;

    log_debug_msg(LOG_AAATOKEN, "update on global receiving msg token (%s)  structures ... %p (size %d)",
                             token->uuid,property, pll_size(ledger->recv_tokens));

    // insert new token
    log_debug_msg(LOG_AAATOKEN, ".step1._np_aaatoken_add_receiver %d / %s", pll_size(ledger->recv_tokens), token->subject);

    // update #2 subject specific data
    struct np_data_conf conf;
    np_data_value max_threshold ={0}, mep_type ={0};
    enum np_data_return get_data_ret;

    if((get_data_ret = np_get_data(token->attributes, "max_threshold", &conf, &max_threshold) != np_ok)) {
        max_threshold.unsigned_integer = 0;
        log_debug_msg(LOG_ERROR|LOG_AAATOKEN, "token %s is missing key \"max_threshold\" code: %"PRIu32, token->uuid, get_data_ret);

    }
    if((get_data_ret = np_get_data(token->attributes, "mep_type", &conf, &mep_type) != np_ok)) {
        mep_type.unsigned_integer = DEFAULT_TYPE;
        log_debug_msg(LOG_ERROR|LOG_AAATOKEN, "token %s is missing key \"mep_type\" code: %"PRIu32, token->uuid, get_data_ret);
    }

    property->mep_type |= (mep_type.unsigned_integer & RECEIVER_MASK);
    // property->last_update = np_time_now();

    if (max_threshold.unsigned_integer > 0)
    {   // only add if there are messages to receive
        log_debug_msg(LOG_AAATOKEN, "adding receiver token %p threshold %"PRIu8, token, max_threshold);

        np_msg_mep_type receiver_mep_type = (property->mep_type & RECEIVER_MASK);

        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
        bool allow_dups = true;

        if (FLAG_CMP(receiver_mep_type, SINGLE_RECEIVER))
        {
            cmp_aaatoken_replace   = _np_intent_cmp;
            allow_dups = false;
        }

        // update #1 key specific data
        np_ref_obj(np_aaatoken_t, token, ref_aaatoken_local_mx_tokens);
        ret = pll_replace(np_aaatoken_ptr, ledger->recv_tokens, token, cmp_aaatoken_replace);
        if (NULL == ret)
        {
            pll_insert(np_aaatoken_ptr, ledger->recv_tokens, token, allow_dups, cmp_aaatoken_add);
        }
        else
        {
            token->state = ret->state;
        }
        log_debug_msg(LOG_AAATOKEN, "added new single receiver token for message hash %s", _np_key_as_str(subject_key) );
    }

    return ret;    
}

np_aaatoken_t* _np_intent_get_receiver(np_key_t* subject_key, const np_dhkey_t target)
{
    np_ctx_memory(subject_key);
    log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_intent_get_receiver(...){");

    static np_dhkey_t empty_dhkey = {0};

    NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

    np_aaatoken_t* return_token = NULL;
    bool found_return_token = false;

    pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->recv_tokens);
    while (NULL != iter &&
           false == found_return_token)
    {
        log_debug_msg(LOG_AAATOKEN, "checking receiver msg tokens %p/%p", iter, iter->val);
        return_token = iter->val;

        if (false == _np_aaatoken_is_valid(context, return_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN, "ignoring invalid receiver msg tokens %p", return_token );
            pll_next(iter);
            return_token = NULL;
            continue;
        }

        np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(return_token->issuer);

        if (_np_dhkey_equal(&recvtoken_issuer_key, &context->my_identity->dhkey) ||
            _np_dhkey_equal(&recvtoken_issuer_key, &context->my_node_key->dhkey) )
        {   // only use the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
            log_debug_msg(LOG_AAATOKEN, "ignoring token to send messages to myself %p", return_token );
            pll_next(iter);
            return_token = NULL;
            continue;
        }
        
        if(!_np_dhkey_equal(&empty_dhkey, &target) )
        {
#ifdef DEBUG
            char targetnode_str[65];
            _np_dhkey_str(&target, targetnode_str);
            log_debug_msg(LOG_AAATOKEN, "searching token for target %s ", targetnode_str);
#endif
            if (!_np_dhkey_equal(&recvtoken_issuer_key, &target)) 
            {
                log_debug_msg(LOG_AAATOKEN, "ignoring %s receiver token for others nodes", return_token->issuer);
                pll_next(iter);
                return_token = NULL;
                continue;
            }
        }

        // last check: has the token received authn/authz already
        if (IS_AUTHORIZED(return_token->state) /* && IS_AUTHENTICATED(return_token->state)*/ )
        {
            log_debug_msg(LOG_AAATOKEN,
                          "found valid receiver token (issuer: %s)", return_token->issuer );
            // found_return_token = true;
            np_ref_obj(np_aaatoken_t, return_token);
            break;
        }
        else 
        {
            pll_next(iter);
            return_token = NULL;
            continue;
        }
    }

    if(NULL == return_token ) 
    {
        log_debug_msg(LOG_AAATOKEN, "found no valid receiver token" );
    }

    return (return_token);
}

void _np_intent_get_all_receiver(np_key_t* subject_key, np_dhkey_t audience, np_sll_t(np_aaatoken_ptr, *tmp_token_list))
{
    np_ctx_memory(subject_key);

    np_sll_t(np_aaatoken_ptr, result_list = *tmp_token_list);
    NP_CAST_RAW(subject_key->entity_array[2], struct __np_token_ledger, ledger);

    pll_iterator(np_aaatoken_ptr) tmp = pll_first(ledger->recv_tokens);
    while (NULL != tmp)
    {
        if (false == _np_aaatoken_is_valid(context, tmp->val, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN, "ignoring receiver msg token as it is invalid" );
        }
        else if (IS_NOT_AUTHORIZED(tmp->val->state))
        {
            log_debug_msg(LOG_AAATOKEN, "ignoring receiver msg token %s as it is not authorized",tmp->val->uuid );
        }
        else
        {
            np_dhkey_t issuer = np_dhkey_create_from_hash(tmp->val->issuer);
            bool include_token = true;

            include_token =
                    _np_dhkey_equal(&audience, &issuer)     ||
                    _np_dhkey_equal(&audience, &dhkey_zero) ;

            if (include_token==true) 
            {
                log_debug_msg(LOG_ROUTING, "found valid receiver token (issuer: %s uuid: %s)", tmp->val->issuer,tmp->val->uuid);
                np_ref_obj(np_aaatoken_t, tmp->val);
                // only pick key from a list if the subject msg_treshold is bigger than zero
                // and the sending threshold is bigger than zero as well
                // and we actually have a receiver node in the list
                sll_append(np_aaatoken_ptr, result_list, tmp->val);
            } else {
                char buf[65] = {0};
                log_debug_msg(LOG_AAATOKEN, "ignoring receiver token for issuer %s as it is not in audience \"%s\"", tmp->val->issuer, np_id_str(buf, *(np_id*)&audience));
            }
        }

        pll_next(tmp);
    }
    log_trace_msg(LOG_TRACE, ".step2._np_aaatoken_get_all_receiver %u -> selected %u", pll_size(ledger->recv_tokens), sll_size(result_list));
}

bool __is_intent_authz(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_trace_msg(LOG_TRACE, "start: void __is_intent_authz(...){");

    bool ret = false;
    // NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_authz);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= FLAG_CMP(token->type, np_aaatoken_type_message_intent);
        ret &= _np_aaatoken_is_valid(context, token, token->type);
    }
    log_trace(LOG_ROUTING, "%s ret %"PRIu8, FUNC, ret);
    return ret;
}

void __np_intent_check(np_util_statemachine_t* statemachine, NP_UNUSED const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    if (intent_key->entity_array[0] == NULL) return;
    if (intent_key->entity_array[2] == NULL) return;

    NP_CAST(intent_key->entity_array[0], np_msgproperty_conf_t, property);
    NP_CAST_RAW(intent_key->entity_array[2], struct __np_token_ledger, ledger);

    log_debug_msg(LOG_AAATOKEN,
            "%s has intent token (recv: %u / send: %u)",
            property->msg_subject, sll_size(ledger->recv_tokens), sll_size(ledger->send_tokens));

    if (ledger == NULL) return;
    pll_iterator(np_aaatoken_ptr) iter = NULL;

    // check for outdated sender token
    iter = pll_first(ledger->send_tokens);
    while (NULL != iter)
    {
        np_aaatoken_t* tmp_token = iter->val;
        pll_next(iter);

        if (NULL  != tmp_token &&
            false == _np_aaatoken_is_valid(context, tmp_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN, "deleting old / invalid sender msg tokens %s", tmp_token->uuid);
            pll_remove(np_aaatoken_ptr, ledger->send_tokens, tmp_token, _np_intent_cmp_exact);
            np_unref_obj(np_aaatoken_t, tmp_token, ref_aaatoken_local_mx_tokens);
            break;
        }
    }    

    // check for outdated sender token
    iter = pll_first(ledger->recv_tokens);
    while (NULL != iter)
    {
        np_aaatoken_t* tmp_token = iter->val;
        pll_next(iter);

        if (NULL  != tmp_token &&
            false == _np_aaatoken_is_valid(context, tmp_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN, "deleting old / invalid receiver msg token %s", tmp_token->uuid);
            pll_remove(np_aaatoken_ptr, ledger->recv_tokens, tmp_token, _np_intent_cmp_exact);
            np_unref_obj(np_aaatoken_t, tmp_token, ref_aaatoken_local_mx_tokens);
            break;
        }
    }
} 

// TODO: send out intents if dht distance is not mmatching anymore
