//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project

// this file conatins the state machine conditions, transitions and states that an identity can
// have. It is included form np_key.c, therefore there are no extra #include directives.

#include <inttypes.h>

#include "core/np_comp_intent.h"

#include "neuropil.h"

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

    ret_check = strncmp(first->issuer, second->issuer, 65);
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->subject, second->subject, (strnlen(first->subject,255)));
    if (0 != ret_check )
    {
        return (ret_check);
    }

    ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
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

void _np_intent_create_token_ledger(np_key_t* my_intent_key, const np_util_event_t event)
{
    np_ctx_memory(my_intent_key);
    log_debug_msg(LOG_TRACE, "start: void _np_intent_create_token_ledger(...) {");

    NP_CAST(event.user_data, np_aaatoken_t, token);

    if (sll_size(my_intent_key->entities) == 0) 
    {   // list is not empty if subject is already locally well known
        // create a wrapper property to facilitate the message intent exchange 
        np_msgproperty_t* new_property = NULL;
        np_new_obj(np_msgproperty_t, new_property);

        new_property->msg_subject = strndup(token->subject, 255);
        new_property->mode_type = (OUTBOUND | INBOUND);

        sll_append(void_ptr, my_intent_key->entities, new_property);
        np_ref_obj(np_msgproperty_t, new_property, "_np_intent_create_token_ledger");

        log_debug_msg(LOG_DEBUG, "created ledger property for %s %p", token->subject, new_property);
    }

    if (sll_size(my_intent_key->entities) == 1) 
    {
        // could be empty on first use, therefore create and append it to the entities
        struct __np_token_ledger* token_ledger = malloc( sizeof (struct __np_token_ledger) );
        pll_init(np_aaatoken_ptr, token_ledger->recv_tokens);
        pll_init(np_aaatoken_ptr, token_ledger->send_tokens);
    
        sll_append(void_ptr, my_intent_key->entities, token_ledger);
        log_debug_msg(LOG_DEBUG, "creating intent ledger lists for %s / %p", token->subject, token_ledger);
    }
}

// update internal structure and return a interest if a matching pair has been found
np_aaatoken_t* _np_intent_add_sender(np_key_t* subject_key, np_aaatoken_t *token)
{
    assert(token != NULL);
    np_state_t* context = np_ctx_by_memory(token);

    NP_CAST(sll_first(subject_key->entities)->val, np_msgproperty_t, property);
    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    np_aaatoken_t * ret = NULL;

    log_debug_msg(LOG_DEBUG, "update on global sender msg token structures ... %p (size %d)",
                             property, pll_size(ledger->send_tokens) );

    // insert new token
    // update #2 subject specific data
    property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & SENDER_MASK);
    property->ack_mode = np_tree_find_str(token->extensions, "ack_mode")->val.value.ush;
    property->last_update = np_time_now();

    uint8_t max_threshold = np_tree_find_str(token->extensions_local, "max_threshold")->val.value.ush;

    if (max_threshold > 0)
    {
        log_debug_msg(LOG_DEBUG, "adding sender token %p threshold %"PRIu8, token, max_threshold);
        np_msg_mep_type sender_mep_type = property->mep_type & SENDER_MASK;

        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
        bool allow_dups = true;

        if (SINGLE_SENDER == (SINGLE_SENDER & sender_mep_type))
        {
            cmp_aaatoken_replace   = _np_intent_cmp;
            allow_dups = false;
        }
        
        // update #1 key specific data
        np_ref_obj(np_aaatoken_t, token, "send_tokens");
        ret = pll_replace(np_aaatoken_ptr, ledger->send_tokens, token, cmp_aaatoken_replace);
        if (NULL == ret)
        {
            pll_insert(np_aaatoken_ptr, ledger->send_tokens, token, allow_dups, cmp_aaatoken_add);
        }
        else
        {
            token->state = ret->state;
        }
        log_debug_msg(LOG_DEBUG, "added new single sender token for message hash %s", _np_key_as_str(subject_key) );
    }

    return ret;
}

np_aaatoken_t* _np_intent_get_sender_token(np_key_t* subject_key, const np_dhkey_t sender_dhkey)
{
    np_ctx_memory(subject_key);
    log_debug_msg(LOG_DEBUG, "lookup in global sender msg token structures (%p)...", subject_key);

    static np_dhkey_t empty_dhkey = {0};
    NP_CAST(sll_first(subject_key->entities)->val, np_msgproperty_t, property);
    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    // look up sources to see whether a sender already exists
    np_aaatoken_t* return_token = NULL;
    bool found_return_token = false;

#ifdef DEBUG
    char sender_dhkey_as_str[65];
    _np_dhkey_str(&sender_dhkey, sender_dhkey_as_str);
#endif

    log_debug_msg(LOG_DEBUG, ".step1._np_intent_get_sender_token %d / %s", pll_size(ledger->send_tokens), property->msg_subject);
    pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->send_tokens);
    while (NULL != iter && false == found_return_token)
    {
        return_token = iter->val;
        if (false == _np_aaatoken_is_valid(return_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_DEBUG, "ignoring invalid sender token for issuer %s", return_token->issuer);
            return_token = NULL;
            pll_next(iter);
            continue;
        }

        np_dhkey_t partner_token_dhkey = np_aaatoken_get_partner_fp(return_token);
        // only pick key from a list if the subject msg_treshold is bigger than zero
        // and we actually have the correct sender node in the list
        if (false == _np_dhkey_equal(&partner_token_dhkey, &sender_dhkey))
        {
#ifdef DEBUG
            char partner_token_dhkey_str[65]; partner_token_dhkey_str[64] = '\0';
            _np_dhkey_str(&partner_token_dhkey, partner_token_dhkey_str);
            log_debug_msg(LOG_DEBUG,
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
            log_debug_msg(LOG_DEBUG, "found valid sender token (%s)", return_token->issuer);
            found_return_token = true;
            np_ref_obj(np_aaatoken_t, return_token);
        } 
        else 
        {
            pll_next(iter);
            return_token = NULL;
        }
    }
    log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_sender_token %d", pll_size(ledger->send_tokens));

    return (return_token);
}

// update internal structure and clean invalid tokens
np_aaatoken_t* _np_intent_add_receiver(np_key_t* subject_key, np_aaatoken_t *token)
{
    assert(token != NULL);
    np_state_t* context = np_ctx_by_memory(token);

    NP_CAST(sll_first(subject_key->entities)->val, np_msgproperty_t, property);
    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    np_aaatoken_t* ret = NULL;	

    log_debug_msg(LOG_DEBUG, "update on global receiving msg token structures ... %p (size %d)",
                             property, pll_size(ledger->recv_tokens));

    // insert new token
    log_debug_msg(LOG_DEBUG, ".step1._np_aaatoken_add_receiver %d / %s", pll_size(ledger->recv_tokens), token->subject);

    // update #2 subject specific data
    property->mep_type |= (np_tree_find_str(token->extensions, "mep_type")->val.value.ul & RECEIVER_MASK);
    property->last_update = np_time_now();

    uint8_t max_threshold = np_tree_find_str(token->extensions_local, "max_threshold")->val.value.ush;
    if (max_threshold > 0)
    {	// only add if there are messages to receive
        log_debug_msg(LOG_DEBUG, "adding receiver token %p threshold %"PRIu8, token, max_threshold);

        np_msg_mep_type receiver_mep_type = (property->mep_type & RECEIVER_MASK);
        
        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_add     = _np_intent_cmp;
        np_aaatoken_ptr_pll_cmp_func_t cmp_aaatoken_replace = _np_intent_cmp_exact;
        bool allow_dups = true;

        if (SINGLE_RECEIVER == (SINGLE_RECEIVER & receiver_mep_type))
        {
            cmp_aaatoken_replace   = _np_intent_cmp;
            allow_dups = false;
        }

        // update #1 key specific data
        np_ref_obj(np_aaatoken_t, token, "recv_tokens");
        ret = pll_replace(np_aaatoken_ptr, ledger->recv_tokens, token, cmp_aaatoken_replace);
        if (NULL == ret)
        {
            pll_insert(np_aaatoken_ptr, ledger->recv_tokens, token, allow_dups, cmp_aaatoken_add);
        }
        else
        {
            token->state = ret->state;
        }
        log_debug_msg(LOG_DEBUG, "added new single receiver token for message hash %s", _np_key_as_str(subject_key) );
    }

    return ret;    
}

np_aaatoken_t* _np_intent_get_receiver(np_key_t* subject_key, const np_dhkey_t target)
{
    np_ctx_memory(subject_key);
    log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: np_aaatoken_t* _np_intent_get_receiver(...){");

    static np_dhkey_t empty_dhkey = {0};

    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    np_aaatoken_t* return_token = NULL;
    bool found_return_token = false;

    pll_iterator(np_aaatoken_ptr) iter = pll_first(ledger->recv_tokens);
    while (NULL != iter &&
           false == found_return_token)
    {
        log_debug_msg(LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
        return_token = iter->val;

        if (false == _np_aaatoken_is_valid(return_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_DEBUG, "ignoring invalid receiver msg tokens %p", return_token );
            pll_next(iter);
            return_token = NULL;
            continue;
        }

        np_dhkey_t recvtoken_issuer_key = np_dhkey_create_from_hash(return_token->issuer);

        if (_np_dhkey_equal(&recvtoken_issuer_key, &context->my_identity->dhkey) ||
            _np_dhkey_equal(&recvtoken_issuer_key, &context->my_node_key->dhkey) )
        {   // only use the token if it is not from ourself (in case of IN/OUTBOUND on same subject)
            log_debug_msg(LOG_DEBUG, "ignoring token to send messages to myself %p", return_token );
            pll_next(iter);
            return_token = NULL;
            continue;
        }
        
        if(!_np_dhkey_equal(&empty_dhkey, &target) )
        {
#ifdef DEBUG
            char targetnode_str[65];
            _np_dhkey_str(&target, targetnode_str);
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "searching token for target %s ", targetnode_str);
#endif
            if (!_np_dhkey_equal(&recvtoken_issuer_key, &target)) 
            {
                log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring %s receiver token for others nodes", return_token->issuer);
                pll_next(iter);
                return_token = NULL;
                continue;
            }
        }

        // last check: has the token received authn/authz already
        if (IS_AUTHORIZED(return_token->state) /* && IS_AUTHENTICATED(return_token->state)*/ )
        {
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
                          "found valid receiver token (%s)", return_token->issuer );
            found_return_token = true;
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
        log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found no valid receiver token" );
    }

    return (return_token);
}

/** np_get_sender_token
 ** retrieve a list of valid sender tokens from the cache
 ** TODO extend this function with a key and an amount of messages
 ** TODO use a different function for mitm and leaf nodes ?
 **/
sll_return(np_aaatoken_ptr) _np_intent_get_all_sender(np_key_t* subject_key, const char* const audience)
{
    np_ctx_memory(subject_key);

    sll_init_full(np_aaatoken_ptr, return_list);
    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    pll_iterator(np_aaatoken_ptr) tmp = pll_first(ledger->send_tokens);
    while (NULL != tmp)
    {
        if (false == _np_aaatoken_is_valid(tmp->val, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->val->issuer);
        }
        else
        {
            bool include_token = true;
            
            if (audience != NULL && strlen(audience) > 0) {
                include_token =
                        (strncmp(audience, tmp->val->issuer, strlen(tmp->val->issuer)) == 0) |
                        (strncmp(audience, tmp->val->realm, strlen(tmp->val->realm)) == 0) ;
            }

            if (include_token==true) {
                log_debug_msg(LOG_DEBUG, "found valid sender token (%s)", tmp->val->issuer );
                // only pick key from a list if the subject msg_treshold is bigger than zero
                // and the sending threshold is bigger than zero as well
                // and we actually have a receiver node in the list
                np_ref_obj(np_aaatoken_t, tmp->val);
                sll_append(np_aaatoken_ptr, return_list, tmp->val);
            } 
            else
            {
                log_debug_msg(LOG_DEBUG, "ignoring sender token for issuer %s as it is not in audience \"%s\"", tmp->val->issuer, audience);
            }
        }
        pll_next(tmp);
    }
    log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_all_sender %d", pll_size(ledger->send_tokens));

    return (return_list);
}

sll_return(np_aaatoken_ptr) _np_intent_get_all_receiver(np_key_t* subject_key, const char* const audience)
{
    np_ctx_memory(subject_key);

    sll_init_full(np_aaatoken_ptr, return_list);
    NP_CAST(sll_last(subject_key->entities)->val, struct __np_token_ledger, ledger);

    pll_iterator(np_aaatoken_ptr) tmp = pll_first(ledger->recv_tokens);
    while (NULL != tmp)
    {
        if (false == _np_aaatoken_is_valid(tmp->val, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_DEBUG, "ignoring receiver msg token as it is invalid" );
        }
        else
        {
            bool include_token = true;
            if (audience != NULL && strlen(audience) > 0) {
                include_token =
                        (strncmp(audience, tmp->val->issuer, strlen(tmp->val->issuer)) == 0) |
                        (strncmp(audience, tmp->val->realm, strlen(tmp->val->realm)) == 0) ;
            }

            if (include_token==true) {
                log_debug_msg(LOG_DEBUG, "found valid receiver token (%s)", tmp->val->issuer );
                np_ref_obj(np_aaatoken_t, tmp->val);
                // only pick key from a list if the subject msg_treshold is bigger than zero
                // and the sending threshold is bigger than zero as well
                // and we actually have a receiver node in the list
                sll_append(np_aaatoken_ptr, return_list, tmp->val);
            } else {
                log_debug_msg(LOG_DEBUG, "ignoring receiver token for issuer %s as it is not in audience \"%s\"", tmp->val->issuer, audience);
            }
        }
        pll_next(tmp);
    }
    log_debug_msg(LOG_DEBUG, ".step2._np_aaatoken_get_all_receiver %d", pll_size(ledger->recv_tokens));

    return (return_list);
}

void _np_intent_propagate_list(np_state_t* context, np_dhkey_t msgprop_dhkey, np_dhkey_t target, const char* subject, np_sll_t(np_aaatoken_ptr, list_to_send)) 
{
    np_aaatoken_t * tmp_token;
    np_message_t * msg_out = NULL;

    sll_iterator(np_aaatoken_ptr) iter_list_to_send = sll_first(list_to_send);

    while (iter_list_to_send != NULL)
    {
        tmp_token = iter_list_to_send->val;
        sll_next(iter_list_to_send);

        np_dhkey_t tmp_token_issuer = np_aaatoken_get_partner_fp(tmp_token);
        // do not send the msgtoken to its own issuer (remove clutter)
        if (_np_dhkey_equal(&target, &tmp_token_issuer) == false)
        {
            np_tree_t* available_data = np_tree_create();
            np_aaatoken_encode(available_data, tmp_token);

            np_new_obj(np_message_t, msg_out);
            _np_message_create(
                msg_out,
                target,
                context->my_node_key->dhkey,
                subject,
                available_data
            );

            log_msg(LOG_INFO,
                    "discovery success: sending back %s (msg uuid: %s / intent token %s)",
                    subject, msg_out->uuid, tmp_token->uuid);

            np_util_event_t propagate_event = { .type=(evt_internal|evt_message), .context=context, .user_data=msg_out , .target_dhkey=target };
            _np_keycache_handle_event(context, msgprop_dhkey, propagate_event, false);
        }
    }
}

void _np_intent_propagate_receiver(np_key_t* intent_key, np_message_intent_public_token_t* sender_msg_token) 
{
    np_ctx_memory(intent_key);

    np_sll_t(np_aaatoken_ptr, available_list) = _np_intent_get_all_receiver(intent_key, NULL /* sender_msg_token->audience */);

    np_dhkey_t target_dhkey = np_aaatoken_get_partner_fp(sender_msg_token);
    np_dhkey_t available_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_AVAILABLE_RECEIVER);

    _np_intent_propagate_list(context, available_dhkey, target_dhkey, _NP_MSG_AVAILABLE_RECEIVER, available_list);
    
    np_aaatoken_unref_list(available_list, "_np_intent_get_all_receiver");
    sll_free(np_aaatoken_ptr, available_list);

    // TODO: deprecated
    // reason: any system should not be able to inflict traffic on peer nodes by sending message intents.
    // message intents already bear a danger of being misused for flooding the network
    // by just returning data to the sender the main conflict will be caused at the initiator of the traffic
    /*
    if(inform_counterparts){
        available_list = _np_aaatoken_get_all_sender(context, sender_msg_token->subject, sender_msg_token->audience);

        sll_iterator(np_aaatoken_ptr) iter_sender_tokens = sll_first(available_list);
        while (iter_sender_tokens != NULL)
        {
            np_tree_elem_t* target_ele = np_tree_find_str(iter_sender_tokens->val->extensions, "target_node");

            np_dhkey_t target_key;
            if (target_ele != NULL) {
                target_key = np_dhkey_create_from_hash(np_treeval_to_str(target_ele->val, NULL));
            }
            else {
                target_key = _np_aaatoken_get_issuer(iter_sender_tokens->val);
            }

            _np_dendrit_propagate_senders(target_key, sender_msg_token, false);
            sll_next(iter_sender_tokens);
        }

        np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_sender");
        sll_free(np_aaatoken_ptr, available_list);
    }
    */
}

void _np_intent_propagate_sender(np_key_t* intent_key, np_message_intent_public_token_t* receiver_msg_token)
{
    np_ctx_memory(intent_key);

    np_sll_t(np_aaatoken_ptr, available_list) = _np_intent_get_all_sender(intent_key, NULL /* receiver_msg_token->audience */ );

    np_dhkey_t target_dhkey = np_aaatoken_get_partner_fp(receiver_msg_token);
    np_dhkey_t available_dhkey = _np_msgproperty_dhkey(OUTBOUND, _NP_MSG_AVAILABLE_SENDER);

    _np_intent_propagate_list(context, available_dhkey, target_dhkey, _NP_MSG_AVAILABLE_SENDER, available_list);

    np_aaatoken_unref_list(available_list, "_np_intent_get_all_sender");
    sll_free(np_aaatoken_ptr, available_list);

    // TODO: deprecated
    // reason: any system should not be able to inflict traffic on peer nodes by sending message intents.
    // message intents already bear a danger of being misused for flooding the network
    // by just returning data to the sender the main conflict will be caused at the initiator of the traffic
    /*
    if (inform_counterparts) {
        available_list = _np_aaatoken_get_all_receiver(context, receiver_msg_token->subject, receiver_msg_token->audience);

        sll_iterator(np_aaatoken_ptr) iter_receiver_tokens = sll_first(available_list);
        while (iter_receiver_tokens != NULL)
        {

            np_tree_elem_t* target_ele = np_tree_find_str(iter_receiver_tokens->val->extensions, "target_node");

            np_dhkey_t target_key;
            if (target_ele != NULL) {
                target_key = np_dhkey_create_from_hash(np_treeval_to_str(target_ele->val, NULL));
            }
            else {
                target_key = _np_aaatoken_get_issuer(iter_receiver_tokens->val);
            }
            _np_dendrit_propagate_receivers(target_key, receiver_msg_token, false);
            sll_next(iter_receiver_tokens);
        }

        np_aaatoken_unref_list(available_list, "_np_aaatoken_get_all_receiver");
        sll_free(np_aaatoken_ptr, available_list);
    }
    */
}

bool __is_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_intent_token(...){");

    bool ret = false;
    
    // NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);

    if (!ret) ret  = (FLAG_CMP(event.type, evt_token) && FLAG_CMP(event.type, evt_external) );
    if ( ret) ret &= _np_memory_rtti_check(intent_token, np_memory_types_np_aaatoken_t);
    if ( ret) ret &= _np_aaatoken_is_valid(intent_token, np_aaatoken_type_message_intent);

    return ret;
} 

void __np_set_intent(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t,  my_intent_key);    
    log_debug_msg(LOG_TRACE, "start: void __np_set_intent(...) { %p", my_intent_key);

    _np_intent_create_token_ledger(my_intent_key, event);

    np_ref_obj(no_key_t, my_intent_key, "__np_set_intent");
    my_intent_key->type |= np_key_type_intent;

}

bool __is_receiver_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_receiver_intent_token(...){");

    bool ret = __is_intent_token(statemachine, event);

    np_dhkey_t receiver_intent_dhkey = np_dhkey_create_from_hostport(_NP_MSG_DISCOVER_SENDER, "0");
    ret &= _np_dhkey_equal(&event.target_dhkey, &receiver_intent_dhkey);

    return ret;
} 

bool __is_sender_intent_token(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __is_sender_intent_token(...){");

    bool ret = __is_intent_token(statemachine, event);

    np_dhkey_t sender_intent_dhkey = np_dhkey_create_from_hostport(_NP_MSG_DISCOVER_RECEIVER, "0");
    ret &= _np_dhkey_equal(&event.target_dhkey, &sender_intent_dhkey);

    return ret;
} 

// add intent token
void __np_intent_receiver_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_intent_receiver_update(...){");

    NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);

    // just store the available tokens in memory and update them if new data arrives
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "discovery: received new receiver token %s for %s", intent_token->uuid, intent_token->subject);

    np_aaatoken_t* old_token = _np_intent_add_receiver(intent_key, intent_token);
    np_unref_obj(np_aaatoken_t, old_token, "recv_tokens");

    _np_intent_propagate_sender(intent_key, intent_token);
} 

void __np_intent_sender_update(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: bool __np_intent_sender_update(...){");

    NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    NP_CAST(event.user_data, np_aaatoken_t, intent_token);
    // just store the available tokens in memory and update them if new data arrives
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "discovery: received new sender token %s for %s", intent_token->uuid, intent_token->subject);

    np_aaatoken_t* old_token = _np_intent_add_sender(intent_key, intent_token);
    np_unref_obj(np_aaatoken_t, old_token, "send_tokens");

    _np_intent_propagate_receiver(intent_key, intent_token);
}

bool __is_intent_authn(np_util_statemachine_t* statemachine, const np_util_event_t event) {}

bool __is_intent_authz(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{
    np_ctx_memory(statemachine->_user_data);
    log_debug_msg(LOG_TRACE, "start: void __is_intent_authz(...){");

    bool ret = false;
    NP_CAST(statemachine->_user_data, np_key_t, my_identity_key);
    
    if (!ret) ret  = FLAG_CMP(event.type, evt_authz);
    if ( ret) ret &= (FLAG_CMP(event.type, evt_external) && FLAG_CMP(event.type, evt_token) );
    if ( ret) ret &= (np_memory_get_type(event.user_data) == np_memory_types_np_aaatoken_t);
    if ( ret) {
        NP_CAST(event.user_data, np_aaatoken_t, token);
        ret &= FLAG_CMP(token->type, np_aaatoken_type_message_intent);
        ret &= _np_aaatoken_is_valid(token, token->type);
    }
    return ret;
}


void __np_intent_update(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // add authorization for intent token

bool __is_intent_invalid(np_util_statemachine_t* statemachine, const np_util_event_t event) {}
void __np_intent_destroy(np_util_statemachine_t* statemachine, const np_util_event_t event) {} // no updates received for xxx minutes?

void __np_intent_check(np_util_statemachine_t* statemachine, const np_util_event_t event) 
{    
    np_ctx_memory(statemachine->_user_data);

    NP_CAST(statemachine->_user_data, np_key_t, intent_key);
    if (intent_key->entities == NULL) return;
    if (sll_size(intent_key->entities) < 2) return;

    NP_CAST(sll_last(intent_key->entities)->val, struct __np_token_ledger, ledger);
    
    if (ledger == NULL) return;
    pll_iterator(np_aaatoken_ptr) iter = NULL;

    // check for outdated sender token
    iter = pll_first(ledger->send_tokens);
    while (NULL != iter)
    {
        np_aaatoken_t* tmp_token = iter->val;
        pll_next(iter);

        if (NULL  != tmp_token &&
            false == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_DEBUG, "deleting old / invalid sender msg tokens %p", tmp_token);
            pll_remove(np_aaatoken_ptr, ledger->send_tokens, tmp_token, _np_intent_cmp_exact);
            np_unref_obj(np_aaatoken_t, tmp_token, "send_tokens");
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
            false == _np_aaatoken_is_valid(tmp_token, np_aaatoken_type_message_intent))
        {
            log_debug_msg(LOG_DEBUG, "deleting old / invalid receiver msg token %p", tmp_token);
            pll_remove(np_aaatoken_ptr, ledger->recv_tokens, tmp_token, _np_intent_cmp_exact);
            np_unref_obj(np_aaatoken_t, tmp_token, "recv_tokens");
            break;
        }
    }
} 

// TODO: send out intents if dht distance is not mmatching anymore
