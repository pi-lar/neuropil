//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include <inttypes.h>
#include <unistd.h>

#include "sodium.h"

#include "neuropil.h"
#include "neuropil_data.h"
#include "np_data.h"
#include "neuropil_attributes.h"
#include "np_attributes.h"


#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "core/np_comp_intent.h"
#include "util/np_event.h"


#include "np_aaatoken.h"
#include "np_attributes.h"
#include "np_bootstrap.h"
#include "np_dhkey.h"
#include "np_event.h"
#include "np_jobqueue.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "neuropil_log.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_network.h"
#include "np_route.h"
#include "np_serialization.h"
#include "np_statistics.h"
#include "np_shutdown.h"
#include "np_threads.h"
#include "np_time.h"
#include "np_token_factory.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"
#include "np_types.h"
#include "np_util.h"



static const char *error_strings[] = {
    "",
    "unknown error cause",
    "operation is not implemented",
    "could not init network",
    "argument is invalid",
    "operation is currently invalid",
    "insufficient memory",
    "startup error. See log for more details"
};
const char *np_error_str(enum np_return e) {
    if (e > 0)
        return error_strings[e];
    else
        return NULL;
}

// split into hash 
void np_get_id(np_id (*id), const char* string, NP_UNUSED size_t length) {
    // np_ctx_cast(ac);
     
    np_dhkey_t  dhkey = np_dhkey_create_from_hostport(string, "0");
    memcpy(id, &dhkey, NP_FINGERPRINT_BYTES);
}

struct np_settings * np_default_settings(struct np_settings * settings) {
    struct np_settings * ret;
    if (settings == NULL) {
        ret = malloc(sizeof(struct np_settings));
    }
    else {
        ret = settings;
    }
    ret->n_threads = 5;
    snprintf(ret->log_file, 256, "%.0f_neuropil.log",_np_time_now(NULL)*100);
    ret->log_level = LOG_ERROR;
    ret->log_level |= LOG_WARN;
    ret->log_level |= LOG_INFO;

    ret->leafset_size = 16;

#ifdef DEBUG
    ret->log_level |= LOG_DEBUG;    
//    ret->log_level |= LOG_VERBOSE;    
    ret->log_level |= LOG_MESSAGE|LOG_ROUTING|LOG_MISC;
#endif

    return ret;
}

np_context* np_new_context(struct np_settings * settings_in)
{
    enum np_return status = np_ok;
    np_state_t* context = NULL;

    struct np_settings * settings = settings_in;
    if (settings_in == NULL) {
        settings = np_default_settings(NULL);
    }

    //TODO: check settings for bad configuration
    context = (np_state_t *)calloc(1, sizeof(np_state_t));
    CHECK_MALLOC(context);

    context->settings = settings;

    MAP(np_module_init_null, NP_CTX_MODULES);

    if (sodium_init() == -1) {
        log_msg(LOG_ERROR, "neuropil_init: could not init crypto library");
        status = np_startup;
    }
    else if (_np_statistics_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: could not init statistics");
        status = np_startup;
    }
    else if (_np_threads_init(context) == false) {
        log_msg(LOG_ERROR, "neuropil_init: could not init threading mutexes");
        status = np_startup;
    }
    else if (_np_event_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: could not init event system");
        status = np_startup;
    }
    else if (_np_log_init(context, settings->log_file, settings->log_level) == false) {
        log_msg(LOG_ERROR, "neuropil_init: could not init logging");
        status = np_startup;       
    }
    else if (_np_memory_init(context) == false) {
        log_msg(LOG_ERROR, "neuropil_init: could not init memory");
        status = np_startup;
    }
    else if (_np_time_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: could not init time cache");
        status = np_startup;
    }
    else if (_np_dhkey_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: could not init distributed hash table");
        status = np_startup;
    }
    else if (_np_keycache_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: _np_keycache_init failed");
        status = np_startup;
    }
    else if (_np_msgproperty_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: _np_msgproperty_init failed");
        status = np_startup;
    }
    else if (_np_attributes_init(context) == false)
    {
        log_msg(LOG_ERROR, "neuropil_init: _np_attributes_init failed");
        status = np_startup;
    }
    else {
        np_thread_t * new_thread =
            __np_createThread(context, 0, NULL, false, np_thread_type_main);
        new_thread->id = (unsigned long)getpid();
        _np_threads_set_self(new_thread);

        // set default aaa functions
        np_set_authorize_cb(context, _np_default_authorizefunc);
        np_set_accounting_cb(context, _np_default_accountingfunc);
        np_set_authenticate_cb(context, _np_default_authenticatefunc);

        context->enable_realm_client = false;
        context->enable_realm_server = false;

        // initialize message part handling cache
        context->msg_part_cache  = np_tree_create();
        struct np_bloom_optable_s decaying_op = {
            .add_cb = _np_decaying_bloom_add,
            .check_cb = _np_decaying_bloom_check,
            .clear_cb = _np_standard_bloom_clear,
        };
        context->msg_part_filter = _np_decaying_bloom_create(1024, 8, 1);
        context->msg_part_filter->op = decaying_op;

        _np_log_rotate(context, true);
    }

    TSP_INITD(context->status, np_uninitialized);
    if (status == np_ok) {
        TSP_SET(context->status, np_stopped);
    }
    else  {
        TSP_SET(context->status, np_error);
    }
    return ((np_context*)context);
}

bool __np_is_already_listening(np_state_t* context)
{
    return (context->my_node_key != NULL);
}


enum np_return _np_listen_safe(np_context* ac, char* protocol, char* host, uint16_t port)
{
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    TSP_GET(enum np_status, context->status, context_status);

    if (__np_is_already_listening(context)) 
    {
        log_msg(LOG_ERROR, "node listens already and cannot get a second listener");
        ret = np_invalid_operation;
    }
    else if (context_status != np_stopped) 
    {
        log_msg(LOG_ERROR, "node is not in stopped state and cannot start propertly");
        ret = np_invalid_operation;
    }
    else 
    {
        char np_service[7];
        enum socket_type np_proto = UDP | IPv6;

        snprintf(np_service, 7, "%"PRIu16, port);

        if (NULL != protocol)
        {
            np_proto = _np_network_parse_protocol_string(protocol);
            if (np_proto == UNKNOWN_PROTO) {
                ret = np_invalid_argument;
            }
            else {
                log_debug_msg(LOG_DEBUG, "now initializing networking for %s:%s", protocol, np_service);
            }
        }
        else
        {
            log_debug_msg(LOG_DEBUG, "now initializing networking for udp6://%s", np_service);
        }

        if (ret == np_ok) {
            log_debug_msg(LOG_DEBUG, "building network base structure");
            // np_network_t* my_network = NULL;
            // np_new_obj(np_network_t, my_network);
            // get public / local network interface id
            char np_host[255];			
            bool has_host = true;
            if (NULL == host && port != 0) {
                log_msg(LOG_INFO, "neuropil_init: resolve hostname");
                // if (np_get_local_ip(context, np_host, 255) == false) {
                if (0 != gethostname(np_host, 255)) {
                    strncpy(np_host,"localhost",255);
                }
                // }
            } else if (NULL != host) {
                strncpy(np_host, host, 255);
            } else {
                has_host = false;
            }

            np_aaatoken_t* node_token = _np_token_factory_new_node_token(context, np_proto, np_host, np_service);
            _np_set_identity(context, node_token);
            
            // initialize routing table
            if (_np_route_init(context, context->my_node_key)== false)
            {
                log_msg(LOG_ERROR, "neuropil_init: route_init failed: %s", strerror(errno));
                ret = np_startup;
            }
            else if (_np_jobqueue_init(context) == false)
            {
                log_msg(LOG_ERROR, "neuropil_init: _np_jobqueue_init failed: %s", strerror(errno));
                ret = np_startup;
            }
            else if (_np_bootstrap_init(context)== false)
            {
                log_msg(LOG_ERROR, "neuropil_init: _np_bootstrap_init failed: %s", strerror(errno));
                ret = np_startup;
            }
            else if (!_np_statistics_enable(context))
            {
                log_msg(LOG_ERROR, "neuropil_init: could not enable statistics");
                ret = np_startup;
            }
            else
            {
                _np_shutdown_init(context);
                np_threads_start_workers(context, context->settings->n_threads);
                TSP_SET(context->status, np_stopped);

                log_msg(LOG_INFO, "neuropil successfully initialized: id:   %s", _np_key_as_str(context->my_identity));
                log_msg(LOG_INFO, "neuropil successfully initialized: node: %s", _np_key_as_str(context->my_node_key));
                _np_log_fflush(context, true);
            }
        }
        if (ret != np_ok)
        {
            TSP_SET(context->status, np_error);
        }
    }

    return ret;
}

enum np_return np_listen(np_context* ac, const char* protocol, const char* host, uint16_t port) {
    char * safe_protocol = protocol ? strndup(protocol,5) : NULL;
    char * safe_host = host ? strndup(host,200) : NULL;
    enum np_return ret =  _np_listen_safe(ac, safe_protocol, safe_host,port) ;
    free(safe_host);
    free(safe_protocol);
    return ret;
}

// secret_key is nullable
struct np_token np_new_identity(np_context* ac, double expires_at, unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]) {
    np_ctx_cast(ac); 
    
    struct np_token ret = {0};	
    np_ident_private_token_t* new_token =  np_token_factory_new_identity_token(context, expires_at, secret_key);
    np_aaatoken4user(&ret, new_token);

#ifdef DEBUG
    char tmp[65] = { 0 };
    np_dhkey_t d = np_aaatoken_get_fingerprint(new_token, false);
    np_id_str(tmp, *(np_id*)&d);
    log_debug_msg(LOG_AAATOKEN, "created new ident token %s (fp:%s)", ret.uuid, tmp);
#endif

    np_unref_obj(np_aaatoken_t, new_token, "np_token_factory_new_identity_token");
    return ret;
}

enum np_return np_node_fingerprint(np_context* ac, np_id (*id))
{
  np_ctx_cast(ac); 
    enum np_return ret = np_ok;
   
    if(id == NULL) {
        ret = np_invalid_argument;
    }
    else {
        np_dhkey_t fp = np_aaatoken_get_fingerprint(_np_key_get_token(context->my_node_key), false);
        memcpy(id, &fp , NP_FINGERPRINT_BYTES);
    }
    return ret;
 
}

enum np_return np_sign_identity(np_context* ac, struct np_token* identity, bool self_sign)
{
    np_ctx_cast(ac);

    enum np_return ret = np_ok;
    if(identity == NULL) {
        ret = np_invalid_argument;
    } else {
        np_ident_private_token_t* id_token = NULL;
        if (self_sign) {
            id_token = np_token_factory_new_identity_token(context, identity->expires_at, &identity->secret_key);
            np_user4aaatoken(id_token, identity);
            _np_aaatoken_set_signature(id_token, NULL);
        } else {
            id_token = np_token_factory_new_identity_token(context, 20.0, NULL);
            np_user4aaatoken(id_token, identity);
            _np_aaatoken_set_signature(id_token, _np_key_get_token(context->my_identity) );
        }
        _np_aaatoken_update_attributes_signature(id_token);
        np_aaatoken4user(identity, id_token);

        np_unref_obj(np_aaatoken_t, id_token, "np_token_factory_new_identity_token");
    }
    return ret;
}

enum np_return np_token_fingerprint(np_context* ac, struct np_token identity, bool include_attributes, np_id (*id))
{
    np_ctx_cast(ac); 

    enum np_return ret = np_ok;
    if(id == NULL) {
        ret = np_invalid_argument;
    }
    else {
        // np_ident_private_token_t* imported_token = np_token_factory_new_identity_token(ac,  identity.expires_at, &identity.secret_key);
        np_ident_private_token_t* imported_token = np_token_factory_new_identity_token(ac,  identity.expires_at, NULL);
        np_user4aaatoken(imported_token, &identity);

        np_dhkey_t fp = np_aaatoken_get_fingerprint(imported_token, include_attributes);

		memcpy(id, &fp, NP_FINGERPRINT_BYTES);
        np_unref_obj(np_aaatoken_t, imported_token, "np_token_factory_new_identity_token");
    }

    return ret;
}

enum np_return np_use_identity(np_context* ac, struct np_token identity) {
    np_ctx_cast(ac);

    TSP_GET(enum np_status, context->status, state);
    if (state == np_running) return np_invalid_operation;

    log_debug_msg(LOG_AAATOKEN, "importing ident token %s", identity.uuid);

    np_ident_private_token_t* imported_token = np_token_factory_new_identity_token(ac,  identity.expires_at, &identity.secret_key);

    np_user4aaatoken(imported_token, &identity);
    _np_aaatoken_set_signature(imported_token, NULL);

    _np_set_identity(context, imported_token);
    _np_aaatoken_update_attributes_signature(imported_token);
    log_msg(LOG_INFO, "neuropil successfully initialized: id:   %s", _np_key_as_str(context->my_identity));
    return np_ok;
}

enum np_return np_get_address(np_context* ac, char* address, uint32_t max) {
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    char* str = np_get_connection_string_from(context->my_node_key, true);
    if (strlen(str) > max) {
        ret = np_invalid_argument;
    }
    else {
        strncpy(address, str, max);
    }
    free(str);

    return ret;
}

bool np_has_joined(np_context* ac) 
{
    assert(ac != NULL);
    bool ret = false;
    np_ctx_cast(ac);

    if (_np_route_my_key_has_connection(context) && 
        context->my_node_key != NULL && 
        _np_key_get_node(context->my_node_key) != NULL) 
    {
        ret = _np_key_get_node(context->my_node_key)->joined_network;
    }

    return ret;
}

bool np_has_receiver_for(np_context*ac, const char * subject)
{
    assert(ac != NULL);
    assert(subject != NULL);

    np_ctx_cast(ac);
    bool ret = false;

    np_dhkey_t prop_dhkey = _np_msgproperty_dhkey(OUTBOUND, subject);
    np_key_t*  prop_key   = _np_keycache_find(context, prop_dhkey);

    np_sll_t(np_aaatoken_ptr, receiver_list);
    sll_init(np_aaatoken_ptr, receiver_list);

    np_dhkey_t null_dhkey = {0};
    _np_intent_get_all_receiver(prop_key, null_dhkey, &receiver_list);

    if (sll_size(receiver_list) > 0) ret = true;

    np_aaatoken_unref_list(receiver_list, "_np_intent_get_all_receiver");
    sll_free(np_aaatoken_ptr, receiver_list);
    np_unref_obj(np_key_t, prop_key, "_np_keycache_find");

    return ret;
}

enum np_return np_join(np_context* ac, const char* address) 
{
  enum np_return ret = np_ok;
  np_ctx_cast(ac);
  TSP_GET(enum np_status,context->status,context_status);
  if (address == NULL)             return np_invalid_argument;
  if (strnlen(address,500) <=  10) return np_invalid_argument;
  if (strnlen(address,500) >= 500) return np_invalid_argument;
  if (context_status != np_running) return np_invalid_operation;
  // char *nts = memchr(address,'\0', strnlen(address, 500));
  // if (nts == NULL) return np_invalid_argument;
  char* safe_address = strndup(address, 500);
  np_send_join(context, safe_address);
  free(safe_address);
  return ret;
}

enum np_return np_send(np_context* ac, const char* subject, const unsigned char* message, size_t length) 
{

	if (subject == NULL) return np_invalid_argument;
	if (strnlen(subject,500) == 0) return np_invalid_argument;

	char* safe_subject = strndup(subject,255);
    enum np_return ret = np_send_to(ac, safe_subject, message, length, NULL);

    free(safe_subject);
    return ret;
}

enum np_return np_send_to(np_context* ac, const char* subject, const unsigned char* message, size_t length, np_id (*target)) 
{
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    np_tree_t* body = np_tree_create();
    np_tree_insert_str(body, NP_SERIALISATION_USERDATA, np_treeval_new_bin((void*) message, length));


    np_attributes_t tmp_msg_attr;
    if( np_ok == np_init_datablock(tmp_msg_attr,sizeof(tmp_msg_attr))){
        np_merge_data(tmp_msg_attr,_np_get_attributes_cache(context, NP_ATTR_USER_MSG));
        np_merge_data(tmp_msg_attr,_np_get_attributes_cache(context, NP_ATTR_IDENTITY_AND_USER_MSG));
        np_merge_data(tmp_msg_attr,_np_get_attributes_cache(context, NP_ATTR_INTENT_AND_USER_MSG));
        size_t attributes_size;
        if(np_ok == np_get_data_size(tmp_msg_attr, &attributes_size) && attributes_size > 0){
            np_tree_insert_str(body, NP_SERIALISATION_ATTRIBUTES, np_treeval_new_bin(tmp_msg_attr, attributes_size));
        }
    }

    np_dhkey_t subject_dhkey = _np_msgproperty_dhkey(OUTBOUND, subject);
    np_dhkey_t target_dhkey = {0};
    if (target != NULL) {
        // TOOD: id to dhkey
    }
    // make sure that an outbound msgproperty exists
    np_msgproperty_t* prop = _np_msgproperty_get_or_create(ac, INBOUND | OUTBOUND, subject);

    np_message_t* msg_out = NULL;
    np_new_obj(np_message_t, msg_out, ref_message_in_send_system);
    _np_message_create(msg_out, subject_dhkey, context->my_node_key->dhkey, subject, body);

    log_msg(LOG_INFO, "sending message (size: %"PRIu16" msg: %s)", length, msg_out->uuid);

    np_util_event_t send_event = { .type=(evt_internal | evt_message), .context=ac, .user_data=msg_out, .target_dhkey=target_dhkey };
    // _np_keycache_handle_event(context, subject_dhkey, send_event, false);

    if(!np_jobqueue_submit_event(context, 0.0, subject_dhkey, send_event, "event: userspace message delivery request")){
        log_msg(LOG_WARN, "rejecting possible sending of message, please check jobqueue settings!");
    }

    return ret;
}

bool __np_receive_callback_converter(np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata)
{
    np_ctx_cast(ac);
    bool ret = true;
    np_receive_callback callback = localdata;
    np_tree_elem_t* userdata = np_tree_find_str(body, NP_SERIALISATION_USERDATA);

    if (userdata != NULL) {
        struct np_message message = { 0 };
        strncpy(message.uuid, msg->uuid, NP_UUID_BYTES-1);
        np_get_id(&message.subject, _np_message_get_subject(msg), strlen(_np_message_get_subject(msg)));

        ASSERT(msg->decryption_token != NULL,"The decryption token should never be empty in this stage");
        np_dhkey_t _t ;
        np_str_id(&_t,msg->decryption_token->issuer);
        memcpy(&message.from, &_t, NP_FINGERPRINT_BYTES);

        message.received_at = np_time_now(); // todo get from network
        //message.send_at = msg.             // todo get from msg
        message.data = userdata->val.value.bin;
        message.data_length = userdata->val.size;


        np_tree_elem_t* msg_attributes = np_tree_find_str(body, NP_SERIALISATION_ATTRIBUTES);
        if(msg_attributes == NULL){
            np_init_datablock(message.attributes,sizeof(message.attributes));
        }else{

            np_datablock_t * dt = msg_attributes->val.value.bin;
            // size_t attr_size;
            if(sizeof(message.attributes) >= msg_attributes->val.size) {
                memcpy(message.attributes, dt, msg_attributes->val.size);
            }
        }
        log_debug(LOG_MESSAGE | LOG_VERBOSE,"(msg: %s) conversion into public structs complete.", msg->uuid);
        log_debug(LOG_MESSAGE | LOG_VERBOSE,"(msg: %s) Calling user function.", msg->uuid);
        callback(context, &message);
        log_debug(LOG_MESSAGE | LOG_VERBOSE,"(msg: %s) Called  user function.", msg->uuid);
    }else{
        log_info(LOG_MESSAGE |LOG_ROUTING,"(msg: %s) contains no userdata", msg->uuid);
    }
    return ret;
}

enum np_return np_add_receive_cb(np_context* ac, const char* subject, np_receive_callback callback)
{
    enum np_return ret = np_ok;
    np_ctx_cast(ac);
    log_debug(LOG_MISC, "np_add_receive_cb %s", subject);

    char* safe_subject = strndup(subject,255);
    np_add_receive_listener(ac, __np_receive_callback_converter, callback, safe_subject);
    free(safe_subject);
    return ret;
}

enum np_return np_set_authenticate_cb(np_context* ac, np_aaa_callback callback) {
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    context->authenticate_func = callback;

    return ret;
}

enum np_return np_set_authorize_cb(np_context* ac, np_aaa_callback callback) {
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    context->authorize_func = callback;

    return ret;
}

enum np_return np_set_accounting_cb(np_context* ac, np_aaa_callback callback)
{
    enum np_return ret = np_ok;
    np_ctx_cast(ac);

    context->accounting_func = callback;

    return ret;
}

struct np_mx_properties np_get_mx_properties(np_context* ac, const char* subject) 
{
    np_ctx_cast(ac);
    struct np_mx_properties ret = { 0 };

    np_msgproperty_t* property = _np_msgproperty_get_or_create(context, DEFAULT_MODE, subject);

    np_msgproperty4user(&ret, property);

    return ret;
}

enum np_return np_set_mx_properties(np_context* ac, const char* subject, struct np_mx_properties user_property) 
{
    np_ctx_cast(ac);
    enum np_return ret = np_ok;
    
    // TODO: validate user_property
    struct np_mx_properties safe_user_property = user_property;
    safe_user_property.reply_subject[254] = 0;
 
    np_msgproperty_t* property = _np_msgproperty_get_or_create(context, DEFAULT_MODE, subject);
    np_msgproperty_from_user(context, property, &safe_user_property);

    return ret;
}

enum np_return np_mx_properties_enable(np_context* ac, const char* subject) 
{
    np_ctx_cast(ac);
    enum np_return ret = np_ok;
    
    np_msgproperty_t* property = _np_msgproperty_get(context, DEFAULT_MODE, subject);
    np_dhkey_t property_dhkey = _np_msgproperty_dhkey(DEFAULT_MODE, subject);
    np_util_event_t enable_event = { .type=(evt_enable | evt_internal | evt_property), .context=ac, .user_data=property, .target_dhkey=property_dhkey };
    _np_keycache_handle_event(ac, property_dhkey, enable_event, false);
    return ret;
}

enum np_return np_mx_properties_disable(np_context* ac, const char* subject) 
{
    np_ctx_cast(ac);
    enum np_return ret = np_ok;
    
    np_msgproperty_t* property = _np_msgproperty_get(context, DEFAULT_MODE, subject);
    np_dhkey_t property_dhkey = _np_msgproperty_dhkey(DEFAULT_MODE, subject);
    np_util_event_t enable_event = { .type=(evt_disable | evt_internal | evt_property), .context=ac, .user_data=property, .target_dhkey=property_dhkey };
    _np_keycache_handle_event(ac, property_dhkey, enable_event, false);

    return ret;
}

enum np_return np_run(np_context* ac, double duration) {
    np_ctx_cast(ac);
    enum np_return ret = np_ok;
    np_thread_t * thread = _np_threads_get_self(context);
    
    if (!__np_is_already_listening(context)) 
    {
        ret = np_listen(ac, _np_network_get_protocol_string(context, PASSIVE | IPv4), "localhost", 31415);
    }

    TSP_GET(enum np_status, context->status, context_status);
    if (context_status == np_shutdown) ret = np_invalid_operation;

    if(ret == np_ok) 
    {
        TSP_SET(context->status, np_running);
    
        if (duration <= 0) 
        {
            np_threads_busyness(context, thread, true);
            __np_jobqueue_run_jobs_once(context, thread);
            np_threads_busyness(context, thread, false);
        }
        else 
        {
            np_jobqueue_run_jobs_for(context, thread, duration);
        }
    }
    return ret;
}

enum np_return np_add_shutdown_cb(np_context* ac, np_callback callback) 
{
    np_ctx_cast(ac);
    np_shutdown_add_callback(ac, (np_destroycallback_t) callback);
}

void np_set_userdata(np_context *ac, void* userdata) {
    np_ctx_cast(ac);
    context->userdata = userdata;
}

void* np_get_userdata(np_context *ac) {
    np_ctx_cast(ac);
    return context->userdata;
}

enum np_status np_get_status(np_context* ac) {
    np_ctx_cast(ac);
    TSP_GET(enum np_status, context->status, ret);
    return ret;
}

char * np_id_str(char str[65], const np_id id)
{
    sodium_bin2hex(str, NP_FINGERPRINT_BYTES*2+1, id, NP_FINGERPRINT_BYTES);
    //ASSERT(r==0, "could not convert np_id to str code: %"PRId32, r);
    return str;
}

void np_str_id(np_id (*id), const char str[65])
{
    // TODO: this is dangerous, encoding could be different between systems,
    // encoding has to be send over the wire to be sure ...
    // for now: all tests on the same system
    //assert (64 == strnlen((char*) str,65));
    int r = sodium_hex2bin(*id, NP_FINGERPRINT_BYTES, str, NP_FINGERPRINT_BYTES*2, NULL, NULL, NULL);
    ASSERT(r==0, "could not convert str to np_id  code: %"PRId32, r);
}

void np_destroy(np_context* ac, bool gracefully)
{
    np_ctx_cast(ac);

    if (gracefully)
    {
        np_shutdown_add_callback(context, _np_shutdown_notify_others);
    }
    _np_shutdown_run_callbacks(context);

    np_util_event_t shutdown_event = { .type=(evt_shutdown|evt_internal), .context=ac, .user_data=NULL};
    if (context->my_node_key != NULL ) 
    {
        shutdown_event.target_dhkey = context->my_node_key->dhkey;
        _np_keycache_handle_event(context, context->my_node_key->dhkey, shutdown_event, true);
    }
    if (context->my_identity != NULL && 
        context->my_identity != context->my_node_key) 
    {
        shutdown_event.target_dhkey=context->my_identity->dhkey;
        _np_keycache_handle_event(context, context->my_identity->dhkey, shutdown_event, true);
    }
    _np_log_fflush(context, true);

    // verify all other threads are stopped
    TSP_SET(context->status, np_stopped);

    // destroy modules
    // _np_sysinfo_destroy_cache(context);
    _np_shutdown_destroy(context);    
    _np_bootstrap_destroy(context);

    np_threads_shutdown_workers(context);

    TSP_SET(context->status, np_shutdown);

    _np_jobqueue_destroy(context);
    _np_time_destroy(context);
     
    // sodium_destroy() /* not available */
    _np_route_destroy(context);
    // _np_keycache_destroy(context);            
    _np_event_destroy(context);    
    _np_dhkey_destroy(context);
    _np_msgproperty_destroy(context);        
    _np_statistics_destroy(context);            
    _np_memory_destroy(context);    
    _np_threads_destroy(context);
    _np_log_destroy(context);

    np_tree_free(context->msg_part_cache);
    TSP_DESTROY(context->status);
    free(context);
}

bool np_id_equals(np_id first, np_id second) {
    return memcmp(first,second,sizeof(np_id))==0;
}
