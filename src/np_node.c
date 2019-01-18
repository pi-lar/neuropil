//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
/*
** $Id: host.c,v 1.14 2006/06/16 07:55:37 ravenben Exp $
**
** Matthew Allen
** description:
*/

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sodium.h"

#include "np_node.h"

#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_memory.h"

#include "np_tree.h"
#include "np_msgproperty.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_network.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_settings.h"
#include "np_constants.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);


void _np_node_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void*  node)
{
    log_trace_msg(LOG_TRACE, "start: void _np_node_t_new(void* node){");
    np_node_t* entry = (np_node_t *) node;

    _np_threads_mutex_init(context, &entry->lock,"node lock");
    _np_threads_mutex_init(context, &entry->latency_lock,"node latency lock");

    entry->dns_name = NULL;
    entry->protocol = 0;
    entry->port = 0;

    entry->session_key_is_set = false;

    entry->last_success = np_time_now();
    entry->success_win_index = 0;
    np_node_set_handshake(entry, np_handshake_status_Disconnected);

    entry->handshake_send_at = 0;
    entry->joined_network = false;	
    entry->handshake_priority = randombytes_random();

    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
        entry->success_win[i] = i%2;
    entry->success_avg = 0.5;
    
    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
        entry->latency_win[i] = 0.031415;
    entry->latency = 0.031415;
}

void _np_node_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* node)
{
    log_trace_msg(LOG_TRACE, "start: void _np_node_t_del(void* node){");
    np_node_t* entry = (np_node_t *) node;
    if (entry->dns_name) free (entry->dns_name);
    if (entry->port) free (entry->port);

    _np_threads_mutex_destroy(context, &entry->latency_lock);
    _np_threads_mutex_destroy(context, &entry->lock);
}

/** np_node_encode:
 ** encodes the #node# into a string, putting it in #s#, which has
 ** #len# bytes in it.
 **/
void _np_node_encode_to_str (char *s, uint16_t len, np_key_t* key)
{
    np_ctx_memory(key);
    snprintf (s, len, "%s:", _np_key_as_str(key));

    if (NULL != key->node->dns_name) {
        snprintf (s + strlen (s), len - strlen (s), "%s:", _np_network_get_protocol_string(context, key->node->protocol));
        snprintf (s + strlen (s), len - strlen (s), "%s:", key->node->dns_name);
        snprintf (s + strlen (s), len - strlen (s), "%s",  key->node->port);
    }
} 
void _np_node_encode_to_jrb (np_tree_t* data, np_key_t* node_key, bool include_stats)
{
    // np_ctx_memory(node_key);
    np_tree_insert_str( data, NP_SERIALISATION_NODE_PROTOCOL, np_treeval_new_ush(node_key->node->protocol));
    np_treeval_t dns_name;
    if (node_key->node->dns_name == NULL) {
        char tmp[255];
        dns_name = np_treeval_new_s(np_network_get_ip(node_key, tmp));
    }
    else {
        dns_name = np_treeval_new_s(node_key->node->dns_name);
    }
    np_tree_insert_str(data, NP_SERIALISATION_NODE_DNS_NAME, dns_name);
    np_treeval_t port;
    if (node_key->node->port == NULL) {
        char tmp[255];
        port = np_treeval_new_s(np_network_get_port(node_key, tmp));
    }
    else {
        port = np_treeval_new_s(node_key->node->port);
    }
    np_tree_insert_str(data, NP_SERIALISATION_NODE_PORT, port);

    np_tree_insert_str( data, NP_SERIALISATION_NODE_KEY, np_treeval_new_s(_np_key_as_str(node_key)));

    if (true == include_stats)
    {		
        np_tree_insert_str( data, NP_SERIALISATION_NODE_CREATED_AT, np_treeval_new_d(node_key->created_at));

        if(node_key->node != NULL){

            np_tree_insert_str( data, NP_SERIALISATION_NODE_SUCCESS_AVG,
                    np_treeval_new_f(node_key->node->success_avg));
            np_tree_insert_str( data, NP_SERIALISATION_NODE_LATENCY,
                    np_treeval_new_d(node_key->node->latency));
            np_tree_insert_str( data, NP_SERIALISATION_NODE_LAST_SUCCESS,
                    np_treeval_new_d(node_key->node->last_success));
        }
    }
}

/** np_node_decode
 * decodes a string into a node structure. This acts as a
 * np_node_get, and should be followed eventually by a np_node_release.
 *
 * Example: _np_node_decode_from_str("04436571312f73109f697851cfd0529a06ae66080dc9f07581f45526691d4290:udp4:example.com:1234");
 * The key always requires a 64 char hash value as first parameter
 **/
np_key_t* _np_node_decode_from_str (np_state_t* context, const char *key)
{
    assert (key != 0);

    char *key_dup = strndup(key, 255);
    assert (key_dup != NULL);

    uint16_t iLen = strlen(key);
    assert (iLen > 0);

    char     *s_hostkey = NULL;
    char     *s_hostproto = NULL;
    char     *s_hostname = NULL;
    char     *s_hostport = NULL;

    // key is mandatory element in string
    s_hostkey = strtok(key_dup, ":");
    // log_debug_msg(LOG_DEBUG, "node decoded, extracted hostkey %s", sHostkey);

    if (iLen > strlen(s_hostkey))
    {
        s_hostproto = strtok(NULL, ":");
        s_hostname  = strtok(NULL, ":");
        s_hostport  = strtok(NULL, ":");
    }

    // string encoded data contains key, eventually plus hostname and hostport
    // key string is mandatory !
    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "s_hostkey %s / %s : %s : %s", s_hostkey, s_hostproto, s_hostname, s_hostport);

    np_dhkey_t search_key = np_dhkey_create_from_hash(s_hostkey);
    np_key_t* node_key    = _np_keycache_find_or_create(context, search_key);


    enum socket_type proto = PASSIVE | IPv4;
    if(s_hostproto!=NULL)
    {	proto = _np_network_parse_protocol_string(s_hostproto);
    }

    if (NULL == node_key->node && NULL != s_hostname && NULL != s_hostport)
    {
        np_node_t* newnode;
        np_new_obj(np_node_t, newnode);
        _np_node_update(newnode, proto, s_hostname, s_hostport);
        np_ref_switch(np_node_t, node_key->node, ref_key_node, newnode);
        np_unref_obj(np_node_t, newnode,ref_obj_creation);
    }
    else {
        // overwrite hostname only if it is not set yet
        if (NULL != s_hostname && NULL != s_hostport && (NULL == node_key->node->dns_name || NULL == node_key->node->port)) {
            _np_node_update(node_key->node, proto, s_hostname, s_hostport);
        }
    }

    free (key_dup);

    ref_replace_reason(np_key_t, node_key, "_np_keycache_find_or_create", FUNC);

    return (node_key);
}

np_node_t* _np_node_decode_from_jrb(np_state_t* context,np_tree_t* data)
{
    // MANDATORY paramter
    enum socket_type i_host_proto;
    char* s_host_name = NULL;
    char* s_host_port = NULL;
    np_tree_elem_t* ele;
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_PROTOCOL))) {
        i_host_proto = ele->val.value.ush;
    }
    else { return NULL; }

    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_DNS_NAME))) {
        s_host_name = np_treeval_to_str(ele->val, NULL);
    }
    else { return NULL; }

    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_PORT))) {
        s_host_port = np_treeval_to_str(ele->val, NULL);
    }
    else { return NULL; }

    np_node_t* new_node = NULL;
    np_new_obj(np_node_t, new_node);

    if (NULL != s_host_name &&
        NULL == new_node->dns_name)
    {
        // uint8_t proto = _np_network_parse_protocol_string(s_host_proto);
        _np_node_update(new_node, i_host_proto, s_host_name, s_host_port);
        log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "decoded node from jrb %d:%s:%s",
            i_host_proto, s_host_name, s_host_port);
    }
    /*
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_LATENCY))) {
    new_node->latency = ele->val.value.d;
    }
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_SUCCESS_AVG))) {
    new_node->success_avg = ele->val.value.f;
    }
    */
    ref_replace_reason(np_node_t, new_node, ref_obj_creation, FUNC);

    return (new_node);
}

np_node_t* _np_node_from_token(np_handshake_token_t* token, np_aaatoken_type_e expected_type)
{
    np_ctx_memory(token);
    if (FLAG_CMP(token->type, expected_type) == false) {
        log_debug_msg(LOG_DEBUG, "## decoding node from token str: %s", token->subject);
        return NULL;
    }

    //snprintf(node_subject, 255, _NP_URN_NODE_PREFIX "%s:%s:%s",
    //	_np_network_get_protocol_string(source_node->protocol), source_node->dns_name, source_node->port);
    char* details = strndup(&token->subject[strlen(_NP_URN_NODE_PREFIX)], sizeof(token->subject) - strlen(_NP_URN_NODE_PREFIX));
    // char* detail_data = details;

    log_debug_msg(LOG_DEBUG, "#  decoding node from token str: %s", details);

    // MANDATORY paramter
    uint8_t i_host_proto = UNKNOWN_PROTO;
    char* s_host_proto = strtok(details, ":");
    char* s_host_name  = strtok(NULL,    ":");
    char* s_host_port  = strtok(NULL,    ":");

    if (s_host_proto != NULL) {
        i_host_proto = _np_network_parse_protocol_string(s_host_proto);
    } 
    if (i_host_proto == UNKNOWN_PROTO || s_host_name == NULL || s_host_port == NULL) {
        free(details);
        return NULL;
    }
    
    np_node_t* new_node = NULL;
    np_new_obj(np_node_t, new_node, FUNC);
     
    _np_node_update(new_node, i_host_proto, s_host_name, s_host_port);
    log_debug_msg(LOG_DEBUG, "decodeded node from token: %d/%s:%s",
                   i_host_proto, s_host_name, s_host_port);
       
    free(details);

    return (new_node);
}


uint16_t _np_node_encode_multiple_to_jrb (np_tree_t* data, np_sll_t(np_key_ptr, node_keys), bool include_stats)
{
    uint16_t j=0;
    np_key_t* current;

    sll_clone(np_key_ptr, node_keys, node_keys_to_encode)

    while(NULL != (current = sll_head(np_key_ptr, node_keys_to_encode)))
    {		
        if (current->node != NULL)
        {
            // np_ctx_memory(current);
            np_tree_t* node_jrb = np_tree_create();
            // log_debug_msg(LOG_DEBUG, "c: %p -> adding np_node to jrb", node);
            _np_node_encode_to_jrb(node_jrb, current, include_stats);

            np_tree_insert_int( data, j, np_treeval_new_tree(node_jrb));
            j++;
            np_tree_free( node_jrb);
        }
    }
    sll_free(np_key_ptr, node_keys_to_encode);
    return (j);
}

sll_return(np_key_ptr) _np_node_decode_multiple_from_jrb (np_state_t* context, np_tree_t* data)
{
    uint16_t nodenum = data->size;

    np_sll_t(np_key_ptr, node_list);
    sll_init(np_key_ptr, node_list);

    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (uint16_t i = 0; i < nodenum; i++)
    {
        np_tree_elem_t* node_data = np_tree_find_int(data, i);

        bool free_s_key = false;
        char* s_key = np_treeval_to_str(np_tree_find_str(node_data->val.value.tree, NP_SERIALISATION_NODE_KEY)->val,&free_s_key);
        np_dhkey_t search_key = np_dhkey_create_from_hash(s_key);
        if (free_s_key == true) {
            free(s_key);
        }
        np_key_t* node_key    = _np_keycache_find_or_create(context, search_key);
        if (NULL == node_key->node)
        {
            node_key->node = _np_node_decode_from_jrb(context, node_data->val.value.tree);
            ref_replace_reason(np_node_t, node_key->node, "_np_node_decode_from_jrb", ref_key_node);
        } 
        
        ref_replace_reason(np_key_t, node_key, "_np_keycache_find_or_create", FUNC);
        
        sll_append(np_key_ptr, node_list, node_key);
    }
    return (node_list);
}

np_key_t* _np_key_create_from_token(np_aaatoken_t* token)
{
    np_ctx_memory(token);
    // TODO: check whether metadata is used as a hash key in general
    np_dhkey_t search_key = np_aaatoken_get_fingerprint(token, false);
    np_key_t* node_key    = _np_keycache_find_or_create(context, search_key);
    
    if (NULL == node_key->node && token->extensions != NULL && token->extensions->size > 0){
    
        node_key->node = _np_node_decode_from_jrb(context, token->extensions);
        if(node_key->node != NULL){
            ref_replace_reason(
                np_node_t, node_key->node,
                "_np_node_decode_from_jrb",
                ref_key_node		
            );
        }
    }
    ref_replace_reason(
            np_key_t, node_key,
            "_np_keycache_find_or_create",
            FUNC
    );
    
    return (node_key);
}
int _np_node_cmp(np_node_t* a, np_node_t* b) {

    int ret = ( (a == NULL) || (b == NULL) );
    
    if (ret == 0) {
        ret = strcmp(a->dns_name, b->dns_name);
    }
    else {
        if (ret == 0) {
            ret = strcmp(a->port, b->port);
        }
        else {
            if (ret == 0) {
                ret = a->protocol == b->protocol;
            }
        }
    }
    return ret;
}


void _np_node_update (np_node_t* node, enum socket_type proto, char *hn, char* port)
{
    node->protocol = proto;

    char* old = node->dns_name;	
    node->dns_name = strndup (hn, strlen(hn));
    if (old)free(old);

     old = node->port; 
    node->port = strndup(port, strlen(port));
    if(old)free(old);
}


/** _np_node_update_stat:
 ** updates the responded rate to the host based on the NP_NODE_SUCCESS_WINDOW average
 **/
void _np_node_update_stat (np_node_t* node, bool responded)
{
    np_ctx_memory(node);
    float total = 0;
    np_ref_obj(np_node_t, node, "usage");
     {
        _LOCK_ACCESS(&node->lock) {

            node->success_win_index++;
            if (node->success_win_index == NP_NODE_SUCCESS_WINDOW)
                node->success_win_index = 0;

            node->success_win[node->success_win_index % NP_NODE_SUCCESS_WINDOW] = responded;

            for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
            {
                total += node->success_win[i];
            }
            node->success_avg = total / NP_NODE_SUCCESS_WINDOW;

            if (true == responded) node->last_success = np_time_now();
        }
        log_msg(LOG_INFO, "connection to node %s:%s success rate now: %1.2f (%2u / %2u)", node->dns_name, node->port, node->success_avg, node->success_win_index, node->success_win[node->success_win_index]);

        np_unref_obj(np_node_t, node,"usage");
    }
}

void _np_node_update_latency (np_node_t* node, double new_latency)
{
    np_ctx_memory(node);
    if (new_latency > 0.0)
    {
        np_ref_obj(np_node_t, node, "usage");
        {
            _LOCK_ACCESS(&node->latency_lock) {
                node->latency_win_index++;
                if (node->latency_win_index == NP_NODE_SUCCESS_WINDOW)
                    node->latency_win_index = 0;

                node->latency_win[node->latency_win_index % NP_NODE_SUCCESS_WINDOW] = new_latency;
                
                double total = 0.0;
                for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
                {
                    // log_debug_msg(LOG_DEBUG, "latency for node now: %1.1f / %1.1f ", total, node->latency_win[i]);
                    total += node->latency_win[i];
                }
                node->latency = total / NP_NODE_SUCCESS_WINDOW;
                log_msg(LOG_INFO, "connection to node node %s:%s latency      now: %1.3f (update with: %1.3f)",
                        node->dns_name, node->port, node->latency, new_latency);
                
            }
            np_unref_obj(np_node_t, node,"usage");
        }
    }
}

char* _np_node_get_dns_name (np_node_t* np_node)
{
    assert(np_node != NULL);
    return (np_node->dns_name);
}

char* _np_node_get_port (np_node_t* np_node)
{
    assert(np_node != NULL);
    return (np_node->port);
}

float _np_node_get_success_avg (np_node_t* np_node)
{
    assert(np_node != NULL);
    return (np_node->success_avg);
}

float _np_node_get_latency (np_node_t* np_node)
{
    assert(np_node != NULL);
    return (np_node->latency);
}

uint8_t _np_node_check_address_validity (np_node_t* np_node)
{
    assert(np_node != NULL);
    // assert(np_node->network != NULL);

    return (np_node->dns_name && np_node->port);
}

char * _np_node2str(np_node_t* self, char* buffer) {	
    snprintf(buffer, 500, "%s:%s/%s", _np_node_get_dns_name(self), _np_node_get_port(self), np_memory_get_id(self));
    return buffer;
}

void _np_node_set_handshake(np_node_t* self, enum np_handshake_status set_to, char* func, int line)
{
    np_ctx_memory(self);
    char tmp[500];
    log_debug_msg(LOG_HANDSHAKE, 
        "Setting handshake of node \"%s\" from \"%s\" to \"%s\" at \"%s:%d\"", 
        _np_node2str(self, tmp),
        np_handshake_status_str[self->_handshake_status], 
        np_handshake_status_str[set_to], 
        func, line
    );
    self->_handshake_status = set_to;	
}
