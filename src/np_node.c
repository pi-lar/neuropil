//
// neuropil is copyright 2016-2021 by pi-lar GmbH
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

#include "util/np_tree.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "np_dhkey.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_network.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_settings.h"
#include "np_constants.h"
#include "np_statistics.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_node_t);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_node_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_node_ptr);

void _np_node_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void*  node)
{
    log_trace_msg(LOG_TRACE, "start: void _np_node_t_new(void* node){");
    np_node_t* entry = (np_node_t *) node;

    entry->dns_name = NULL;
    entry->host_key = NULL;
    entry->protocol = 0;
    entry->port = 0;

    entry->session_key_is_set = false;

    entry->last_success = np_time_now();
    entry->success_win_index = 0;
    entry->_handshake_status = 0;

    entry->_joined_status = 0;
    entry->handshake_send_at = 0.0;
    entry->join_send_at = 0.0;
    entry->joined_network = false;	
    entry->handshake_priority = randombytes_random();

    entry->next_routing_table_update = 0.0;
    entry->is_in_routing_table = false;;
    entry->is_in_leafset = false;

    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
        entry->success_win[i] = i%2;
    entry->success_avg = 0.5;
    
    for (uint8_t i = 0; i < NP_NODE_SUCCESS_WINDOW; i++)
        entry->latency_win[i] = 0.01;
    entry->latency = 0.01;
}

void _np_node_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* node)
{
    log_trace_msg(LOG_TRACE, "start: void _np_node_t_del(void* node){");
    np_node_t* entry = (np_node_t *) node;
    if (entry->host_key) free (entry->host_key);
    if (entry->dns_name) free (entry->dns_name);
    if (entry->port) free (entry->port);
}

struct __node_from_string_s {
    char*     s_dhkey;
    char*     s_protocol;
    char*     s_hostname;
    char*     s_port;
};

struct __node_from_string_s __get_node_details_from_string(np_state_t* context, char * str, bool parse_dhkey){

    struct __node_from_string_s ret = {0};
    char* delimiter[3];

    // search last ':'
    delimiter[2] = strrchr(str,            ':');
    if (delimiter[2] == NULL) return ret;

    // search first two ':'
    delimiter[0] = strchr (str,            ':');
    if (delimiter[0] == NULL) return ret;
    delimiter[1] = strchr (delimiter[0]+1, ':');
    if (delimiter[1] == NULL) return ret;

    if (delimiter[0] == delimiter[1] || delimiter[1] == delimiter[2])
        return ret;

    // string encoded data contains dhkey, protocol, hostname and port
    // hostname could be an ip6 address (has additional ':' in it)
    ret.s_dhkey    = str;
    ret.s_protocol = delimiter[0]+1; *delimiter[0] = '\0';
    ret.s_hostname = delimiter[1]+1; *delimiter[1] = '\0';
    ret.s_port     = delimiter[2]+1; *delimiter[2] = '\0';
    
    log_debug_msg(LOG_DEBUG, "s_hostkey %s / %s / %s / %s", ret.s_dhkey, ret.s_protocol, ret.s_hostname, ret.s_port);

    return ret;
}

void _np_node_encode_to_jrb (np_tree_t* data, np_key_t* node_key, bool include_stats)
{
    np_node_t* node = _np_key_get_node(node_key);
    np_network_t* network = _np_key_get_network(node_key);
    
    np_tree_insert_str( data, NP_SERIALISATION_NODE_PROTOCOL, np_treeval_new_ui(node->protocol));

    np_treeval_t address;
    if (node->dns_name == NULL) {
        address = np_treeval_new_s(network->ip);
    }
    else 
    {
        address = np_treeval_new_s(node->dns_name);
    }
    np_tree_insert_str(data, NP_SERIALISATION_NODE_DNS_NAME, address);

    np_treeval_t port;
    if (node->port == NULL) 
    {
        port = np_treeval_new_s(network->port);
    }
    else 
    {
        port = np_treeval_new_s(node->port);
    }

    np_tree_insert_str(data, NP_SERIALISATION_NODE_PORT, port);
    np_tree_insert_str(data, NP_SERIALISATION_NODE_KEY, np_treeval_new_s(_np_key_as_str(node_key)));

    if (true == include_stats)
    {
        np_tree_insert_str( data, NP_SERIALISATION_NODE_CREATED_AT,   np_treeval_new_d(node_key->created_at));
        np_tree_insert_str( data, NP_SERIALISATION_NODE_LAST_SUCCESS, np_treeval_new_d(node->last_success));

        np_tree_insert_str( data, NP_SERIALISATION_NODE_SUCCESS_AVG,  np_treeval_new_f(node->success_avg));
        np_tree_insert_str( data, NP_SERIALISATION_NODE_LATENCY,      np_treeval_new_d(node->latency));
    }
}

/** np_node_decode
 * decodes a string into a node structure. This acts as a
 * np_node_get, and should be followed eventually by a np_node_release.
 *
 * Example: _np_node_decode_from_str("04436571312f73109f697851cfd0529a06ae66080dc9f07581f45526691d4290:udp4:example.com:1234");
 * The key always requires a 64 char hash value as first parameter
 **/
np_node_t* _np_node_decode_from_str (np_state_t* context, const char *key)
{
    assert (key != 0);

    char *key_dup = NULL, *to_parse = NULL;
    key_dup = to_parse = strndup(key, 255);
    assert (key_dup != NULL);

    log_debug_msg(LOG_DEBUG, "## now decoding node from key string: %s", key);

    uint16_t iLen = strlen(key);
    assert (iLen > 0);

    struct __node_from_string_s details = __get_node_details_from_string(context, to_parse, true);

    enum socket_type proto = UNKNOWN_PROTO;
    if(details.s_protocol != NULL)
    {
        proto = _np_network_parse_protocol_string(details.s_protocol);
    }

    if (FLAG_CMP(proto, UNKNOWN_PROTO) || details.s_hostname == NULL || details.s_port == NULL)
    {
        log_debug_msg(LOG_ERROR, "error decoding node from token str: %s / %s / %s / %s orginal: %s", details.s_dhkey, details.s_protocol, details.s_hostname, details.s_port,to_parse);
        free(to_parse);
        return NULL;
    }

    // key string is not mandatory, could be a wildcard
    np_dhkey_t _null_dhkey = {0};
    np_dhkey_t node_dhkey = np_dhkey_create_from_hash(details.s_dhkey);
    if (_np_dhkey_equal(&_null_dhkey, &node_dhkey)) {
        log_debug_msg(LOG_ERROR, "error decoding node from token str: %s / %s / %s / %s orginal: %s", details.s_dhkey, details.s_protocol, details.s_hostname, details.s_port,to_parse);
        details.s_dhkey[0] = '*';
        details.s_dhkey[1] = '\0';
    }

    log_debug_msg(LOG_DEBUG, "decoding result node from token str: %s / %s : %s : %s", details.s_dhkey, details.s_protocol, details.s_hostname, details.s_port);

    // string encoded data contains key, eventually plus hostname and hostport
    np_node_t* new_node;
    np_new_obj(np_node_t, new_node, FUNC);
    _np_node_update(new_node, proto, details.s_hostname, details.s_port);
    new_node->host_key = strndup(details.s_dhkey, 64);
    
    free (key_dup);
    return (new_node);
}

np_node_t* _np_node_decode_from_jrb(np_state_t* context,np_tree_t* data)
{
    // MANDATORY paramter
    enum socket_type i_host_proto;
    char* s_host_name = NULL;
    char* s_host_port = NULL;
    char* s_host_key  = NULL;

    np_tree_elem_t* ele;
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_PROTOCOL))) {
        i_host_proto = ele->val.value.ui;
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

    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_KEY))) {
        s_host_key = np_treeval_to_str(ele->val, NULL);
    } else {
        s_host_key = "*";
    }

    np_node_t* new_node = NULL;
    np_new_obj(np_node_t, new_node, FUNC);

    if (NULL != s_host_name &&
        NULL == new_node->dns_name)
    {
        // uint8_t proto = _np_network_parse_protocol_string(s_host_proto);
        _np_node_update(new_node, i_host_proto, s_host_name, s_host_port);
        new_node->host_key = strndup(s_host_key, 255); // strndup(s_host_key, 64);
        log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "decoded node from jrb %s:%d:%s:%s",
                      s_host_key, i_host_proto, s_host_name, s_host_port);
    }
    /*
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_LATENCY))) {
    new_node->latency = ele->val.value.d;
    }
    if (NULL != (ele = np_tree_find_str(data, NP_SERIALISATION_NODE_SUCCESS_AVG))) {
    new_node->success_avg = ele->val.value.f;
    }
    */
    // ref_replace_reason(np_node_t, new_node, ref_obj_creation, FUNC);

    return (new_node);
}

np_node_t* _np_node_from_token(np_handshake_token_t* token, np_aaatoken_type_e expected_type)
{
    np_ctx_memory(token);
    
    if (FLAG_CMP(token->type, expected_type) == false) {
        log_debug_msg(LOG_DEBUG, "## decoding node from token str: %s", token->subject);
        return NULL;
    }

    char *to_free = NULL, *to_parse = NULL;
    to_free = to_parse = strndup(&token->subject[strlen(_NP_URN_NODE_PREFIX)-2], 255);
    // "-2" is an ugly hack to have at least one character in front of the connection string

    log_debug_msg(LOG_DEBUG, "## decoding node from token string: %s", to_parse);
    struct __node_from_string_s details = __get_node_details_from_string(context, to_parse, false);

    uint16_t i_host_proto = UNKNOWN_PROTO;
    if (details.s_protocol != NULL) 
    {
        i_host_proto = _np_network_parse_protocol_string(details.s_protocol);
    }

    if (FLAG_CMP(i_host_proto, UNKNOWN_PROTO) || details.s_hostname == NULL || details.s_port == NULL)
    {
        log_debug_msg(LOG_ERROR, "error decoding node from token str: %i / %p / %p", i_host_proto, details.s_hostname, details.s_port);
        free(to_parse);
        return NULL;
    }

    // key string is not mandatory, could be a wildcard
    np_dhkey_t _null_dhkey = {0};
    np_dhkey_t node_dhkey = np_dhkey_create_from_hash(details.s_dhkey);
    if (_np_dhkey_equal(&_null_dhkey, &node_dhkey)) {
        log_debug_msg(LOG_ERROR, "error decoding node from token str: %s / %s / %s / %s", details.s_dhkey, details.s_protocol, details.s_hostname, details.s_port);
        details.s_dhkey[0] = '*';
        details.s_dhkey[1] = '\0';
    }

    log_debug_msg(LOG_DEBUG, "decodeded node from token: %d/%s:%s", i_host_proto, details.s_hostname, details.s_port);
    
    np_node_t* new_node = NULL;
    np_new_obj(np_node_t, new_node, FUNC);
     
    _np_node_update(new_node, i_host_proto, details.s_hostname, details.s_port);
    new_node->host_key = strndup(details.s_dhkey, 64);

    free(to_free);
    return (new_node);
}

uint16_t _np_node_encode_multiple_to_jrb (np_tree_t* data, np_sll_t(np_key_ptr, node_keys), bool include_stats)
{
    uint16_t j=0;
    np_key_t* current;

    sll_clone(np_key_ptr, node_keys, node_keys_to_encode)

    while(NULL != (current = sll_head(np_key_ptr, node_keys_to_encode)))
    {		
        if (_np_key_get_node(current) != NULL)
        {
            // np_ctx_memory(current);
            np_tree_t* node_jrb = np_tree_create();
            _np_node_encode_to_jrb(node_jrb, current, include_stats);

            np_tree_insert_int(data, j, np_treeval_new_tree(node_jrb));
            j++;
            np_tree_free( node_jrb);
        }
    }
    sll_free(np_key_ptr, node_keys_to_encode);
    return (j);
}

sll_return(np_node_ptr) _np_node_decode_multiple_from_jrb (np_state_t* context, np_tree_t* data)
{
    uint16_t nodenum = data->size;

    np_sll_t(np_node_ptr, node_list);
    sll_init(np_node_ptr, node_list);

    /* gets the number of hosts in the lists and goes through them 1 by 1 */
    for (uint16_t i = 0; i < nodenum; i++)
    {
        np_tree_elem_t* node_data = np_tree_find_int(data, i);

        // bool free_s_key = false;
        // char* s_key = np_treeval_to_str(np_tree_find_str(node_data->val.value.tree, NP_SERIALISATION_NODE_KEY)->val, &free_s_key);
        np_node_t* node = _np_node_decode_from_jrb(context, node_data->val.value.tree);
        if (NULL != node)
            sll_append(np_node_ptr, node_list, node);

        // free(s_key);
    }
    return (node_list);
}

int _np_node_cmp(np_node_t* a, np_node_t* b) 
{
    int ret = ( (a == NULL) || (b == NULL) );
    
    if (ret == 0) {
        ret = strcmp(a->dns_name, b->dns_name);
    }
    else 
    {
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
    if (old) free(old);

    old = node->port; 
    node->port = strndup(port, strlen(port));
    if(old) free(old);

    if (FLAG_CMP(proto, PASSIVE)) 
    {
        node->handshake_priority = 0;
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
