//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_KEY_H_
#define _NP_KEY_H_

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "tree/tree.h"

#include "np_dhkey.h"
#include "np_threads.h"
#include "np_memory.h"

#include "np_types.h"
#include "np_node.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_key_type {
	np_key_type_unknown			= 0x000,
	np_key_type_alias			= 0x001,
	np_key_type_node            = 0x002,
	// no detection available (only local)
	np_key_type_wildcard        = 0x004,

	//DETECTION NOT IMPLEMENTED
	np_key_type_ident			= 0x008,
	//DETECTION NOT IMPLEMENTED
	np_key_type_subject			= 0x010,
};
struct np_key_s
{
	              // link to memory management and ref counter

	double created_at;
	bool in_destroy;

	SPLAY_ENTRY(np_key_s) link; // link for cache management

	/*
	only available for subject key
	use _np_key_get_dhkey()
	*/
	np_dhkey_t dhkey;
	double last_update;
	char*      dhkey_str;

	bool is_in_keycache;
	/*
	only available for node key
	*/
	np_node_t*    node;		    // link to a neuropil node if this key represents a node
	/*
	only available for node key
	*/
	np_network_t* network;	    // link to a neuropil network if this key represents a node

	/*
	only available for node and ident key
	*/
	np_aaatoken_t* aaa_token; // link to aaatoken for this key (if it exists)

	np_pll_t(np_aaatoken_ptr, local_mx_tokens); // link to runtime interest data on which this node is interested in

	// required structure if this node becomes a mitm for message exchange
	np_msgproperty_t* recv_property;
	np_msgproperty_t* send_property;

	np_pll_t(np_aaatoken_ptr, recv_tokens); // link to runtime interest data on which this node is interested in
	np_pll_t(np_aaatoken_ptr, send_tokens); // link to runtime interest data on which this node is interested in

	enum np_key_type type;

	/*
	 * Holds a reference to the parent if the key is an alias key.
	 */
	np_key_t* parent_key;
} NP_API_INTERN;

_NP_GENERATE_MEMORY_PROTOTYPES(np_key_t);

NP_PLL_GENERATE_PROTOTYPES(np_key_ptr);


NP_API_INTERN
int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2);
NP_API_INTERN
int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2);

NP_API_INTERN
void _np_key_destroy(np_key_t* to_destroy) ;

NP_API_INTERN
char* _np_key_as_str(np_key_t * key);

NP_API_EXPORT
void np_key_renew_token();

NP_API_INTERN
void np_key_ref_list(np_sll_t(np_key_ptr, sll_list), const char* reason, const char* reason_desc);

NP_API_INTERN
void np_key_unref_list(np_sll_t(np_key_ptr, sll_list) , const char* reason);

NP_API_INTERN
np_key_t* _np_key_get_by_key_hash(np_state_t* context,	char* targetDhkey);

NP_API_INTERN
void _np_key_set_recv_property(np_key_t* self, np_msgproperty_t* prop);
NP_API_INTERN
void _np_key_set_send_property(np_key_t* self, np_msgproperty_t* prop);
NP_API_INTERN
void _np_key_set_network(np_key_t* self, np_network_t* ng);

#ifdef __cplusplus
}
#endif


#endif /* _NP_KEY_H_ */
