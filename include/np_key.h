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

#include "util/np_event.h"
#include "util/np_statemachine.h"

#ifdef __cplusplus
extern "C" {
#endif

enum np_key_type {

	np_key_type_unknown			= 0x000,
	// np_comp_alias
	np_key_type_alias			= 0x001,
	// np_comp_node
	np_key_type_node            = 0x002,
	np_key_type_wildcard        = 0x004,
	// np_comp_identity
	np_key_type_ident			= 0x008,
	// np_comp_msgproperty
	np_key_type_subject			= 0x010,
	// np_comp_intent
	np_key_type_intent			= 0x020,
};


struct np_key_s
{
	// link to memory management and ref counter
	RB_ENTRY(np_key_s) link; // link for cache management

	// state machine
	np_util_statemachine_t sm;

    // np_mutex_t key_lock;
	np_dhkey_t dhkey;
	char*      dhkey_str;

	double created_at;
	double last_update;

	bool   is_in_keycache;

	enum np_key_type type;

	np_key_t* parent_key; // reference to parent/partner key
	np_sll_t(void_ptr, entities); // link to components attached to this key id

    np_mutex_t key_lock;

} NP_API_INTERN;

_NP_GENERATE_MEMORY_PROTOTYPES(np_key_t);


NP_API_INTERN
int8_t _np_key_cmp(np_key_t* const k1, np_key_t* const k2);
NP_API_INTERN
int8_t _np_key_cmp_inv(np_key_t* const k1, np_key_t* const k2);

NP_API_INTERN
void _np_key_destroy(np_key_t* to_destroy) ;

NP_API_INTERN
char* _np_key_as_str(np_key_t * key);

NP_API_INTERN
void _np_key_handle_event(np_key_t* key, np_util_event_t event, bool force);

struct __np_node_trinity {
    np_aaatoken_t  *token;
    np_node_t      *node;
    np_network_t   *network;
};

NP_API_INTERN
void __np_key_to_trinity(np_key_t* key, struct __np_node_trinity *trinity);
NP_API_INTERN
np_network_t* _np_key_get_network(np_key_t* key);
NP_API_INTERN
np_node_t* _np_key_get_node(np_key_t* key);
NP_API_INTERN
np_aaatoken_t* _np_key_get_token(np_key_t* key);


#ifdef __cplusplus
}
#endif


#endif /* _NP_KEY_H_ */
