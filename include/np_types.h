//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_TYPES_H_
#define _NP_TYPES_H_

#include <stdbool.h>
#include <stdint.h>

#include "event/ev.h"

#include "neuropil.h"
#include "np_list.h"

/*
 *  simple types / typedefs
 */

typedef struct np_util_event_s np_util_event_t;

typedef struct np_responsecontainer_s np_responsecontainer_t;

typedef struct np_aaatoken_s np_aaatoken_t;
typedef np_aaatoken_t np_ident_public_token_t;
typedef np_aaatoken_t np_ident_private_token_t;
typedef np_aaatoken_t np_message_intent_public_token_t;
typedef np_aaatoken_t np_node_public_token_t;
typedef np_aaatoken_t np_node_private_token_t;
typedef np_aaatoken_t np_handshake_token_t;

typedef np_aaatoken_t* np_aaatoken_ptr;
typedef enum np_aaatoken_type np_aaatoken_type_e;

typedef struct np_dhkey_s np_dhkey_t;

typedef struct np_job_s np_job_t;

typedef struct np_key_s np_key_t;
typedef np_key_t* np_key_ptr;

typedef struct np_message_s np_message_t;
typedef np_message_t* np_message_ptr;

typedef struct np_msgproperty_s np_msgproperty_t;
typedef np_msgproperty_t* np_msgproperty_ptr;

typedef struct _np_obj_buffer_container_s _np_obj_buffer_container_t;

typedef struct np_network_s np_network_t;

typedef struct np_node_s np_node_t;
typedef np_node_t* np_node_ptr;

typedef struct np_state_s np_state_t;


typedef struct np_tree_conf_s np_tree_conf_t;
typedef struct np_tree_s np_tree_t;

typedef struct np_treeval_s np_treeval_t;

typedef struct np_mutex_s np_mutex_t;

typedef char* char_ptr;
typedef void* void_ptr;

typedef struct np_thread_s np_thread_t;
typedef np_thread_t* np_thread_ptr;

typedef struct np_crypto_s np_crypto_t;
typedef struct np_crypto_session_s np_crypto_session_t;

/*
 *  user callback functions
 */
typedef void (*np_destroycallback_t)      (np_context* ac);
typedef bool (*np_usercallbackfunction_t) (np_context* ac, const np_message_t* const msg, np_tree_t* body, void* localdata);
typedef void (*np_responsecontainer_on_t) (const np_responsecontainer_t* const entry);
typedef void (*np_msgproperty_on_reply_t) (const np_responsecontainer_t* const entry, const np_message_t* const reply_msg);
typedef void (*np_threads_worker_run)     (np_state_t* context, np_thread_t* thread);

// internal callback functions
typedef void (*np_callback_t) (np_state_t* context, np_util_event_t event);
typedef bool (*np_evt_callback_t) (np_state_t* context, np_util_event_t event);
typedef int(*_np_cmp_t)(void* a, void* b);

typedef struct np_usercallback_s {
    void * data;
    np_usercallbackfunction_t fn;
} np_usercallback_t;

typedef np_usercallback_t* np_usercallback_ptr;

/*
* list types and typedefs
*/
#pragma clang diagnostic push ignored "-Wstrict-prototypes"

NP_PLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);

NP_SLL_GENERATE_PROTOTYPES(void_ptr);
NP_SLL_GENERATE_PROTOTYPES(char_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_key_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_message_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_msgproperty_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_node_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_thread_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_usercallback_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_callback_t);
NP_SLL_GENERATE_PROTOTYPES(np_evt_callback_t);
NP_SLL_GENERATE_PROTOTYPES(np_destroycallback_t);
NP_SLL_GENERATE_PROTOTYPES(np_responsecontainer_on_t);
NP_SLL_GENERATE_PROTOTYPES(np_msgproperty_on_reply_t);

NP_DLL_GENERATE_PROTOTYPES(np_thread_ptr);

#pragma clang diagnostic pop

#endif /* _INCLUDE_H_ */
