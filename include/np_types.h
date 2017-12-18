//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_TYPES_H_
#define _NP_TYPES_H_

#include <stdint.h>

#include "event/ev.h"

#include "np_list.h"

/* just in case NULL is not defined */
#ifndef NULL
#define NULL (void*)0
#endif

typedef enum
{
    FALSE=0,
    TRUE=1
} np_bool;

//
// int __attribute__((overloadable)) square(int);

#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__linux__)
#define NP_ENUM
#endif
#if defined(__APPLE__) && defined(__MACH__)
#define NP_ENUM __attribute__ ((flag_enum))
#endif

#define NP_CONST __attribute__ ((const))
#define NP_PURE  __attribute__ ((pure))

#define NP_PACKED(x)  __attribute__ ((packed(x)))
#define NP_DEPRECATED __attribute__ ((deprecated("!!! DEPRECATED !!!")))

#define NP_UNUSED     __attribute__ ((unused))

#define NP_API_EXPORT __attribute__ ((visibility ("default")))

//#ifndef TEST_COMPILE
//  #define NP_API_HIDDEN __attribute__ ((visibility ("hidden")))
//  #define NP_API_PROTEC __attribute__ ((visibility ("protected")))
//  #define NP_API_INTERN __attribute__ ((visibility ("internal")))
//#else
  #define NP_API_HIDDEN __attribute__ ((visibility ("default")))
  #define NP_API_PROTEC __attribute__ ((visibility ("default")))
  #define NP_API_INTERN __attribute__ ((visibility ("default")))
// #endif


/* np_obj_t
*
* void* like wrapper around structures to allow ref counting and null pointer checking
* each np_new_obj needs a corresponding np_unref_obj
* if other methods would like to claim ownership, they should call np_ref_obj, np_unref_obj
* will release the object again (and possible delete it)
*
*/
typedef struct np_obj_s np_obj_t;


/*
 *  simple types / typedefs
 */
typedef struct np_ackentry_s np_ackentry_t;

typedef struct np_aaatoken_s np_aaatoken_t;
typedef np_aaatoken_t* np_aaatoken_ptr;

typedef struct np_dhkey_s np_dhkey_t;

typedef struct np_job_s np_job_t;
typedef struct np_jobargs_s np_jobargs_t;

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


/*
 *  user callback functions
 */
typedef np_bool (*np_aaa_func_t) (np_aaatoken_t* aaa_token );
typedef np_bool(*np_usercallback_t) (const np_message_t* const msg, np_tree_t* properties, np_tree_t* body);
typedef void(*np_ackentry_on_t) (const np_ackentry_t const * entry);

// internal callback functions
typedef void (*np_callback_t) (np_jobargs_t*);
typedef int(*_np_cmp_t)(void* a, void* b);

// void f() __attribute__ ((weak, alias ("__f")));

/*
* list types and typedefs
*/
NP_PLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);

NP_SLL_GENERATE_PROTOTYPES(void_ptr);
NP_SLL_GENERATE_PROTOTYPES(char_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_key_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_message_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_msgproperty_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_node_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_thread_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_usercallback_t);
NP_SLL_GENERATE_PROTOTYPES(np_callback_t);
NP_SLL_GENERATE_PROTOTYPES(np_ackentry_on_t);


#endif /* _INCLUDE_H_ */
