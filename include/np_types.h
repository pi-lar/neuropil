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


/*
 *  simple types / typedefs
 */
typedef struct np_aaatoken_s np_aaatoken_t;
typedef np_aaatoken_t* np_aaatoken_ptr;

typedef struct np_dhkey_s np_dhkey_t;

typedef struct np_job_s np_job_t;
typedef struct np_jobargs_s np_jobargs_t;

typedef struct np_key_s np_key_t;

typedef struct np_message_s np_message_t;
typedef struct np_msgproperty_s np_msgproperty_t;

typedef struct np_network_s np_network_t;
typedef struct np_node_s np_node_t;

typedef struct np_state_s np_state_t;

typedef struct np_tree_s np_tree_t;

typedef struct np_val_s np_val_t;

 /*
 * list types and typedefs
 */
NP_SLL_GENERATE_PROTOTYPES(np_aaatoken_t);
NP_PLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);
NP_SLL_GENERATE_PROTOTYPES(np_node_t);
NP_SLL_GENERATE_PROTOTYPES(np_key_t);
NP_SLL_GENERATE_PROTOTYPES(np_message_t);

/*
 *  user callback functions
 */
typedef np_bool (*np_aaa_func_t) (np_aaatoken_t* aaa_token );
typedef np_bool (*np_usercallback_t) (np_tree_t* msg_properties, np_tree_t* msg_body);

// internal callback functions
typedef void (*np_callback_t) (np_jobargs_t*);

// void f() __attribute__ ((weak, alias ("__f")));


#endif /* _INCLUDE_H_ */
