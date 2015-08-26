/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _INCLUDE_H_
#define _INCLUDE_H_

/* just in case NULL is not defined */
#ifndef NULL
#define NULL (void*)0
#endif

typedef enum {
	FALSE=0,
	TRUE=1
} np_bool;

#define crypto_bytes crypto_box_PUBLICKEYBYTES

// memory management
typedef struct np_obj_pool_s np_obj_pool_t;
typedef struct np_obj_s np_obj_t;

// global neuopil state
typedef struct np_state_s np_state_t;

// node an network data
typedef struct np_node_s np_node_t;
typedef struct np_network_s np_network_t;

// routing table
typedef struct np_routeglobal_t np_routeglobal_t;

// message
typedef struct np_messageglobal_s np_messageglobal_t;
typedef struct np_message_s np_message_t;
typedef struct np_msgcache_s np_msgcache_t;
typedef struct np_msgproperty_s np_msgproperty_t;
typedef struct np_msginterest_s np_msginterest_t;

// threading and job execution structures
typedef struct np_job_s np_job_t;
typedef struct np_joblist_s np_joblist_t;
typedef struct np_jobargs_s np_jobargs_t;

// red black tree structures
typedef struct np_jtree np_jtree_t;
typedef struct np_jtree_elem_s np_jtree_elem_t;

// generic value structure
typedef struct np_jval_s np_jval_t;

// dh-key structure
typedef struct np_key_s np_key_t;

// aaa token data - (inspired by json.web.token, kerberos, diameter)
typedef struct np_aaatoken_s np_aaatoken_t;

// callback functions
typedef np_bool (*np_aaa_func_t) (np_state_t* state, np_aaatoken_t* node );
typedef np_bool (*np_join_func_t) (np_state_t* state, np_node_t* node );

typedef void (*np_callback_t) (np_state_t*, np_jobargs_t*);
typedef np_bool (*np_usercallback_t) (np_jtree_t* msg_properties, np_jtree_t* msg_body);

#ifndef _NP_MEMORY_H
extern np_obj_pool_t np_obj_pool;
#else
np_obj_pool_t np_obj_pool; //  = { 0,0,0,0,0,0 };
#endif

#endif /* _INCLUDE_H_ */
