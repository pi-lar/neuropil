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

typedef enum
{
	FALSE=0,
	TRUE=1
} np_bool;

//
// TODO: think about using these attributes:
//
// int square (int) __attribute__ ((pure));
// void __attribute__ ((visibility ("protected"))) f () { /* Do something. */; }
// int i __attribute__ ((visibility ("hidden")));
// #define NP_PROTECTED __attribute__ ((visibility ("protected")))
// #define NP_INTERNAL  __attribute__ ((visibility ("internal")))
// #define NP_API       __attribute__ ((visibility ("default")))

// void f() __attribute__ ((weak, alias ("__f")));

#define crypto_bytes crypto_box_PUBLICKEYBYTES

static const int MSG_ARRAY_SIZE = 1;
static const int MSG_PAYLOADBIN_SIZE = 15;
static const int MSG_FOOTERBIN_SIZE = 10;
static const int MSG_CHUNK_SIZE_1024 = 1024;
static const int MSG_ENCRYPTION_BYTES_40 = 40;

// object-like / memory management
typedef struct np_obj_s np_obj_t;

// global neuopil state
typedef struct np_state_s np_state_t;

// node data and corresponding network layer
typedef struct np_node_s np_node_t;
typedef struct np_network_s np_network_t;

// routing table
typedef struct np_routeglobal_s np_routeglobal_t;

// messages and message handling structures
typedef struct np_message_s np_message_t;
typedef struct np_messagepart_s np_messagepart_t;
typedef struct np_msgproperty_s np_msgproperty_t;

// threading and job execution structures
typedef struct np_jobqueue_s np_jobqueue_t;
typedef struct np_jobargs_s np_jobargs_t;
typedef struct np_job_s np_job_t;
typedef np_job_t* np_job_ptr;

// red-black-tree structures
typedef struct np_jtree np_jtree_t;
typedef struct np_jtree_elem_s np_jtree_elem_t;

// generic value structure
typedef struct np_jval_s np_jval_t;

// dh-key structures
typedef struct np_dhkey_s np_dhkey_t;
typedef struct np_key_s np_key_t;

// localhost http interface
typedef struct np_http_s np_http_t;

// aaa token data - (inspired by json.web.token, kerberos, diameter)
typedef struct np_aaatoken_s np_aaatoken_t;
typedef np_aaatoken_t* np_aaatoken_ptr;

// callback functions
typedef np_bool (*np_aaa_func_t) (np_state_t* state, np_aaatoken_t* node );
typedef np_bool (*np_join_func_t) (np_state_t* state, np_node_t* node );

typedef void (*np_callback_t) (np_state_t*, np_jobargs_t*);
typedef np_bool (*np_usercallback_t) (np_jtree_t* msg_properties, np_jtree_t* msg_body);

#endif /* _INCLUDE_H_ */
