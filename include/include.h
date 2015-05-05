#ifndef _INCLUDE_H_
#define _INCLUDE_H_

/* just in case NULL is not defined */
#ifndef NULL
#define NULL    0
#endif

typedef enum {
	FALSE=0,
	TRUE=1
} np_bool;

#define crypto_bytes crypto_box_PUBLICKEYBYTES

typedef struct np_state_s np_state_t;
typedef struct np_global_s np_global_t;

typedef struct np_nodecache_s np_nodecache_t;
typedef struct np_node_s np_node_t;

typedef struct np_routeglobal_t np_routeglobal_t;

typedef struct np_message_s np_message_t;
typedef struct np_messageglobal_s np_messageglobal_t;
typedef struct np_msgproperty_s np_msgproperty_t;
typedef struct np_msginterest_s np_msginterest_t;
typedef struct np_networkglobal_s np_networkglobal_t;

typedef struct np_job_t np_job_t;
typedef struct np_joblist_t np_joblist_t;
typedef struct np_jobargs_t np_jobargs_t;

typedef struct np_jrb_s np_jrb_t;

typedef struct np_key_s np_key_t;

typedef struct np_aaatoken_cache_s np_aaatoken_cache_t;
typedef struct np_aaatoken_s np_aaatoken_t;

typedef int (*np_aaa_func_t) (np_state_t* state, np_aaatoken_t* node );
typedef int (*np_join_func_t) (np_state_t* state, np_node_t* node );
typedef void (*np_callback_t) (np_state_t*, np_jobargs_t*);


#endif /* _INCLUDE_H_ */


//#ifndef _NEUROPIL_H_
//#include "neuropil.h"
//#endif
//
//#ifndef _NP_ROUTE_H
//#include "route.h"
//#endif
//
//#ifndef _NP_NETWORK_H_
//#include "network.h"
//#endif
//
//#ifndef _NP_JOBQUEUE_H
//#include "job_queue.h"
//#endif
//
//#ifndef _NP_MESSAGE_H_
//#include "message.h"
//#endif
//
//#ifndef _NP_NODE_H_
//#include "host.h"
//#endif
//
//#ifndef _NP_KEY_H_
//#include "key.h"
//#endif
//
//#ifndef _NP_THREADS_H_
//#include "threads.h"
//#endif
//
//#ifndef _NP_SEMAPHORE_H_
//#include "semaphore.h"
//#endif
//
//#ifndef _NP_JRB_H_
//#include "jrb.h"
//#endif
//
//#ifndef _NP_JVAL_H_
//#include "jval.h"
//#endif
//
//#ifndef _NP_DLLIST_H_
//#include "dllist.h"
//#endif
