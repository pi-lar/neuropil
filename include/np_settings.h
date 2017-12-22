//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_SETTINGS_H_
#define NP_SETTINGS_H_

#include <stdlib.h>
#include "np_constants.h"

#ifdef __cplusplus
extern "C" {
#endif
	
/*
	Possible compile switches:
	 - NP_MEMORY_CHECK_MEMORY		(NP_THREADS_CHECK_THREADING should be disabled if this switch is enabled)
	 - NP_THREADS_CHECK_THREADING	(NP_MEMORY_CHECK_MEMORY should be disabled if this switch is enabled)
	 - DEBUG_CALLBACKS
	 - x64 (enable 64 Bit support)	(is automaticly set by SConstruct file)
*/
#ifdef DEBUG
	#define DEBUG_CALLBACKS 1
	#define NP_MEMORY_CHECK_MEMORY 1
	//#define NP_THREADS_CHECK_THREADING 1
#endif // DEBUG


/*
 *	if the sysinfo subsystem in enabled and the node is a slave
 *	this is the intervall it may send his own data in a proactive
 *	attempt to share its data.
 */
#ifndef SYSINFO_PROACTIVE_SEND_IN_SEC
	#define SYSINFO_PROACTIVE_SEND_IN_SEC (1.)
#endif
#ifndef SYSINFO_MAX_TTL
	#define SYSINFO_MAX_TTL (30)
#endif

#ifndef SYSINFO_MIN_TTL
	#define SYSINFO_MIN_TTL (SYSINFO_MAX_TTL - 10)
#endif

#ifndef MSGPROPERTY_DEFAULT_MAX_TTL
	#define MSGPROPERTY_DEFAULT_MAX_TTL_SEC (30)
#endif

#ifndef MSGPROPERTY_DEFAULT_MIN_TTL
	#define MSGPROPERTY_DEFAULT_MIN_TTL_SEC (MSGPROPERTY_DEFAULT_MAX_TTL_SEC - 10)
#endif
/*
 * The maximum lifetime of a node before it is refreshed
 */
#ifndef NODE_MAX_TTL_SEC
	#define NODE_MAX_TTL_SEC (31540000)
#endif

#ifndef TOKEN_GRACETIME
	#define TOKEN_GRACETIME (10)
#endif

/*
 * The minimum lifetime of a node before it is refreshed
 */
#ifndef NODE_MIN_TTL_SEC
	#define NODE_MIN_TTL_SEC (NODE_MAX_TTL_SEC - 120)
#endif
#ifndef NODE_RENEW_BEFORE_EOL_SEC
	#define NODE_RENEW_BEFORE_EOL_SEC (5)
#endif

#define MSG_ARRAY_SIZE (1)
#define MSG_PAYLOADBIN_SIZE (15)

#define MSG_CHUNK_SIZE_1024 (1024)
#define MSG_ENCRYPTION_BYTES_40 (40)

	
#ifndef MISC_LOG_FLUSH_INTERVAL_SEC
	#define MISC_LOG_FLUSH_INTERVAL_SEC (1.0)
#endif
#ifndef MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC
	#define MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC (5.0)
#endif
#ifndef MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC
	#define MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC (3.1415)
#endif
#ifndef MISC_KEYCACHE_CLEANUP_INTERVAL_SEC
	#define MISC_KEYCACHE_CLEANUP_INTERVAL_SEC (3.1415)
#endif
#ifndef MISC_ACKENTRY_CLEANUP_INTERVAL_SEC
	#define MISC_ACKENTRY_CLEANUP_INTERVAL_SEC (0.31415)
#endif
#ifndef MISC_CHECK_ROUTES_SEC
	#define MISC_CHECK_ROUTES_SEC (3.1415)
#endif
#ifndef MISC_SEND_PIGGY_REQUESTS_SEC
	#define MISC_SEND_PIGGY_REQUESTS_SEC (3.1415)
#endif
#ifndef MISC_SEND_UPDATE_MSGS_SEC
	#define MISC_SEND_UPDATE_MSGS_SEC (3.1415)
#endif
#ifndef MISC_RENEW_NODE_SEC
	#define MISC_RENEW_NODE_SEC (3141.5)
#endif
#ifndef MISC_RETRANSMIT_MSG_TOKENS_SEC
	#define MISC_RETRANSMIT_MSG_TOKENS_SEC (3.1415)
#endif
#ifndef MISC_READ_EVENTS_SEC
	#define MISC_READ_EVENTS_SEC (0.031415)
#endif
#ifndef MISC_SEND_PINGS_SEC
	#define MISC_SEND_PINGS_SEC (13.1415)
#endif
	

#ifndef GOOD_LINK
	#define GOOD_LINK 0.7
#endif
#ifndef BAD_LINK
	#define BAD_LINK 0.3
#endif
/* Even if the link is bad we wait
 * BAD_LINK_REMOVE_GRACETIME seconds before we
 * remove the link from the leafset/routing table
 */
#ifndef BAD_LINK_REMOVE_GRACETIME
	#define BAD_LINK_REMOVE_GRACETIME 2.0
#endif

#ifndef PRIORITY_MOD_LOWEST
#define PRIORITY_MOD_LOWEST (PRIORITY_MOD_LEVEL_6)
#endif


#ifndef PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif													
#ifndef PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif						
#ifndef PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif													
#ifndef PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif													
#ifndef PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif													
#ifndef PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif													
#ifndef PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD (TRUE)
#endif

#ifndef PRIORITY_MOD_USER_DEFAULT
#define PRIORITY_MOD_USER_DEFAULT (PRIORITY_MOD_LOWEST)
#endif

#ifndef JOBQUEUE_PRIORITY_MOD_BASE_STEP
#define JOBQUEUE_PRIORITY_MOD_BASE_STEP (10000)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT
	#define JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT (PRIORITY_MOD_LEVEL_3 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE
	#define JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE (PRIORITY_MOD_LEVEL_3 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE
	#define JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE (PRIORITY_MOD_LEVEL_4 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN
	#define JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN (PRIORITY_MOD_LEVEL_2 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG
	#define JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG (PRIORITY_MOD_LEVEL_3 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT
	#define JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT (PRIORITY_MOD_LEVEL_2 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_MAX_SIZE
#define JOBQUEUE_MAX_SIZE (500)
#endif

#ifndef LOG_ROTATE_COUNT
	#define LOG_ROTATE_COUNT (3)
#endif

#ifndef LOG_ROW_SIZE
		#define LOG_ROW_SIZE (5000)
#endif

#ifndef LOG_ROTATE_AFTER_BYTES	
		#define LOG_ROTATE_AFTER_BYTES (1000000	/* 10 MB */)
#endif

#ifndef LOG_ROTATE_ENABLE
	#if defined(DEBUG) && DEBUG == 1
		#define LOG_ROTATE_ENABLE FALSE
	#else
		#define LOG_ROTATE_ENABLE TRUE
	#endif
#endif
#ifndef LOG_FORCE_INSTANT_WRITE
	#if defined(DEBUG) && DEBUG == 1
		#define LOG_FORCE_INSTANT_WRITE (TRUE)
	#else
		#define LOG_FORCE_INSTANT_WRITE (FALSE)
	#endif
#endif

#ifndef NP_NETWORK_MAX_MSGS_PER_SCAN
	#define NP_NETWORK_MAX_MSGS_PER_SCAN (10) 
#endif
 // indirect #define NP_NETWORK_MAX_BYTES_PER_SCAN (NP_NETWORK_MAX_MSGS_PER_SCAN*1024) 
#ifndef NETWORK_RECEIVING_TIMEOUT_SEC 
	#define NETWORK_RECEIVING_TIMEOUT_SEC (0.031415) 
#endif


#ifndef MUTEX_WAIT_SEC
	#define MUTEX_WAIT_SEC  ((const ev_tstamp )0.5)
#endif
#ifndef MUTEX_WAIT_SOFT_SEC
	#define MUTEX_WAIT_SOFT_SEC  MUTEX_WAIT_SEC *5
#endif
#ifndef MUTEX_WAIT_MAX_SEC
	#define MUTEX_WAIT_MAX_SEC  MUTEX_WAIT_SEC *10
#endif
#ifndef NP_JOBQUEUE_MAX_SLEEPTIME_SEC
	#define NP_JOBQUEUE_MAX_SLEEPTIME_SEC (0.3)
#endif

#ifndef NP_EVENT_IO_CHECK_PERIOD_SEC
	#define NP_EVENT_IO_CHECK_PERIOD_SEC (0.0031415)
#endif

/*
	lower value => success avg more on realtime
	higher value => more msgs need to be failed to regard this link as bad
*/
#define NP_NODE_SUCCESS_WINDOW 50


#ifndef NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK
	#define NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK (!defined(__APPLE__) || !defined(__MACH__ ) ) 
#endif




#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */
