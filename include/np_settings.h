//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_SETTINGS_H_
#define NP_SETTINGS_H_

#include <stdlib.h>
#include "sodium.h"

#include "np_constants.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
    Additional compile switches:
     - NP_MEMORY_CHECK_MEMORY_REFFING	(NP_THREADS_CHECK_THREADING should be disabled if this switch is enabled)
     - NP_THREADS_CHECK_THREADING		(NP_MEMORY_CHECK_MEMORY_REFFING should be disabled if this switch is enabled)
     - DEBUG_CALLBACKS					(Allows the job system to collect statistics for job callbacks)
     - x64								(enable 64 Bit support)	(is automaticly set by SConstruct file)
     - CONSOLE_LOG						(prints the log in stdout)
     - NP_BENCHMARKING					if defined enables the performance point macros and sets the size of the calucations array
     - NP_STATISTICS                    enables all of the following NP_STATISTICS* switches
     - NP_STATISTICS_COUNTER			in/out bytes, forwarding counter statistics
     - NP_STATISTICS_THREADS			thread statistics
*/
#ifdef DEBUG
    #define DEBUG_CALLBACKS 1
    #define NP_MEMORY_CHECK_MEMORY_REFFING 1
    #define NP_MEMORY_CHECK_MAGIC_NO
     //#define NP_THREADS_CHECK_THREADING 1
    #define NP_BENCHMARKING 4096
#endif // DEBUG

#define NP_STATISTICS

#ifdef NP_STATISTICS
    #define NP_STATISTICS_COUNTER
    #define NP_STATISTICS_THREADS
#endif

#define NP_PI 3.1415926535
#define NP_PI_INT 3

#ifndef NP_STATISTICS_PROMETHEUS_PREFIX
     #define NP_STATISTICS_PROMETHEUS_PREFIX "neuropil_"
#endif

#ifndef NP_STATISTICS_PROMETHEUS_DATA_GATHERING_INTERVAL
    #define NP_STATISTICS_PROMETHEUS_DATA_GATHERING_INTERVAL (NP_PI/10)
#endif

#ifndef NP_LOG_FLUSH_INTERVAL
    #define NP_LOG_FLUSH_INTERVAL (NP_PI/100)
#endif

#ifndef NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL
    #define NP_BOOTSTRAP_REACHABLE_CHECK_INTERVAL (NP_PI*10)
#endif

#ifndef NP_KEYCACHE_DEPRECATION_INTERVAL
    #define NP_KEYCACHE_DEPRECATION_INTERVAL (31.415)
#endif	

#ifndef _NP_KEYCACHE_ITERATION_STEPS
    #define _NP_KEYCACHE_ITERATION_STEPS (11)
#endif	

/*
 * msgproperty default vaue definitions 
 */
#ifndef MSGPROPERTY_DEFAULT_MAX_TTL_SEC
    #define MSGPROPERTY_DEFAULT_MAX_TTL_SEC (NP_PI_INT * 60) // 180 seconds
#endif
#ifndef MSGPROPERTY_DEFAULT_MIN_TTL_SEC
    #define MSGPROPERTY_DEFAULT_MIN_TTL_SEC (NP_PI_INT) // 3 seconds
#endif

/*
 *	if the sysinfo subsystem in enabled and the node is a client
 *	this is the interval it may send his own data in a proactive
 *	attempt to share its data.
 */
#ifndef SYSINFO_PROACTIVE_SEND_IN_SEC
    #define SYSINFO_PROACTIVE_SEND_IN_SEC (30)
#endif
#ifndef SYSINFO_MAX_TTL
    #define SYSINFO_MAX_TTL (MAX(60, SYSINFO_PROACTIVE_SEND_IN_SEC*12))
#endif
#ifndef SYSINFO_MIN_TTL
    #define SYSINFO_MIN_TTL (MAX(MSGPROPERTY_DEFAULT_MIN_TTL_SEC, SYSINFO_PROACTIVE_SEND_IN_SEC) )
#endif

/*
 * The maximum lifetime of a node before it is refreshed
 */
#ifndef NODE_MAX_TTL_SEC
    #define NODE_MAX_TTL_SEC (NP_PI_INT*100000000)
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
#define MSG_ENCRYPTION_BYTES_40 (crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES)	


#ifndef MISC_LOG_FLUSH_INTERVAL_SEC
    #define MISC_LOG_FLUSH_INTERVAL_SEC (NP_PI/30)
#endif
#ifndef MISC_LOG_FLUSH_MAX_ITEMS
    #define MISC_LOG_FLUSH_MAX_ITEMS (1000)
#endif
#ifndef MISC_LOG_FLUSH_AFTER_X_ITEMS
    #define MISC_LOG_FLUSH_AFTER_X_ITEMS (20)
#endif
#ifndef MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC
    #define MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC (NP_PI)
#endif
#ifndef MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC
    #define MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC (NP_PI/10)
#endif

#ifndef MISC_KEYCACHE_CLEANUP_INTERVAL_SEC
    #define MISC_KEYCACHE_CLEANUP_INTERVAL_SEC (NP_PI/31)
#endif

#ifndef MISC_MEMORY_REFRESH_INTERVAL_SEC
    #define MISC_MEMORY_REFRESH_INTERVAL_SEC (NP_PI/100)
#endif
#ifndef MISC_RESPONSECONTAINER_CLEANUP_INTERVAL_SEC
#define MISC_RESPONSECONTAINER_CLEANUP_INTERVAL_SEC (NP_PI/10)
#endif
#ifndef MISC_CHECK_ROUTES_SEC
    #define MISC_CHECK_ROUTES_SEC (NP_PI)
#endif
#ifndef MISC_SEND_PIGGY_REQUESTS_SEC
    #define MISC_SEND_PIGGY_REQUESTS_SEC (NP_PI*20) // each minute
#endif
#ifndef MISC_SEND_UPDATE_MSGS_SEC
    #define MISC_SEND_UPDATE_MSGS_SEC (NP_PI)
#endif
#ifndef MISC_MSGPROPERTY_MSG_UNIQUITY_CHECK_SEC
    #define MISC_MSGPROPERTY_MSG_UNIQUITY_CHECK_SEC (NP_PI)
#endif
#ifndef MISC_RENEW_NODE_SEC
    #define MISC_RENEW_NODE_SEC (NP_PI*1000)
#endif
#ifndef MISC_READ_EVENTS_SEC
    #define MISC_READ_EVENTS_SEC (NP_PI/500)
#endif
#ifndef MISC_SEND_PINGS_SEC
    #define MISC_SEND_PINGS_SEC (NP_PI*10)
#endif
#ifndef MISC_SEND_PINGS_MAX_EVERY_X_SEC
    #define MISC_SEND_PINGS_MAX_EVERY_X_SEC (MISC_SEND_PINGS_SEC*2)
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
    #define BAD_LINK_REMOVE_GRACETIME (MISC_SEND_PINGS_SEC*3)
#endif

#ifndef PRIORITY_MOD_LOWEST
#define PRIORITY_MOD_LOWEST (PRIORITY_MOD_LEVEL_6)
#endif

#ifndef PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_0_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_1_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_2_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_3_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_4_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_5_SHOULD_HAVE_OWN_THREAD (true)
#endif
#ifndef PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD
#define PRIORITY_MOD_LEVEL_6_SHOULD_HAVE_OWN_THREAD (true)
#endif

#ifndef PRIORITY_MOD_USER_DEFAULT
#define PRIORITY_MOD_USER_DEFAULT (PRIORITY_MOD_LOWEST)
#endif

#ifndef JOBQUEUE_PRIORITY_MOD_BASE_STEP
#define JOBQUEUE_PRIORITY_MOD_BASE_STEP (100)
#endif

#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN
    #define JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN (PRIORITY_MOD_LEVEL_3 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT
    #define JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT (PRIORITY_MOD_LEVEL_3 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE
    #define JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE (PRIORITY_MOD_LEVEL_2 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG
    #define JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG (PRIORITY_MOD_LEVEL_4 * JOBQUEUE_PRIORITY_MOD_BASE_STEP)
#endif

#ifndef JOBQUEUE_MAX_SIZE
#define JOBQUEUE_MAX_SIZE (512)
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
        #define LOG_ROTATE_ENABLE false
    #else
        #define LOG_ROTATE_ENABLE true
    #endif
#endif

#ifndef NP_NETWORK_MAX_MSGS_PER_SCAN_OUT
    #define NP_NETWORK_MAX_MSGS_PER_SCAN_OUT (1)
#endif

#ifndef NP_NETWORK_MAX_MSGS_PER_SCAN_IN
    #define NP_NETWORK_MAX_MSGS_PER_SCAN_IN (5)
#endif
 // indirect #define NP_NETWORK_MAX_BYTES_PER_SCAN (NP_NETWORK_MAX_MSGS_PER_SCAN*1024)
#ifndef NETWORK_RECEIVING_TIMEOUT_SEC
    #define NETWORK_RECEIVING_TIMEOUT_SEC (NP_PI/500)
#endif


#ifndef MUTEX_WAIT_SEC
    #define MUTEX_WAIT_SEC  ((const ev_tstamp )4.0)
#endif

#ifndef MUTEX_WAIT_MAX_SEC
    #define MUTEX_WAIT_MAX_SEC  MUTEX_WAIT_SEC 
#endif
#ifndef NP_JOBQUEUE_MAX_SLEEPTIME_SEC
    #define NP_JOBQUEUE_MAX_SLEEPTIME_SEC (NP_PI/10)
#endif

#ifndef NP_EVENT_IO_CHECK_PERIOD_SEC
    // the optimal libev run interval remains to be seen
    // if set too low, base cpu usage increases on no load
    #define NP_EVENT_IO_CHECK_PERIOD_SEC (NP_PI/1000)
#endif

/*
    lower value => success avg more on realtime
    higher value => more msgs need to be failed to regard this link as bad

    use a prime number because of modulo division
*/
#define NP_NODE_SUCCESS_WINDOW 31


#if !(defined(__APPLE__) || defined(__MACH__ ))
    #define NP_THREADS_PTHREAD_HAS_MUTEX_TIMEDLOCK 1
#endif

#define NP_SLEEP_MIN (NP_PI/1000)


#define __MAX_ROW    64 /* length of key                   */
#define __MAX_COL    16 /* 16 different characters         */
#define __MAX_ENTRY   3 /* three alternatives for each key */

#define NP_ROUTES_MAX_ENTRIES __MAX_ENTRY
#define NP_ROUTES_TABLE_SIZE (__MAX_ROW * __MAX_COL * __MAX_ENTRY)

// TODO: change size to match the possible log10(hash key max value)
// TODO: change the size according to the number of entries in the routing table (min: 2/ max: 8)
#define NP_ROUTE_LEAFSET_SIZE  12 /* (must be even) excluding node itself */


#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */

