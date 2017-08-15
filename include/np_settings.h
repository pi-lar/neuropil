//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_SETTINGS_H_
#define NP_SETTINGS_H_

#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif

/*
 *	if the sysinfo subsystem in enabled and the node is a slave
 *	this is the intervall it may send his own data in a proactive
 *	attempt to share its data.
 */
#ifndef SYSINFO_PROACTIVE_SEND_IN_SEC
	static const double SYSINFO_PROACTIVE_SEND_IN_SEC = 5.0;
#endif
#ifndef SYSINFO_MAX_TTL
	static const uint32_t SYSINFO_MAX_TTL = 30; //31540000;//30;
#endif

#ifndef SYSINFO_MIN_TTL
	static const uint32_t SYSINFO_MIN_TTL = SYSINFO_MAX_TTL - 10;
#endif

#ifndef MSGPROPERTY_DEFAULT_MAX_TTL
	static const uint32_t MSGPROPERTY_DEFAULT_MAX_TTL_SEC = 30; //31540000;//30;
#endif

#ifndef MSGPROPERTY_DEFAULT_MIN_TTL
	static const uint32_t MSGPROPERTY_DEFAULT_MIN_TTL_SEC = MSGPROPERTY_DEFAULT_MAX_TTL_SEC - 10;
#endif
/*
 * The maximum lifetime of a node before it is refreshed
 */
#ifndef NODE_MAX_TTL_SEC
	static const double NODE_MAX_TTL_SEC =  31540000; // 3600 = 1h
#endif

#ifndef TOKEN_GRACETIME
	static const double TOKEN_GRACETIME =  10;
#endif

/*
 * The minimum lifetime of a node before it is refreshed
 */
#ifndef NODE_MIN_TTL_SEC
	static const double NODE_MIN_TTL_SEC = NODE_MAX_TTL_SEC - 120;
#endif

#ifndef NODE_RENEW_BEFORE_EOL_SEC
	static const double NODE_RENEW_BEFORE_EOL_SEC = 5;
#endif


static const int MSG_ARRAY_SIZE = 1;
static const int MSG_PAYLOADBIN_SIZE = 15;

static const int MSG_CHUNK_SIZE_1024 = 1024;
static const int MSG_ENCRYPTION_BYTES_40 = 40;


#ifndef MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC
	static const double MISC_REJOIN_BOOTSTRAP_INTERVAL_SEC = 5;
#endif

#ifndef MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC
	static const double MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC = 0.31415;
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


#ifndef JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT
	static const double JOBQUEUE_PRIORITY_MOD_RESUBMIT_MSG_OUT = 3;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE
	static const double JOBQUEUE_PRIORITY_MOD_RESUBMIT_ROUTE = 3;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE
	static const double JOBQUEUE_PRIORITY_MOD_SUBMIT_ROUTE = 4;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN
	static const double JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_IN = 3;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG
	static const double JOBQUEUE_PRIORITY_MOD_TRANSFORM_MSG = 2;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT
	static const double JOBQUEUE_PRIORITY_MOD_SUBMIT_MSG_OUT = 4;
#endif
#ifndef JOBQUEUE_PRIORITY_MOD_SUBMIT_EVENT
	static const double JOBQUEUE_PRIORITY_MOD_SUBMIT_EVENT = 1;
#endif

#ifndef LOG_ROTATE_COUNT
#define LOG_ROTATE_COUNT 3
#endif

#ifndef LOG_ROW_SIZE
	#define LOG_ROW_SIZE 5000
#endif

#ifndef LOG_ROTATE_AFTER_BYTES
	#if defined(DEBUG) && DEBUG == 1
		#define LOG_ROTATE_AFTER_BYTES 10000000	// 100 MB
	#else
		#define LOG_ROTATE_AFTER_BYTES 1000000	// 10 MB
	#endif
#endif

#ifndef LOG_ROTATE_ENABLE
	#define LOG_ROTATE_ENABLE TRUE
#endif
#ifndef LOG_FORCE_INSTANT_WRITE
	#define LOG_FORCE_INSTANT_WRITE TRUE
#endif


#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */
