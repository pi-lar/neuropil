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
 *	this is the intervall ist may send his own data in a proactive
 *	attempt to share its data.
 */
#ifndef SYSINFO_PROACTIVE_SEND_IN_SEC
	static const double SYSINFO_PROACTIVE_SEND_IN_SEC = 1.0;
#endif
#ifndef SYSINFO_MAX_TTL
	static const uint32_t SYSINFO_MAX_TTL = 30;//31540000;//30;
#endif

#ifndef SYSINFO_MIN_TTL
	static const uint32_t SYSINFO_MIN_TTL = SYSINFO_MAX_TTL - 10;
#endif

#ifndef MSGPROPERTY_DEFAULT_MAX_TTL
	static const uint32_t MSGPROPERTY_DEFAULT_MAX_TTL_SEC = 30;//31540000;//30;
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

/*
 * The minimum lifetime of a node before it is refreshed
 */
#ifndef NODE_MIN_TTL_SEC
	static const double NODE_MIN_TTL_SEC = NODE_MAX_TTL_SEC - 120;
#endif

#ifndef TOKEN_GRACETIME_SEC
	static const double TOKEN_GRACETIME_SEC = 10;
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
	static const double MISC_MSGPARTCACHE_CLEANUP_INTERVAL_SEC = 5;
#endif

#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */
