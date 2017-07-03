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
	static const int SYSINFO_PROACTIVE_SEND_IN_SEC = 1;
#endif


/*
 * The maximum lifetime of a node before it is refreshed
 */
#ifndef NODE_MAX_TTL_SEC
	static const double NODE_MAX_TTL_SEC = 3*60; //3600; // 3600 = 1h
#endif

/*
 * The minimum lifetime of a node before it is refreshed
 */
#ifndef NODE_MIN_TTL_SEC
	static const double NODE_MIN_TTL_SEC = 2*60; //3480; // 3480 = 58min
#endif

#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */
