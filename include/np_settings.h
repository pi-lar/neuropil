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
 *
 *	set before slave enable
 */
double SYSINFO_PROACTIVE_SEND_IN_SEC = 1;

#ifdef __cplusplus
}
#endif

#endif /* NP_SETTINGS_H_ */
