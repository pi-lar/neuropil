//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_SHUTDOWN_MSG_H_
#define NP_SHUTDOWN_MSG_H_

#include "neuropil.h"
#include "np_types.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif
	NP_API_INTERN
	void _np_shutdown_init_auto_notify_others();
	NP_API_INTERN
	void _np_shutdown_deinit();
	NP_API_PROTEC
	void np_shutdown_notify_others();


#ifdef __cplusplus
}
#endif


#endif /* NP_SHUTDOWN_MSG_H_ */
