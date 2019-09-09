//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_SHUTDOWN_H_
#define _NP_SHUTDOWN_H_

#include "np_legacy.h"
#include "np_types.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif
	NP_API_EXPORT
		void np_shutdown_add_callback(np_context*ac, np_destroycallback_t clb);

	NP_API_INTERN
		void _np_shutdown_init(np_state_t* context);
	NP_API_INTERN
		void _np_shutdown_destroy(np_state_t* context);
	NP_API_INTERN
		void _np_shutdown_run_callbacks(np_context* context);
	NP_API_INTERN
		void _np_shutdown_notify_others(np_state_t* context);

#ifdef __cplusplus
}
#endif


#endif /* NP_SHUTDOWN_H_ */
