//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_STATISTICS_H_
#define NP_STATISTICS_H_

#include <stdlib.h>

#include "neuropil.h"
#include "np_types.h"


#ifdef __cplusplus
extern "C" {
#endif
	NP_API_INTERN
		np_bool np_statistics_init(np_state_t* context);

	NP_API_EXPORT
		void np_statistics_add_watch(np_state_t* context, char* subject);

	NP_API_EXPORT
		char * np_statistics_print(np_state_t* context, np_bool asOneLine);

	NP_API_EXPORT
		void np_statistics_add_watch_internals(np_state_t* context);

#ifdef NP_STATISTICS_COUNTER
	NP_API_INTERN
		void __np_increment_forwarding_counter(np_state_t* context);
	NP_API_INTERN
		void __np_statistics_add_send_bytes(np_state_t* context, uint32_t add);
	NP_API_INTERN
		void __np_statistics_add_received_bytes(np_state_t* context, uint32_t add);

	#define _np_increment_forwarding_counter() __np_increment_forwarding_counter(context)
	#define _np_statistics_add_send_bytes(add) __np_statistics_add_send_bytes(context, add)
	#define _np_statistics_add_received_bytes(add) __np_statistics_add_received_bytes(context, add)
#else
	#define _np_increment_forwarding_counter() 
	#define _np_statistics_add_send_bytes(add) 
	#define _np_statistics_add_received_bytes(add) 
#endif // DEBUG

	

#ifdef __cplusplus
}
#endif

#endif /* NP_STATISTICS_H_ */
