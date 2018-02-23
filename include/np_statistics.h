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
		np_bool np_statistics_init();

	NP_API_EXPORT
		void np_statistics_add_watch(char* subject);

	NP_API_EXPORT
		char * np_statistics_print(np_bool asOneLine);

	NP_API_EXPORT
		void np_statistics_add_watch_internals();

#ifdef DEBUG
	NP_API_INTERN
		void _np_increment_forwarding_counter();
#endif // DEBUG

	

#ifdef __cplusplus
}
#endif

#endif /* NP_STATISTICS_H_ */
