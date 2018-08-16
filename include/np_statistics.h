//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_STATISTICS_H_
#define NP_STATISTICS_H_

#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <float.h>


#include "neuropil.h"
#include "np_types.h"
#include "np_util.h"
#include "np_list.h"
#include "np_scache.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_performance.h"


#ifdef __cplusplus
extern "C" {
#endif 

	np_module_struct(statistics) {
		np_state_t* context;
		np_simple_cache_table_t* __cache;
		np_sll_t(char_ptr, __watched_subjects);

		TSP(double, __forwarding_counter);

		TSP(uint32_t, __network_send_bytes);

		double __network_send_bytes_per_sec_r;
		double __network_send_bytes_per_sec_last;
		uint32_t __network_send_bytes_per_sec_remember;

		TSP(uint32_t, __network_received_bytes);

		double __network_received_bytes_per_sec_r;
		double __network_received_bytes_per_sec_last;
		uint32_t __network_received_bytes_per_sec_remember;

#ifdef NP_BENCHMARKING
		np_statistics_performance_point_t * performance_points[np_statistics_performance_point_END];
#endif

#ifdef DEBUG_CALLBACKS
		np_sll_t(void_ptr, __np_debug_statistics);
#endif
	};

	NP_API_INTERN
		bool _np_statistics_init(np_state_t* context);

	NP_API_EXPORT
		void np_statistics_add_watch(np_state_t* context, char* subject);

	NP_API_EXPORT
		char * np_statistics_print(np_state_t* context, bool asOneLine);

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
