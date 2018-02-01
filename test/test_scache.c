//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"

#include "np_scache.h"
#include "np_log.h"


void setup_scache(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_KEY;
	// np_mem_init();
	np_log_init("test_key.log", log_level);

}

void teardown_scache(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}


TestSuite(np_scache_t, .init=setup_scache, .fini=teardown_scache);


Test(np_scache_t, _np_cache_init, .description="test the initialization of a scache")
{
	uint32_t cache_size = 16;
	np_simple_cache_table_t* cache_table = np_cache_init(cache_size);


	cr_expect(cache_size == (sizeof(cache_table->buckets) / sizeof(np_cache_item_ptr_sll_t)), "expect the size of the bucket list to be %d", cache_size);

	for (int i = 0; i < cache_size; i++) {
		cr_expect(0 == sll_size(cache_table->buckets[i]), "expect the size of the each cache list to be zero");
	}
}


