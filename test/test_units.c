//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "../include/np_settings.h"
#include "test_macros.c"

// Criterion Tests
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
#include "unit/test_memory.c"
#endif

#include "unit/test_aaatoken.c"
#include "unit/test_key.c"
#include "unit/test_dhkey.c"
#include "unit/test_jrb_impl.c"
#include "unit/test_jrb_serialization.c"
#include "unit/test_keycache.c"
#include "unit/test_list_impl.c"
			  
#include "unit/test_message.c"
#include "unit/test_node.c"
#include "unit/test_route.c"
#include "unit/test_util_uuid.c"
#include "unit/test_sodium_crypt.c"
#include "unit/test_scache.c"
#include "unit/test_heap.c"
