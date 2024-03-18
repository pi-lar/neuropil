//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "test_macros.c"

#include "../include/np_settings.h"

// Criterion Tests
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
#include "unit/test_memory.c"
#endif

#include "unit/test_aaatoken.c"
#include "unit/test_bloom.c"
#include "unit/test_cupidbloom.c"
#include "unit/test_cupidtrie.c"
#include "unit/test_dhkey.c"
// #include "unit/test_heap.c" // TODO: fixme
#include "unit/test_jrb_impl.c"
#include "unit/test_jrb_serialization.c"
#include "unit/test_key.c"
#include "unit/test_keycache.c"
#include "unit/test_list_impl.c"
// #include "unit/test_memory.c"  // TODO: fixme
#include "unit/test_message.c"
#include "unit/test_minhash.c"
#include "unit/test_node.c"
#include "unit/test_route.c"
#include "unit/test_util_uuid.c"

#include "unit/test_neuropil_h.c"
// #include "unit/test_sodium_crypt.c" // TODO: fixme on linux!
#include "unit/test_pheromone.c"
#include "unit/test_scache.c"
#include "unit/test_skiplist.c"
#include "unit/test_statemachine.c"

// #include "unit/test_m_jobqueue.c" // TODO: does currently not hold any
// meaningful test
#include "unit/test_m_identity.c"

#include "unit/test_neuropil_attributes.c"
#include "unit/test_neuropil_data.c"
