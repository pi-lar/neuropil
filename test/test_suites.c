//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "../include/np_settings.h"
#include "test_macros.c"

// Criterion Tests
#ifdef NP_MEMORY_CHECK_MEMORY_REFFING
#include "test_memory.c"
#endif

#include "test_aaatoken.c"
#include "test_key.c"
#include "test_dhkey.c"
#include "test_jrb_impl.c"
#include "test_jrb_serialization.c"
#include "test_keycache.c"
#include "test_list_impl.c"



#include "test_message.c"
#include "test_node.c"
#include "test_route.c"
#include "test_util_uuid.c"
#include "test_sodium_crypt.c"
#include "test_scache.c"

// NON Criterion Tests
/*
#include "ipv6_addrinfo.c"
#include "jrb_test_msg.c"
#include "test_chunk_message.c"
#include "test_dh.c"
#include "test_sodium_crypt.c"
*/
