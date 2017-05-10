/*
 * np_messagepart.c
 *
 *  Created on: 10.05.2017
 *      Author: sklampt
 */

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_log.h"

#include "np_messagepart.h"

_NP_MODULE_LOCK_IMPL(np_messagesgpart_cache_t);
NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2)
{
	uint16_t part_1 = value1->part; // tree_find_str(value1->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];
	uint16_t part_2 = value2->part; // tree_find_str(value2->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];

	log_msg(LOG_MESSAGE | LOG_DEBUG, "message part compare %d / %d / %d", part_1, part_2, part_1 - part_2);

	if (part_2 > part_1) return ( 1);
	if (part_1 > part_2) return (-1);
	return (0);
}


