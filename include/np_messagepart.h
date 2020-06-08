//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_MESSAGEPART_H_
#define _NP_MESSAGEPART_H_

#include "np_memory.h"

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct np_messagepart_s np_messagepart_t;
typedef np_messagepart_t* np_messagepart_ptr;

struct np_messagepart_s
{
	np_tree_t* header;
	np_tree_t* instructions;
	char uuid[NP_UUID_BYTES];
	uint16_t part;
	void* msg_part;
} NP_API_INTERN;

NP_PLL_GENERATE_PROTOTYPES(np_messagepart_ptr);
_NP_GENERATE_MEMORY_PROTOTYPES(np_messagepart_t);

NP_API_INTERN
int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2);

// encrypt / decrypt parts of a message
NP_API_INTERN
bool _np_messagepart_decrypt(np_state_t* context,
	np_tree_t* source,
	unsigned char* enc_nonce,
	unsigned char* public_key,
	NP_UNUSED unsigned char* secret_key,
	np_tree_t* target);
NP_API_INTERN

bool _np_messagepart_encrypt(np_state_t* context, np_tree_t* msg_part,
	unsigned char* nonce,
	unsigned char* public_key,
	NP_UNUSED unsigned char* secret_key);

NP_API_INTERN
void _np_messagepart_trace_info(char* desc, np_messagepart_t * msg_in);

NP_API_PROTEC
char* np_messagepart_printcache(np_state_t* context, bool asOneLine);
#ifdef __cplusplus
}
#endif

#endif /* NP_MESSAGEPART_H_ */
