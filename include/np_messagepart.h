/*
 * np_messagepart.h
 *
 *  Created on: 10.05.2017
 *      Author: sklampt
 */

#ifndef NP_MESSAGEPART_H_
#define NP_MESSAGEPART_H_

#include "np_memory.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct np_messagepart_s np_messagepart_t;
typedef np_messagepart_t* np_messagepart_ptr;

struct np_messagepart_s
{
	np_obj_t* obj;

	np_tree_t* header;
	np_tree_t* instructions;
	uint16_t part;
	void* msg_part;
} NP_API_INTERN;

NP_PLL_GENERATE_PROTOTYPES(np_messagepart_ptr);
_NP_GENERATE_MEMORY_PROTOTYPES(np_messagepart_t);

NP_API_INTERN
int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2);

// encrypt / decrypt parts of a message
NP_API_INTERN
np_bool _np_messagepart_decrypt(np_tree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
NP_API_INTERN
np_bool _np_messagepart_encrypt(np_tree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
NP_API_INTERN
char* np_messagepart_printcache(np_bool asOneLine);
#ifdef __cplusplus
}
#endif

#endif /* NP_MESSAGEPART_H_ */
