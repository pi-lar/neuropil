//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_DHKEY_H_
#define _NP_DHKEY_H_

#include "np_types.h"
#include "util/np_list.h"

#ifdef __cplusplus
extern "C" {
#endif


	struct np_dhkey_s
	{
		uint32_t t[8];
	} NP_PACKED;

NP_SLL_GENERATE_PROTOTYPES(np_dhkey_t);

static const np_dhkey_t dhkey_zero = {0};
/* key_comp: k1, k2
 * returns > 0 if k1>k2, < 0 if k1<k2, and 0 if k1==k2
 */
NP_API_INTERN
int8_t _np_dhkey_cmp (const np_dhkey_t* const k1, const np_dhkey_t* const k2);

/* some global variables !! that are set in key_init function */
NP_API_INTERN
np_dhkey_t np_dhkey_min(np_state_t* context);
NP_API_INTERN
np_dhkey_t np_dhkey_half(np_state_t* context);
NP_API_INTERN
np_dhkey_t np_dhkey_max(np_state_t* context);

/* key_init:
 * initializes np_dhkey_t*
 */
NP_API_INTERN
bool _np_dhkey_init (np_state_t* context);

NP_API_INTERN
void _np_dhkey_destroy (np_state_t* context);

NP_API_INTERN
np_dhkey_t np_dhkey_create_from_hash(const char* strOrig);
NP_API_INTERN
np_dhkey_t np_dhkey_create_from_hostport(const char* strOrig, const char* port);

/* key_equal:k1, k2
 * return 1 if #k1#==#k2# 0 otherwise
 */
NP_API_INTERN
bool _np_dhkey_equal (const np_dhkey_t* const k1, const np_dhkey_t* const k2);

NP_API_INTERN
void _np_dhkey_sub (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);
NP_API_INTERN
void _np_dhkey_add (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);

/* key_distance:k1,k2
 * calculate the distance between k1 and k2 in the keyspace and assign that to #diff#
 */
NP_API_INTERN
void _np_dhkey_distance (np_dhkey_t* diff, const np_dhkey_t* const k1, const np_dhkey_t* const k2);

NP_API_INTERN
void _np_dhkey_hamming_distance(uint16_t* diff, const np_dhkey_t* const x, const np_dhkey_t* const y);

/* key_between: test, left, right
 * check to see if the value in #test# falls in the range from #left# clockwise
 * around the ring to #right#.
 */
NP_API_INTERN
bool _np_dhkey_between (const np_dhkey_t* const test, const np_dhkey_t* const left, const np_dhkey_t* const right, const bool includeOuterBounds) NP_CONST;

/* key_midpoint: mid, key
 * calculates the midpoint of the namespace from the #key#
 */
NP_API_INTERN
void _np_dhkey_midpoint (np_dhkey_t* mid, const np_dhkey_t* key);

/* key_index: mykey, key
 * returns the length of the longest prefix match between #mykey# and #k#
 */
NP_API_INTERN
uint16_t _np_dhkey_index (const np_dhkey_t* mykey, const np_dhkey_t* k) NP_CONST;
NP_API_INTERN
uint8_t _np_dhkey_hexalpha_at (np_state_t* context, const np_dhkey_t* key, const int8_t c) NP_CONST;

NP_API_INTERN
void _dhkey_print (np_dhkey_t* k) NP_CONST;

/* key_assign: k1, k2
 * copies value of #k2# to #k1#
 */
NP_API_INTERN
void _np_dhkey_assign (np_dhkey_t* k1, const np_dhkey_t* const k2);
NP_API_INTERN
void _np_dhkey_encode(np_state_t* context, np_tree_t* jrb, np_dhkey_t* key);
NP_API_INTERN
void _np_dhkey_str(const np_dhkey_t* k, char* key_string);
NP_API_INTERN
void _np_str_dhkey(const char* key_string, np_dhkey_t* k);

#ifdef __cplusplus
}
#endif


#endif /* _NP_DHKEY_H_ */
