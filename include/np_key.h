//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#ifndef _NP_KEY_H_
#define _NP_KEY_H_

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_dhkey_s
{
    uint64_t t[4];
};

/** key_comp: k1, k2
 ** returns > 0 if k1>k2, < 0 if k1<k2, and 0 if k1==k2
 **/
NP_API_INTERN
int8_t _dhkey_comp (const np_dhkey_t* const k1, const np_dhkey_t* const k2);

/* some global variables !! that are set in key_init function */
NP_API_INTERN
np_dhkey_t dhkey_min();
NP_API_INTERN
np_dhkey_t dhkey_half();
NP_API_INTERN
np_dhkey_t dhkey_max();

/** key_init:
 ** initializes np_dhkey_t*
 **/
NP_API_INTERN
void _dhkey_init ();

NP_API_INTERN
np_dhkey_t dhkey_create_from_hash(const char* strOrig);
NP_API_INTERN
np_dhkey_t dhkey_create_from_hostport(const char* strOrig, char* port);

/** key_equal:k1, k2
 ** return 1 if #k1#==#k2# 0 otherwise
 **/
NP_API_INTERN
np_bool _dhkey_equal (np_dhkey_t* k1, np_dhkey_t* k2) NP_CONST;

/** key_equal_ui: k1, ul
 ** return 1 if the least significant 32 bits of #k1#==#ul# 0 otherwise
 **/
NP_API_INTERN
np_bool _dhkey_equal_ui (np_dhkey_t* k, uint64_t ul) NP_CONST NP_DEPRECATED;

NP_API_INTERN
void _dhkey_sub (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);
NP_API_INTERN
void _dhkey_add (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);

/** key_distance:k1,k2
 ** calculate the distance between k1 and k2 in the keyspace and assign that to #diff#
 **/
NP_API_INTERN
void _dhkey_distance (np_dhkey_t* diff, const np_dhkey_t* const k1, const np_dhkey_t* const k2);

/** key_between: test, left, right
 ** check to see if the value in #test# falls in the range from #left# clockwise
 ** around the ring to #right#.
 **/
NP_API_INTERN
np_bool _dhkey_between (const np_dhkey_t* const test, const np_dhkey_t* const left, const np_dhkey_t* const right) NP_CONST;

/** key_midpoint: mid, key
 ** calculates the midpoint of the namespace from the #key#
 **/
NP_API_INTERN
void _dhkey_midpoint (np_dhkey_t* mid, const np_dhkey_t* key);

/** key_index: mykey, key
 ** returns the length of the longest prefix match between #mykey# and #k#
 **/
NP_API_INTERN
uint16_t _dhkey_index (const np_dhkey_t* mykey, const np_dhkey_t* k) NP_CONST;
NP_API_INTERN
uint8_t _dhkey_hexalpha_at (const np_dhkey_t* key, const int8_t c) NP_CONST;

// scan a key string to its struct representation
NP_API_INTERN
void _str_to_dhkey (const char *dhkey_string, np_dhkey_t *k);

// always use this function to get the string representation of a key
NP_API_INTERN
void _dhkey_to_str (const np_dhkey_t * k, char* str);

NP_API_INTERN
void _dhkey_print (np_dhkey_t* k) NP_CONST;

/** key_assign: k1, k2
 ** copies value of #k2# to #k1#
 **/
NP_API_INTERN
void _dhkey_assign (np_dhkey_t* k1, const np_dhkey_t* const k2);
/** key_assign_ui: k1, ul
 ** copies #ul# to the least significant 32 bits of #k#
 **/
NP_API_INTERN
void _dhkey_assign_ui (np_dhkey_t * k, uint64_t ul);

NP_API_INTERN
void _np_key_destroy(np_key_t* to_destroy);

#ifdef __cplusplus
}
#endif


#endif /* _NP_KEY_H_ */
