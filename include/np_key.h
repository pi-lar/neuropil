/**
 *  copyright 2015 pi-lar GmbH
 *  original version was taken from chimera project (MIT licensed), but heavily modified
 *  Stephan Schwichtenberg
 **/

#ifndef _NP_KEY_H_
#define _NP_KEY_H_

#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "include.h"


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
int8_t _dhkey_comp (const np_dhkey_t* const k1, const np_dhkey_t* const k2);

/* some global variables !! that are set in key_init function */
np_dhkey_t dhkey_min();
np_dhkey_t dhkey_half();
np_dhkey_t dhkey_max();

/** key_init:
 ** initializes np_dhkey_t*
 **/
void _dhkey_init ();

np_dhkey_t dhkey_create_from_hash(const char* strOrig);
np_dhkey_t dhkey_create_from_hostport(const char* strOrig, char* port);

/** key_equal:k1, k2
 ** return 1 if #k1#==#k2# 0 otherwise
 **/
np_bool _dhkey_equal (np_dhkey_t* k1, np_dhkey_t* k2);

/** key_equal_ui: k1, ul
 ** return 1 if the least significant 32 bits of #k1#==#ul# 0 otherwise
 **/
np_bool _dhkey_equal_ui (np_dhkey_t* k, uint64_t ul);

void _np_encode_dhkey(np_jtree_t* jrb, np_dhkey_t* key);
void _np_decode_dhkey(np_jtree_t* jrb, np_dhkey_t* key);

void _dhkey_sub (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);
void _dhkey_add (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2);

/** key_distance:k1,k2
 ** calculate the distance between k1 and k2 in the keyspace and assign that to #diff#
 **/
void _dhkey_distance (np_dhkey_t* diff, const np_dhkey_t* const k1, const np_dhkey_t* const k2);

/** key_between: test, left, right
 ** check to see if the value in #test# falls in the range from #left# clockwise
 ** around the ring to #right#.
 **/
np_bool _dhkey_between (const np_dhkey_t* const test, const np_dhkey_t* const left, const np_dhkey_t* const right);

/** key_midpoint: mid, key
 ** calculates the midpoint of the namespace from the #key#
 **/
void _dhkey_midpoint (np_dhkey_t* mid, const np_dhkey_t* key);

/** key_index: mykey, key
 ** returns the length of the longest prefix match between #mykey# and #k#
 **/
uint16_t _dhkey_index (const np_dhkey_t* mykey, const np_dhkey_t* k);
uint8_t _dhkey_hexalpha_at (const np_dhkey_t* key, const int8_t c);

// scan a key string to its struct representation
void _str_to_dhkey (const char *dhkey_string, np_dhkey_t *k);

// always use this function to get the string representation of a key
void _dhkey_to_str (const np_dhkey_t * k, char* str);

void _dhkey_print (np_dhkey_t* k);

/** key_assign: k1, k2
 ** copies value of #k2# to #k1#
 **/
void _dhkey_assign (np_dhkey_t* k1, const np_dhkey_t* const k2);
/** key_assign_ui: k1, ul
 ** copies #ul# to the least significant 32 bits of #k#
 **/
void _dhkey_assign_ui (np_dhkey_t * k, uint64_t ul);


#ifdef __cplusplus
}
#endif


#endif /* _NP_KEY_H_ */
