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
// #include <openssl/evp.h>
#include <string.h>

#include "include.h"

#include "np_container.h"
#include "np_memory.h"
#include "np_jtree.h"


struct np_key_s
{
    np_obj_t* obj;            // link to memory management and ref counter

    SPLAY_ENTRY(np_key_s) link; // link for cache management

    uint64_t t[8];
    unsigned char keystr[65]; // string representation of key in hex
    np_bool valid;		  // indicates if the keystr is most up to date with value in t

    np_node_t* node;		    // link to a neuropil node if this key represents a node

    np_msgproperty_t* recv_property;
    np_msgproperty_t* send_property;
    np_sll_t(np_aaatoken_t, recv_tokens); // link to runtime interest data on which this node is interested in
    np_sll_t(np_aaatoken_t, send_tokens); // link to runtime interest data on which this node is interested in

    np_aaatoken_t* authentication; // link to node if this key has an authentication token
    np_aaatoken_t* authorisation;  // link to node if this key has an authorisation token
    np_aaatoken_t* accounting;     // link to node if this key has an accounting token
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_key_t);

/** key_comp: k1, k2
 ** returns > 0 if k1>k2, < 0 if k1<k2, and 0 if k1==k2
 **/
int8_t key_comp (const np_key_t* const k1, const np_key_t* const k2);

/* global variables!! that are set in key_init function */
np_key_t Key_Half;
np_key_t Key_Max;

/** key_init:
 ** initializes np_key_t* 
 **/
void key_init ();

np_key_t* key_create_from_hash(const char* strOrig);
np_key_t* key_create_from_hostport(const char* strOrig, char* port);

/** key_equal:k1, k2
 ** return 1 if #k1#==#k2# 0 otherwise
 **/
np_bool key_equal (np_key_t* k1, np_key_t* k2);
/** key_equal_ui:k1, ul
 ** return 1 if the least significat 32 bits of #k1#==#ul# 0 otherwise
 **/
np_bool key_equal_ui (np_key_t* k, uint64_t ul);

void np_encode_key(np_jtree_t* jrb, np_key_t* key);
void np_decode_key(np_jtree_t* jrb, np_key_t* key);

/** key_distance:k1,k2
 ** calculate the distance between k1 and k2 in the keyspace and assign that to #diff#
 **/
void key_distance (np_key_t* diff, const np_key_t* const k1, const np_key_t* const k2);
/** key_between: test, left, right
 ** check to see if the value in #test# falls in the range from #left# clockwise
 ** around the ring to #right#.
 **/
np_bool key_between (const np_key_t* const test, const np_key_t* const left, const np_key_t* const right);
/** key_midpoint: mid, key
 ** calculates the midpoint of the namespace from the #key#
 **/
void key_midpoint (np_key_t* mid, np_key_t* key);
/** key_index: mykey, key
 ** returns the lenght of the longest prefix match between #mykey# and #k#
 **/
uint16_t key_index (np_key_t* mykey, np_key_t* k);

// scan a key string to its struct representation
void str_to_key (np_key_t *k, const char *key_string);

void  key_print (np_key_t* k);
// always use this function to get the string representation of a key
unsigned char* key_get_as_string (np_key_t * k);

/** key_assign: k1, k2
 ** copies value of #k2# to #k1#
 **/
void key_assign (np_key_t* k1, const np_key_t* const k2);
/** key_assign_ui: k1, ul
 ** copies #ul# to the least significant 32 bits of #k#
 **/
void key_assign_ui (np_key_t * k, uint64_t ul);

// TODO: this needs to be refactored: closest distance clock- or counterclockwise ?
// will have an important effect on routing decisions
np_key_t* find_closest_key (np_sll_t(np_key_t, list_of_keys), np_key_t* key);
void sort_keys_cpm (np_sll_t(np_key_t, node_keys), np_key_t* key);
void sort_keys_kd (np_sll_t(np_key_t, list_of_keys), np_key_t* key);


#endif /* _NP_KEY_H_ */
