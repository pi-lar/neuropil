/*
** $Id: key.h,v 1.16 2006/06/07 09:21:28 krishnap Exp $
**
** Matthew Allen
** description: 
*/

#ifndef _NP_KEY_H_
#define _NP_KEY_H_

#include <limits.h>
#include <stdio.h>
#include <openssl/evp.h>
#include <string.h>

#define KEY_SIZE 160

// Changed this to 2 for base4 and 4 to have keys in base 16; Only these two are supported right now
#define BASE_B 4		/* Base representation of key digits */

#define BASE_16_KEYLENGTH 40

#define BASE_2 2
#define BASE_4 4
#define BASE_16 16

#define IS_BASE_2 (power(2, BASE_B) == BASE_2)
#define IS_BASE_4 (power(2, BASE_B) == BASE_4)
#define IS_BASE_16 (power(2, BASE_B) == BASE_16)

typedef struct Key
{
    unsigned long t[4];
    unsigned char keystr[65];	/* string representation of key in hex */
    short int valid;		// indicates if the keystr is most up to date with value in key
} Key;


/* global variables!! that are set in key_init function */
Key Key_Max;
Key Key_Half;


/** key_init:
 ** initializes Key_Max and Key_Half
 **/
void key_init ();

Key* key_create_from_hash(const unsigned char* strOrig);
Key* key_create_from_hostport(const char* strOrig, int port);

/** key_equal:k1, k2
 ** return 1 if #k1#==#k2# 0 otherwise
 **/
int key_equal (Key* k1, Key* k2);
/** key_equal_ui:k1, ul
 ** return 1 if the least significat 32 bits of #k1#==#ul# 0 otherwise
 **/
int key_equal_ui (Key* k, unsigned long ul);
/** key_comp: k1, k2
 ** returns >0 if k1>k2, <0 if k1<k2, and 0 if k1==k2
 **/
int key_comp (const Key* const k1, const Key* const k2);


/** key_distance:k1,k2
 ** calculate the distance between k1 and k2 in the keyspace and assign that to #diff#
 **/
void key_distance (Key* diff, const Key* const k1, const Key* const k2);
/** key_between: test, left, right
 ** check to see if the value in #test# falls in the range from #left# clockwise
 ** around the ring to #right#.
 **/
int key_between (const Key* const test, const Key* const left, const Key* const right);
/** key_midpoint: mid, key
 ** calculates the midpoint of the namespace from the #key#
 **/
void key_midpoint (Key* mid, Key* key);
/** key_index: mykey, key
 ** returns the lenght of the longest prefix match between #mykey# and #k#
 **/
int key_index (Key* mykey, Key* k);

// scan a key string to its struct representation
void str_to_key (Key *k, const char *key_string);

/* key_makehash: hashed, s
** assign sha1 hash of the string #s# to #hashed# */
// void key_makehash (Key * hashed, char *s);
/* key_make_hash */
// void key_make_hash (Key * hashed, char *s, size_t size);

void  key_print (Key* k);
// void  key_to_str (Key* k);
unsigned char* key_get_as_string (Key * k);	// always use this function to get the string representation of a key

/** key_assign: k1, k2
 ** copies value of #k2# to #k1#
 **/
void key_assign (Key* k1, const Key* const k2);
/** key_assign_ui: k1, ul
 ** copies #ul# to the least significant 32 bits of #k#
 **/
void key_assign_ui (Key * k, unsigned long ul);

int power (int base, int n);


#endif /* _NP_KEY_H_ */
