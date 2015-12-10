/*
Libraries for fields, doubly-linked lists and red-black trees.
Copyright (C) 2001 James S. Plank

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

---------------------------------------------------------------------------
Please see http://www.cs.utk.edu/~plank/plank/classes/cs360/360/notes/Libfdr/
for instruction on how to use this library.

Jim Plank
plank@cs.utk.edu
http://www.cs.utk.edu/~plank

Associate Professor
Department of Computer Science
University of Tennessee
203 Claxton Complex
1122 Volunteer Blvd.
Knoxville, TN 37996-3450

     865-974-4397
Fax: 865-974-4404
 */
#ifndef	_NP_JVAL_H_
#define	_NP_JVAL_H_

#include "stdint.h"

#include "cmp.h"
#include "include.h"


enum {
	none_type = 0,
    short_type,
	int_type,
	long_type,
	long_long_type,
	float_type, // 5
	double_type, //
	char_ptr_type,
    char_type,
	unsigned_char_type,
    unsigned_short_type, // 10
    unsigned_int_type,
    unsigned_long_type, //
    unsigned_long_long_type,
    uint_array_2_type,
    float_array_2_type, // 15
    char_array_8_type,
    unsigned_char_array_8_type, //
    void_type,
    bin_type,
	jrb_tree_type,  // 20
	key_type,
	npobj_type
} np_jvaltype_t;

/* The Jval -- a type that can hold any 8-byte type */
typedef union jval
{	// put void pointer first to enforce zero initialization of union
    void* v;
    void* bin;
    np_jtree_t* tree;
    np_key_t* key;
    np_obj_t* obj;
    int8_t sh;
    int16_t i;
    int32_t l;
    int64_t ll;
    float f;
    double d;
    char* s;
    char c;
    unsigned char uc;
    uint8_t ush;
    uint16_t ui;
    uint32_t ul;
    uint64_t ull;
    uint16_t a2_ui[2];
    float farray[2];
    char carray[8];
    unsigned char ucarray[8];
} jval;

struct np_jval_s {
	uint8_t type;
	uint32_t size;
	jval value;
};

np_jval_t copy_of_jval(np_jval_t from);

np_jval_t new_jval_sh (int8_t);
np_jval_t new_jval_i (int16_t);
np_jval_t new_jval_l (int32_t);
np_jval_t new_jval_ll (int64_t);
np_jval_t new_jval_f (float);
np_jval_t new_jval_d (double);
np_jval_t new_jval_v (void* v);
np_jval_t new_jval_bin (void* data, uint32_t size);
np_jval_t new_jval_s (char *);
np_jval_t new_jval_c (char);
np_jval_t new_jval_uc (unsigned char);
np_jval_t new_jval_ush (uint8_t);
np_jval_t new_jval_ui (uint16_t);
np_jval_t new_jval_ul (uint32_t);
np_jval_t new_jval_ull (uint64_t);
np_jval_t new_jval_iarray (uint16_t, uint16_t);
np_jval_t new_jval_farray (float, float);
np_jval_t new_jval_carray_nt (char *);	/* Carray is null terminated */
np_jval_t new_jval_carray_nnt (char *);	/* Carray is not null terminated */
       /* For ucarray -- use carray, because it uses memcpy */
np_jval_t new_jval_tree(np_jtree_t* tree);
np_jval_t new_jval_key(np_key_t* key);
np_jval_t new_jval_obj(np_obj_t* key);

np_jval_t JNULL;

int16_t jval_i (np_jval_t);
int32_t jval_l (np_jval_t);
float jval_f (np_jval_t);
double jval_d (np_jval_t);
void *jval_v (np_jval_t);
char *jval_s (np_jval_t);
char jval_c (np_jval_t);
unsigned char jval_uc (np_jval_t);
// short jval_sh (np_jval_t);
// unsigned short jval_ush (np_jval_t);
uint16_t jval_ui (np_jval_t);
uint32_t jval_ul (np_jval_t);
int16_t *jval_iarray (np_jval_t);
float *jval_farray (np_jval_t);
char *jval_carray (np_jval_t);

char* jval_to_str(np_jval_t val);

#endif // _NP_JVAL_H_
