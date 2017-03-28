//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
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

#ifndef	_NP_VAL_H_
#define	_NP_VAL_H_

#include "stdint.h"

#include "msgpack/cmp.h"

#include "np_key.h"
#include "np_memory.h"
#include "np_types.h"

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
	hash_type,
	npobj_type,
	npval_count
} np_valtype_t;

/* The Jval -- a type that can hold any type */
typedef union val
{	// put void pointer first to enforce zero initialization of union
    void* v;
    void* bin;
    np_tree_t* tree;
    np_dhkey_t key;
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
} val;

struct np_val_s
{
	uint8_t  type;
	uint32_t size;
	val      value;
};

np_val_t copy_of_val(np_val_t from);

np_val_t new_val_sh (int8_t);
np_val_t new_val_i (int16_t);
np_val_t new_val_l (int32_t);
np_val_t new_val_ll (int64_t);
np_val_t new_val_f (float);
np_val_t new_val_d (double);
np_val_t new_val_v (void* v);
np_val_t new_val_bin (void* data, uint32_t size);
np_val_t new_val_s (char *);
np_val_t new_val_c (char);
np_val_t new_val_uc (unsigned char);
np_val_t new_val_ush (uint8_t);
np_val_t new_val_ui (uint16_t);
np_val_t new_val_ul (uint32_t);
np_val_t new_val_ull (uint64_t);
np_val_t new_val_iarray (uint16_t, uint16_t);
np_val_t new_val_farray (float, float);
np_val_t new_val_carray_nt (char *);	/* Carray is null terminated */
np_val_t new_val_carray_nnt (char *);	/* Carray is not null terminated */
       /* For ucarray -- use carray, because it uses memcpy */
np_val_t new_val_tree(np_tree_t* tree);
np_val_t new_val_hash(char* h_val);
np_val_t new_val_pwhash (char *pw_key);
np_val_t new_val_key(np_dhkey_t key);
np_val_t new_val_obj(np_obj_t* obj);

np_val_t NP_VAL_NULL;

#endif // _NP_JVAL_H_
