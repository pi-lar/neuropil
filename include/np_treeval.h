//
// neuropil is copyright 2016-2019 by pi-lar GmbH
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

#ifndef	_NP_TREEVAL_H_
#define	_NP_TREEVAL_H_

#include "stdint.h"

#include "msgpack/cmp.h"

#include "np_dhkey.h"
#include "np_memory.h"

#include "np_types.h"

enum np_treeval_type_t {
	np_treeval_type_undefined = 0,
    np_treeval_type_short,
	np_treeval_type_int,
	np_treeval_type_long,
	np_treeval_type_long_long,
	np_treeval_type_float, // 5
	np_treeval_type_double, //
	np_treeval_type_char_ptr,
    np_treeval_type_char,
	np_treeval_type_unsigned_char,
    np_treeval_type_unsigned_short, // 10
    np_treeval_type_unsigned_int,
    np_treeval_type_unsigned_long, //
    np_treeval_type_unsigned_long_long,
    np_treeval_type_uint_array_2,
    np_treeval_type_float_array_2, // 15
    np_treeval_type_char_array_8,
    np_treeval_type_unsigned_char_array_8, //
    np_treeval_type_void,
    np_treeval_type_bin,
	np_treeval_type_jrb_tree,  // 20
	np_treeval_type_dhkey,
	np_treeval_type_hash,
	np_treeval_type_npobj,
	np_treeval_type_npval_count,
	np_treeval_type_special_char_ptr,
} np_treeval_type_t;

/* The Jval -- a type that can hold any type */
typedef union val_type
{	// put void pointer first to enforce zero initialization of union
    void* v;
    void* bin;
    np_tree_t* tree;
    np_dhkey_t dhkey;
    
    int8_t sh;
    int16_t i;
    int32_t l;
#ifdef x64
    int64_t ll;
#endif
    float f;
    double d;
	/* To access the string value please use 
		function:np_treeval_to_str()
	*/
    char* s;
    char c;
    unsigned char uc;
    uint8_t ush;
    uint16_t ui;
    uint32_t ul;
#ifdef x64
    uint64_t ull;
#endif
    uint16_t a2_ui[2];
    float farray[2];
    char carray[8];
    unsigned char ucarray[8];
} val;
	   
struct np_treeval_s
{
	uint8_t  type;
	uint32_t size;
	val      value;
};

np_treeval_t np_treeval_copy_of_val(np_treeval_t from) ;

np_treeval_t np_treeval_new_sh (int8_t sh);
np_treeval_t np_treeval_new_i (int16_t i);
np_treeval_t np_treeval_new_l (int32_t l);
#ifdef x64
np_treeval_t np_treeval_new_ll (int64_t ll);
#endif
np_treeval_t np_treeval_new_f (float f);
np_treeval_t np_treeval_new_d (double d);
np_treeval_t np_treeval_new_v (void* v);
np_treeval_t np_treeval_new_bin (void* data, uint32_t size);
np_treeval_t np_treeval_new_s (char * s);
np_treeval_t np_treeval_new_ss(uint8_t idx);
np_treeval_t np_treeval_new_c (char c);
np_treeval_t np_treeval_new_uc (unsigned char uc);
np_treeval_t np_treeval_new_ush (uint8_t ush);
np_treeval_t np_treeval_new_ui (uint16_t ui);
np_treeval_t np_treeval_new_ul (uint32_t ul);
#ifdef x64
np_treeval_t np_treeval_new_ull (uint64_t ull);
#endif
np_treeval_t np_treeval_new_iarray (uint16_t i0, uint16_t i1);
np_treeval_t np_treeval_new_farray (float f0, float f1);
np_treeval_t np_treeval_new_carray_nt (char * carray);	/* Carray is null terminated */
np_treeval_t np_treeval_new_carray_nnt (char * carray);	/* Carray is not null terminated */
       /* For ucarray -- use carray, because it uses memcpy */
np_treeval_t np_treeval_new_tree(np_tree_t* tree);
np_treeval_t np_treeval_new_hash(char* h_val);
np_treeval_t np_treeval_new_dhkey(np_dhkey_t dhkey);
uint32_t np_treeval_get_byte_size(np_treeval_t ele);

static const np_treeval_t np_treeval_NULL = { .type = np_treeval_type_undefined,.size = 0 };

int16_t  np_treeval_i (np_treeval_t);
int32_t  np_treeval_l (np_treeval_t);
uint16_t np_treeval_ui (np_treeval_t);
uint32_t np_treeval_ul (np_treeval_t);

float  np_treeval_f (np_treeval_t);
double np_treeval_d (np_treeval_t);

void * np_treeval_v (np_treeval_t);

char * np_treeval_str (np_treeval_t);
char  np_treeval_c (np_treeval_t);
char * np_treeval_h (np_treeval_t);
unsigned char np_treeval_uc (np_treeval_t);

// int16_t * np_treeval_iarray (np_treeval_t);
float   * np_treeval_farray (np_treeval_t);
char    * np_treeval_carray (np_treeval_t);
char    * np_treeval_to_str(np_treeval_t val, bool* freeable);

#endif // _NP_TREEVAL_H_
