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
	np_special_type = 0,
// 	   short_type,
	int_type,
	long_type,
	long_long_type,
	float_type, //
	double_type, // 5
	char_ptr_type,
    char_type,
	unsigned_char_type,
//     unsigned_short_type, //
    unsigned_int_type,
    unsigned_long_type, // 10
    unsigned_long_long_type,
    int_array_2_type,
    float_array_2_type, //
    char_array_8_type,
    unsigned_char_array_8_type, // 15
    void_type,
    bin_type,
	jrb_tree_type,  //
	key_type,
	npobj_type // 20
} np_jvaltype_t;

/* The Jval -- a type that can hold any 8-byte type */
typedef union jval
{
    // uint8_t sh;
    int16_t i;
    int32_t l;
    int64_t ll;
    float f;
    double d;
    char* s;
    char c;
    unsigned char uc;
    // unsigned short ush;
    uint16_t ui;
    uint32_t ul;
    uint64_t ull;
    int iarray[2];
    float farray[2];
    char carray[8];
    unsigned char ucarray[8];
    void* v;
    void* bin;
    np_jrb_t* tree;
    np_key_t* key;
    np_obj_t* obj;
} jval;

struct np_jval_s {
	int type;
	unsigned long size;
	jval value;
};

extern np_jval_t new_jval_i (int);
extern np_jval_t new_jval_l (long);
extern np_jval_t new_jval_f (float);
extern np_jval_t new_jval_d (double);
extern np_jval_t new_jval_v ( /* void */ );
extern np_jval_t new_jval_bin ( void* data, unsigned long size );
extern np_jval_t new_jval_s (char *);
extern np_jval_t new_jval_c (char);
extern np_jval_t new_jval_uc (unsigned char);
// extern np_jval_t new_jval_sh (short);
// extern np_jval_t new_jval_ush (unsigned short);
extern np_jval_t new_jval_ul (unsigned long);
extern np_jval_t new_jval_ui (unsigned int);
extern np_jval_t new_jval_iarray (int, int);
extern np_jval_t new_jval_farray (float, float);
extern np_jval_t new_jval_carray_nt (char *);	/* Carray is null terminated */
extern np_jval_t new_jval_carray_nnt (char *);	/* Carray is not null terminated */
       /* For ucarray -- use carray, because it uses memcpy */
extern np_jval_t new_jval_tree(np_jrb_t* tree);
extern np_jval_t new_jval_key(np_key_t* key);
extern np_jval_t new_jval_obj(np_obj_t* key);

extern np_jval_t JNULL;

extern int jval_i (np_jval_t);
extern long jval_l (np_jval_t);
extern float jval_f (np_jval_t);
extern double jval_d (np_jval_t);
extern void *jval_v (np_jval_t);
extern char *jval_s (np_jval_t);
extern char jval_c (np_jval_t);
extern unsigned char jval_uc (np_jval_t);
// extern short jval_sh (np_jval_t);
// extern unsigned short jval_ush (np_jval_t);
extern unsigned int jval_ui (np_jval_t);
extern unsigned long jval_ul (np_jval_t);
extern int *jval_iarray (np_jval_t);
extern float *jval_farray (np_jval_t);
extern char *jval_carray (np_jval_t);

#endif // _NP_JVAL_H_
