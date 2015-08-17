#include <stdio.h>
#include <pthread.h>

#include "jval.h"
#include "np_jtree.h"
#include "log.h"

np_jval_t JNULL;

void copy_jval(np_jval_t* from, np_jval_t* to) {

	switch(from->type) {
		// length is always 1 (to identify the type) + the length of the type
  		case short_type:
			to->type = short_type;
			to->value.sh = from->value.sh;
			to->size = sizeof(int8_t);
			break;
		case int_type:
			to->type = int_type;
			to->value.i = from->value.i;
			to->size = sizeof(int16_t);
			break;
		case long_type:
			to->type = long_type;
			to->value.l = from->value.l;
			to->size = sizeof(int32_t);
			break;
		case long_long_type:
			to->type = long_long_type;
			to->value.ll = from->value.ll;
			to->size = sizeof(int64_t);
			break;
 		case float_type:
			to->type = float_type;
			to->value.f = from->value.f;
			to->size = sizeof(float);
			break;
		case double_type:
			to->type = double_type;
			to->value.d = from->value.d;
			to->size = sizeof(double);
			break;
		case char_ptr_type:
			to->type = char_ptr_type;
			to->value.s = strndup(from->value.s, from->size);
			to->size = from->size;
			break;
		case char_type:
			to->type = char_type;
			to->value.c = from->value.c;
			to->size = sizeof(char);
			break;
		case unsigned_char_type:
			to->type = unsigned_char_type;
			to->value.uc = from->value.uc;
			to->size = sizeof(unsigned char);
			break;
 		case unsigned_short_type:
 			to->type = unsigned_short_type;
 			to->value.ush = from->value.ush;
 			to->size = sizeof(uint8_t);
 			break;
 		case unsigned_int_type:
			to->type = unsigned_int_type;
			to->value.ui = from->value.ui;
			to->size = sizeof(uint16_t);
			break;
		case unsigned_long_type:
			to->type = unsigned_long_type;
			to->value.ul = from->value.ul;
			to->size = sizeof(uint32_t);
			break;
		case unsigned_long_long_type:
			to->type = unsigned_long_long_type;
			to->value.ull = from->value.ull;
			to->size = sizeof(uint64_t);
			break;
// 		case int_array_2_type:    byte_size += 1 + 2*sizeof(int); break;
// 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
// 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
// 		case unsigned_char_array_8_type: byte_size += 1 +8*sizeof(unsigned char); break;
 		case void_type:
			to->type = void_type;
			to->value.v = from->value.v;
			to->size = from->size;
			break;
 		case bin_type:
			to->type = bin_type;
			to->value.bin = from->value.bin;
			to->size = from->size;
			break;
 		case jrb_tree_type:
			to->type = jrb_tree_type;
			to->value.v = from->value.v;
			to->size = from->size;
			break;
		case key_type:
			to->type = key_type;
			to->value.key = from->value.key;
			to->size = sizeof(np_key_t);
			break;
		default:
			log_msg(LOG_WARN, "unsupported copy operation for jval type %hhd", from->type);
			break;
	}

}

np_jval_t new_jval_i (int16_t i)
{
    np_jval_t j;
    j.value.i = i;
    j.type = int_type;
    j.size = sizeof(int16_t);
    return j;
}

np_jval_t new_jval_l (int32_t l)
{
    np_jval_t j;
    j.value.l = l;
    j.type = long_type;
    j.size = sizeof(int32_t);
    return j;
}

np_jval_t new_jval_ll (int64_t ll)
{
    np_jval_t j;
    j.value.ll = ll;
    j.type = long_long_type;
    j.size = sizeof(int64_t);
    return j;
}

np_jval_t new_jval_f (float f)
{
    np_jval_t j;
    j.value.f = f;
    j.type = float_type;
    j.size = sizeof(float);
    return j;
}

np_jval_t new_jval_d (double d)
{
    np_jval_t j;
    j.value.d = d;
    j.type = double_type;
    j.size = sizeof(double);
    return j;
}

np_jval_t new_jval_v (void *v)
{
    np_jval_t j;
    j.value.v = v;
    j.type = void_type;
    return j;
}

np_jval_t new_jval_s (char *s)
{
    np_jval_t j;
    j.size = strlen(s);
    j.value.s = strndup(s, j.size);
    j.type = char_ptr_type;
    return j;
}

np_jval_t new_jval_c (char c)
{
    np_jval_t j;
    j.value.c = c;
    j.type = char_type;
    j.size = sizeof(char);
    return j;
}

np_jval_t new_jval_uc (unsigned char uc)
{
    np_jval_t j;
    j.value.uc = uc;
    j.type = unsigned_char_type;
    j.size = sizeof(unsigned char);
    return j;
}

np_jval_t new_jval_sh (int8_t sh)
{
    np_jval_t j;
    j.value.sh = sh;
    j.type = short_type;
    j.size = sizeof(int8_t);
    return j;
}

np_jval_t new_jval_ush (uint8_t ush)
{
    np_jval_t j;
    j.value.ush = ush;
    j.type = unsigned_short_type;
    j.size = sizeof(uint8_t);
    return j;
}

np_jval_t new_jval_ui (uint16_t i)
{
    np_jval_t j;
    j.value.ui = i;
    j.type = unsigned_int_type;
    j.size = sizeof(uint16_t);
    return j;
}

np_jval_t new_jval_ul (uint32_t ul)
{
    np_jval_t j;
    j.value.ul = ul;
    j.type = unsigned_long_type;
    j.size = sizeof(uint32_t);
    return j;
}

np_jval_t new_jval_ull (uint64_t ull)
{
    np_jval_t j;
    j.value.ull = ull;
    j.type = unsigned_long_long_type;
    j.size = sizeof(uint64_t);
    return j;
}

np_jval_t new_jval_bin (void* data, uint32_t ul)
{
    np_jval_t j;

    j.value.bin = malloc(ul);
    memset(j.value.bin, 0, ul);
    memcpy(j.value.bin, data, ul);

    j.size = ul;
    j.type = bin_type;

    return j;
}

np_jval_t new_jval_key (np_key_t* key)
{
    np_jval_t j;

    j.value.key = key;
    j.size = sizeof(key);
    j.type = key_type;

    return j;
}

np_jval_t new_jval_iarray (int16_t i0, int16_t i1)
{
    np_jval_t j;
    j.value.iarray[0] = i0;
    j.value.iarray[1] = i1;
    j.type = int_array_2_type;
    j.size = 2*sizeof(int16_t);
    return j;
}

np_jval_t new_jval_farray (float f0, float f1)
{
    np_jval_t j;
    j.value.farray[0] = f0;
    j.value.farray[1] = f1;
    j.type = float_array_2_type;
    j.size = 2*sizeof(float);
    return j;
}

np_jval_t new_jval_carray_nt (char *carray)
{
    np_jval_t j;
    uint8_t i;

    for (i = 0; i < 8 && carray[i] != '\0'; i++)
	{
	    j.value.carray[i] = carray[i];
	}

    if (i < 8) j.value.carray[i] = carray[i];

    j.type = char_array_8_type;

    return j;
}

np_jval_t new_jval_carray_nnt (char *carray)
{
    np_jval_t j;
    memcpy (j.value.carray, carray, 8);
    j.type = unsigned_char_array_8_type;
	return j;
}

np_jval_t new_jval_tree(np_jtree_t* tree) {

	np_jval_t j;
    j.value.tree = tree;
    j.size = tree->byte_size;
    j.type = jrb_tree_type;
	return j;
}

np_jval_t new_jval_obj(np_obj_t* obj) {
	np_jval_t j;
	j.value.obj = obj;
	j.size = 0;
	j.type = npobj_type;
	return j;
}

int16_t jval_i (np_jval_t j)
{
    return j.value.i;
}

int32_t jval_l (np_jval_t j)
{
    return j.value.l;
}

int64_t jval_ll (np_jval_t j)
{
    return j.value.ll;
}

float jval_f (np_jval_t j)
{
    return j.value.f;
}

double jval_d (np_jval_t j)
{
    return j.value.d;
}

void *jval_v (np_jval_t j)
{
    return j.value.v;
}

char *jval_s (np_jval_t j)
{
    return j.value.s;
}

char jval_c (np_jval_t j)
{
    return j.value.c;
}

unsigned char jval_uc (np_jval_t j)
{
    return j.value.uc;
}

int8_t jval_sh (np_jval_t j)
{
    return j.value.sh;
}

uint8_t jval_ush (np_jval_t j)
{
    return j.value.ush;
}

uint16_t jval_ui (np_jval_t j)
{
    return j.value.ui;
}

uint32_t jval_ul (np_jval_t j)
{
    return j.value.ul;
}

uint64_t jval_ull (np_jval_t j)
{
    return j.value.ull;
}

int16_t* jval_iarray (np_jval_t j)
{
    return j.value.iarray;
}

float* jval_farray (np_jval_t j)
{
    return j.value.farray;
}

char* jval_carray (np_jval_t j)
{
    return j.value.carray;
}
