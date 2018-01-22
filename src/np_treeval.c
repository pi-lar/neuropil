//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "inttypes.h"

#include "sodium.h"

#include "np_treeval.h"

#include "np_log.h"
#include "np_dhkey.h"
#include "np_tree.h"

np_treeval_t np_treeval_NULL = { .type = none_type, .size=0 };

np_treeval_t np_treeval_copy_of_val(np_treeval_t from) {
    log_msg(LOG_TRACE, "start: np_treeval_t np_treeval_copy_of_val(np_treeval_t from) {");
	np_treeval_t to;
	switch (from.type) {
	// length is always 1 (to identify the type) + the length of the type
	case short_type:
		to.type = short_type;
		to.value.sh = from.value.sh;
		to.size = sizeof(int8_t);
		break;
	case int_type:
		to.type = int_type;
		to.value.i = from.value.i;
		to.size = sizeof(int16_t);
		break;
	case long_type:
		to.type = long_type;
		to.value.l = from.value.l;
		to.size = sizeof(int32_t);
		break;
#ifdef x64
	case long_long_type:
		to.type = long_long_type;
		to.value.ll = from.value.ll;
		to.size = sizeof(int64_t);
		break;
#endif
	case float_type:
		to.type = float_type;
		to.value.f = from.value.f;
		to.size = sizeof(float);
		break;
	case double_type:
		to.type = double_type;
		to.value.d = from.value.d;
		to.size = sizeof(double);
		break;
	case char_ptr_type:
		to.type = char_ptr_type;
		to.value.s = strndup(from.value.s, strlen(from.value.s));
		to.size = strlen(from.value.s);
		// log_debug_msg(LOG_DEBUG, "copy str %s %hd", to.value.s, to.size);
		break;
	case special_char_ptr_type:
		to.type = special_char_ptr_type;		
		to.value.ush = from.value.ush;
		to.size = sizeof(uint8_t);
		break;
	case char_type:
		to.type = char_type;
		to.value.c = from.value.c;
		to.size = sizeof(char);
		break;
	case unsigned_char_type:
		to.type = unsigned_char_type;
		to.value.uc = from.value.uc;
		to.size = sizeof(unsigned char);
		break;
	case unsigned_short_type:
		to.type = unsigned_short_type;
		to.value.ush = from.value.ush;
		to.size = sizeof(uint8_t);
		break;
	case unsigned_int_type:
		to.type = unsigned_int_type;
		to.value.ui = from.value.ui;
		to.size = sizeof(uint16_t);
		break;
	case unsigned_long_type:
		to.type = unsigned_long_type;
		to.value.ul = from.value.ul;
		to.size = sizeof(uint32_t);
		break;
#ifdef x64
	case unsigned_long_long_type:
		to.type = unsigned_long_long_type;
		to.value.ull = from.value.ull;
		to.size = sizeof(uint64_t);
		break;
#endif
	case uint_array_2_type:
		to.type = uint_array_2_type;
		to.value.a2_ui[0] = from.value.a2_ui[0];
		to.value.a2_ui[1] = from.value.a2_ui[1];
		to.size = 2 * sizeof(uint16_t);
		break;
		// 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
		// 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
		// 		case unsigned_char_array_8_type: byte_size += 1 +8*sizeof(unsigned char); break;
	case bin_type:
		// if (0 < to.size && bin_type == to.type) free (to.value.bin);
		to.type = bin_type;
		to.value.bin = malloc(from.size);
		CHECK_MALLOC(to.value.bin)
		;
		memset(to.value.bin, 0, from.size);
		memcpy(to.value.bin, from.value.bin, from.size);
		to.size = from.size;
		break;
	case jrb_tree_type:
		to.type = jrb_tree_type;
		to.size = from.size;
		to.value.tree = np_tree_clone(from.value.tree);
		break;
	case dhkey_type:
		to.type = dhkey_type;
		to.value.dhkey.t[0] = from.value.dhkey.t[0];
		to.value.dhkey.t[1] = from.value.dhkey.t[1];
		to.value.dhkey.t[2] = from.value.dhkey.t[2];
		to.value.dhkey.t[3] = from.value.dhkey.t[3];
		to.value.dhkey.t[4] = from.value.dhkey.t[4];
		to.value.dhkey.t[5] = from.value.dhkey.t[5];
		to.value.dhkey.t[6] = from.value.dhkey.t[6];
		to.value.dhkey.t[7] = from.value.dhkey.t[7];
		to.size = sizeof(np_dhkey_t);
		break;
	case hash_type:
		to.type = bin_type;
		to.value.bin = malloc(from.size);
		CHECK_MALLOC(to.value.bin)
		;

		memset(to.value.bin, 0, from.size);
		memcpy(to.value.bin, from.value.bin, from.size);
		to.size = from.size;
		break;
	case void_type:
		to.type = void_type;
		to.value.v = from.value.v;
		to.size = from.size;
		break;
	default:
		to.type = none_type;
		log_msg(LOG_WARN, "unsupported copy operation for jval type %hhd",
				from.type);
		break;
	}
	return to;
}
/*
	@param:freeable: returns the information to free or not to free the result
*/
char* np_treeval_to_str(np_treeval_t val, np_bool* freeable) {
    log_msg(LOG_TRACE, "start: char* np_treeval_to_str(np_treeval_t val) {");

	int len = 0;
	char* result = NULL;
	if(freeable  != NULL) *freeable = FALSE;
	switch(val.type) {
		// length is always 1 (to identify the type) + the length of the type
  		case short_type:
  			len = snprintf(NULL, 0, "%d", val.value.sh);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%d", val.value.sh);
  			}
  			break;
		case int_type:
  			len = snprintf(NULL, 0, "%d", val.value.i);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%d", val.value.i);
  			}
			break;
		case long_type:
  			len = snprintf(NULL, 0, "%d", val.value.l);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%d", val.value.l);
  			}
			break;
#ifdef x64
		case long_long_type:
  			len = snprintf(NULL, 0, "%llu", val.value.ll);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%llu", val.value.ll);
  			}
			break;
#endif
 		case float_type:
  			len = snprintf(NULL, 0, "%f", val.value.f);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%f", val.value.f);
  			}
			break;
		case double_type:
  			len = snprintf(NULL, 0, "%f", val.value.d);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%f", val.value.d);
  			}
			break;
		case char_ptr_type:
			return val.value.s;
			break;
		case special_char_ptr_type:
  			return (char*) _np_tree_get_special_str(val.value.ush);
			break;
		case char_type:
		case unsigned_char_type:
  			return &val.value.c;
			break;
 		case unsigned_short_type:
  			len = snprintf(NULL, 0, "%u", val.value.ush);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%u", val.value.ush);
  			}
 			break;
 		case unsigned_int_type:
  			len = snprintf(NULL, 0, "%u", val.value.ui);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%u", val.value.ui);
  			}
			break;
		case unsigned_long_type:
  			len = snprintf(NULL, 0, "%u", val.value.ul);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%u", val.value.ul);
  			}
			break;
#ifdef x64
		case unsigned_long_long_type:
  			len = snprintf(NULL, 0, "%llu", val.value.ull);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) 	*freeable = TRUE;
  				snprintf(result, len+1, "%llu", val.value.ull);
  			}
			break;
#endif
 		case uint_array_2_type:
  			len = snprintf(NULL, 0, "%u%u", val.value.a2_ui[0], val.value.a2_ui[1]);
  			if (0 < len) {
  				result = malloc(len+1);
  				CHECK_MALLOC(result);
				if (freeable != NULL) *freeable = TRUE;
  				snprintf(result, len+1, "%u%u", val.value.a2_ui[0], val.value.a2_ui[1]);
  			}
 			break;
// 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
// 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
// 		case unsigned_char_array_8_type: byte_size += 1 +8*sizeof(unsigned char); break;
 		case void_type:
 			return "--> pointer";
			break;
 		case hash_type:
 		case bin_type:
 			return "--> binary content";
			break;
 		case jrb_tree_type:
			return "--> subtree";
			break;
		case dhkey_type:
			result = malloc(64);
			CHECK_MALLOC(result);
			if (freeable != NULL) *freeable = TRUE;
			_np_dhkey_to_str(&val.value.dhkey, result);
			break;
		default:
			return "--> unknown";
			break;
	}
	return result;
}

np_treeval_t np_treeval_new_i (int16_t i)
{
    np_treeval_t j;
    j.value.i = i;
    j.type = int_type;
    j.size = sizeof(int16_t);
    return j;
}

np_treeval_t np_treeval_new_l (int32_t l)
{
    np_treeval_t j;
    j.value.l = l;
    j.type = long_type;
    j.size = sizeof(int32_t);
    return j;
}
#ifdef x64
np_treeval_t np_treeval_new_ll (int64_t ll)
{
    np_treeval_t j;
    j.value.ll = ll;
    j.type = long_long_type;
    j.size = sizeof(int64_t);
    return j;
}
#endif
np_treeval_t np_treeval_new_f (float f)
{
    np_treeval_t j;
    j.value.f = f;
    j.type = float_type;
    j.size = sizeof(float);
    return j;
}

np_treeval_t np_treeval_new_d (double d)
{
    np_treeval_t j;
    j.value.d = d;
    j.type = double_type;
    j.size = sizeof(double);
    return j;
}

np_treeval_t np_treeval_new_v (void *v)
{
    np_treeval_t j;
    j.value.v = v;
    j.type = void_type;
    return j;
}

np_treeval_t np_treeval_new_s(char *s)
{
	np_treeval_t j;
	uint8_t idx = 0;
	if (_np_tree_is_special_str(s, &idx)) {
		np_treeval_t k = np_treeval_new_ss(idx);
		memcpy(&j, &k, sizeof(np_treeval_t));
	}
	else {
		j.size = strlen(s);
		j.value.s = s; // strndup(s, j.size);
		j.type = char_ptr_type;
	}
	return j;
}

np_treeval_t np_treeval_new_ss(uint8_t idx)
{
	np_treeval_t j;	
	
	j.size = sizeof(uint8_t);
	j.value.ush = idx;
	j.type = special_char_ptr_type;

	return j;
}

np_treeval_t np_treeval_new_c (char c)
{
    np_treeval_t j;
    j.value.c = c;
    j.type = char_type;
    j.size = sizeof(char);
    return j;
}

np_treeval_t np_treeval_new_uc (unsigned char uc)
{
    np_treeval_t j;
    j.value.uc = uc;
    j.type = unsigned_char_type;
    j.size = sizeof(unsigned char);
    return j;
}

np_treeval_t np_treeval_new_sh (int8_t sh)
{
    np_treeval_t j;
    j.value.sh = sh;
    j.type = short_type;
    j.size = sizeof(int8_t);
    return j;
}

np_treeval_t np_treeval_new_ush (uint8_t ush)
{
    np_treeval_t j;
    j.value.ush = ush;
    j.type = unsigned_short_type;
    j.size = sizeof(uint8_t);
    return j;
}

np_treeval_t np_treeval_new_ui (uint16_t i)
{
    np_treeval_t j;
    j.value.ui = i;
    j.type = unsigned_int_type;
    j.size = sizeof(uint16_t);
    return j;
}

np_treeval_t np_treeval_new_ul (uint32_t ul)
{
    np_treeval_t j;
    j.value.ul = ul;
    j.type = unsigned_long_type;
    j.size = sizeof(uint32_t);
    return j;
}

#ifdef x64
np_treeval_t np_treeval_new_ull (uint64_t ull)
{
    np_treeval_t j;
    j.value.ull = ull;
    j.type = unsigned_long_long_type;
    j.size = sizeof(uint64_t);
    return j;
}
#endif

np_treeval_t np_treeval_new_bin (void* data, uint32_t ul)
{
	np_treeval_t j;

    j.value.bin = data; 
    j.size = ul;
    j.type = bin_type;

    return j;
}

np_treeval_t np_treeval_new_key (np_dhkey_t dhkey)
{
    np_treeval_t j;

    j.value.dhkey = dhkey;
    j.type = dhkey_type;
    j.size = sizeof(np_dhkey_t);

    // j.size = sizeof(key);
    // j.size = 1 + ( 4*sizeof(uint64_t) );
    return j;
}

np_treeval_t np_treeval_new_iarray (uint16_t i0, uint16_t i1)
{
    np_treeval_t j;
    j.value.a2_ui[0] = i0;
    j.value.a2_ui[1] = i1;
    j.type = uint_array_2_type;
    j.size = 2*sizeof(uint16_t);
    return j;
}

np_treeval_t np_treeval_new_farray (float f0, float f1)
{
    np_treeval_t j;
    j.value.farray[0] = f0;
    j.value.farray[1] = f1;
    j.type = float_array_2_type;
    j.size = 2*sizeof(float);
    return j;
}

np_treeval_t np_treeval_new_carray_nt (char *carray)
{
    np_treeval_t j;
    uint8_t i;

    for (i = 0; i < 8 && carray[i] != '\0'; i++)
	{
	    j.value.carray[i] = carray[i];
	}

    if (i < 8) j.value.carray[i] = carray[i];

    j.type = char_array_8_type;

    return j;
}

np_treeval_t np_treeval_new_carray_nnt (char *carray)
{
    np_treeval_t j;
    memcpy (j.value.carray, carray, 8);
    j.type = unsigned_char_array_8_type;
	return j;
}

np_treeval_t np_treeval_new_tree(np_tree_t* tree)
{
    log_msg(LOG_TRACE, "start: np_treeval_t np_treeval_new_tree(np_tree_t* tree){");
	np_treeval_t j;
    j.value.tree = tree;
    j.size = tree->byte_size;
    j.type = jrb_tree_type;
	return j;
}

np_treeval_t np_treeval_new_hash (char *s)
{
    np_treeval_t j;

    char* hash = malloc(crypto_generichash_BYTES);
	CHECK_MALLOC(hash);

    crypto_generichash((unsigned char*) hash, sizeof hash, (unsigned char*)s, sizeof(s), NULL, 0);

    // char hex_hash[2*crypto_generichash_BYTES+1];
    // sodium_bin2hex(hex_hash, 2*crypto_generichash_BYTES+1, (unsigned char*)hash, crypto_generichash_BYTES);

    j.size = crypto_generichash_BYTES; // strlen(hex_hash);
    j.value.bin = hash; // strndup(hex_hash, j.size);
    j.type = hash_type;

    return j;
}

np_treeval_t np_treeval_new_pwhash (NP_UNUSED char *s)
{
	// TODO: implement password hashing function / update of libsodium required ?
    np_treeval_t j = np_treeval_NULL;

//    char pw_hash[crypto_pwhash_STRBYTES];
//    if (crypto_pwhash_str
//        (hashed_password, s, strlen(s),
//         crypto_pwhash_OPSLIMIT_SENSITIVE, crypto_pwhash_MEMLIMIT_SENSITIVE) != 0)
//    {}
//
//    j.size = strlen(pw_hash);
//    j.value.s = strndup(pw_hash, j.size);
//    j.type = pwhash_type;

    return j;
}

np_treeval_t np_treeval_new_obj(np_obj_t* obj)
{
    log_msg(LOG_TRACE, "start: np_treeval_t np_treeval_new_obj(np_obj_t* obj){");
	np_treeval_t j;
	j.value.obj = obj;
	j.size = 0;
	j.type = npobj_type;
	return j;
}

int16_t jval_i (np_treeval_t j)
{
    return j.value.i;
}

int32_t jval_l (np_treeval_t j)
{
    return j.value.l;
}
#ifdef x64
int64_t jval_ll (np_treeval_t j)
{
    return j.value.ll;
}
#endif
float jval_f (np_treeval_t j)
{
    return j.value.f;
}

double jval_d (np_treeval_t j)
{
    return j.value.d;
}

void *jval_v (np_treeval_t j)
{
    return j.value.v;
}

char *jval_s (np_treeval_t j)
{
    return j.value.s;
}

char jval_c (np_treeval_t j)
{
    return j.value.c;
}

unsigned char jval_uc (np_treeval_t j)
{
    return j.value.uc;
}

int8_t jval_sh (np_treeval_t j)
{
    return j.value.sh;
}

uint8_t jval_ush (np_treeval_t j)
{
    return j.value.ush;
}

uint16_t jval_ui (np_treeval_t j)
{
    return j.value.ui;
}

uint32_t jval_ul (np_treeval_t j)
{
    return j.value.ul;
}

#ifdef x64
uint64_t jval_ull (np_treeval_t j)
{
    return j.value.ull;
}
#endif

//int16_t* jval_iarray (np_treeval_t j)
//{
//    return j.value.a2_ui;
//}

float* jval_farray (np_treeval_t j)
{
    return j.value.farray;
}

char* jval_carray (np_treeval_t j)
{
    return j.value.carray;
}
uint32_t np_treeval_get_byte_size(np_treeval_t ele)
{
    log_msg(LOG_TRACE, "start: uint32_t np_treeval_get_byte_size(np_treeval_t ele){");
	uint32_t byte_size = 0;

	switch(ele.type)
	{
		case short_type: 					byte_size += 1 + sizeof(int8_t); break;
		case int_type: 						byte_size += 1 + sizeof(int16_t); break;
		case long_type: 					byte_size += 1 + sizeof(int32_t); break;
#ifdef x64
		case long_long_type:				byte_size += 1 + sizeof(int64_t); break;
#endif
		case float_type: 					byte_size += 1 + sizeof(float); break;
		case double_type: 					byte_size += 1 + sizeof(double); break;
		case char_ptr_type: 				byte_size += sizeof(uint8_t)/*str marker*/ + sizeof(uint32_t)/*size of str*/ + ele.size /*string*/ + sizeof(char)/*terminator*/; break;
		case char_type: 					byte_size += 1 + sizeof(char); break;
		case unsigned_char_type:			byte_size += 1 + sizeof(unsigned char); break;
		case unsigned_short_type:			byte_size += 1 + sizeof(uint8_t); break;
		case unsigned_int_type:				byte_size += 1 + sizeof(uint16_t); break;
		case unsigned_long_type:			byte_size += 1 + sizeof(uint32_t); break;
#ifdef x64
		case unsigned_long_long_type:		byte_size += 1 + sizeof(uint64_t); break;
#endif
		case uint_array_2_type:				byte_size += 1 + 2*sizeof(uint16_t); break;
		case float_array_2_type:			byte_size += 1 + 2*sizeof(float); break;
		case char_array_8_type:				byte_size += 1 + 8*sizeof(char); break;
		case unsigned_char_array_8_type:	byte_size += 1+8*sizeof(unsigned char); break;
		case void_type: 					byte_size += 1 + sizeof(void*); break;
		case bin_type: 						byte_size += 1 + sizeof(uint32_t) + ele.size; break;
		case hash_type: 					byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + ele.size; break;
		case jrb_tree_type:					byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + ele.value.tree->byte_size; break;
		case dhkey_type:					byte_size += sizeof(uint8_t)/*ext32 marker*/ + sizeof(uint32_t)/*size of ext32*/ + sizeof(uint8_t) /*type of ext32*/ + (/*size of dhkey*/8 * (sizeof(uint8_t) /*uint32 marker*/+ sizeof(uint32_t)/*uint32 value*/)); break;
		case special_char_ptr_type:         byte_size += sizeof(uint8_t)/*ext32 marker*/ + sizeof(uint32_t)/*size of ext32*/ + sizeof(uint8_t) /*type of ext32*/ + (/*size of special string (1:1 replacement on target)*/ sizeof(uint8_t)/*uint8 marker*/ + sizeof(uint8_t)/*uint8 value*/); break; 
		default:                  log_msg(LOG_ERROR, "unsupported length calculation for value / type %"PRIu8"", ele.type ); break;
	}

	return byte_size;
}
