//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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
#include "np_util.h"
#include "np_tree.h"



np_treeval_t np_treeval_copy_of_val(np_treeval_t from) {
    log_trace_msg(LOG_TRACE, "start: np_treeval_t np_treeval_copy_of_val(np_treeval_t from) {");
    np_treeval_t to;
    switch (from.type) {
    // length is always 1 (to identify the type) + the length of the type
    case np_treeval_type_short:
        to.type = np_treeval_type_short;
        to.value.sh = from.value.sh;
        to.size = sizeof(int8_t);
        break;
    case np_treeval_type_int:
        to.type = np_treeval_type_int;
        to.value.i = from.value.i;
        to.size = sizeof(int16_t);
        break;
    case np_treeval_type_long:
        to.type = np_treeval_type_long;
        to.value.l = from.value.l;
        to.size = sizeof(int32_t);
        break;
#ifdef x64
    case np_treeval_type_long_long:
        to.type = np_treeval_type_long_long;
        to.value.ll = from.value.ll;
        to.size = sizeof(int64_t);
        break;
#endif
    case np_treeval_type_float:
        to.type = np_treeval_type_float;
        to.value.f = from.value.f;
        to.size = sizeof(float);
        break;
    case np_treeval_type_double:
        to.type = np_treeval_type_double;
        to.value.d = from.value.d;
        to.size = sizeof(double);
        break;
    case np_treeval_type_char_ptr:
        to.type = np_treeval_type_char_ptr;
        to.value.s = strndup(from.value.s, strlen(from.value.s));
        to.size = strlen(from.value.s);
        // log_debug_msg(LOG_DEBUG, "copy str %s %hd", to.value.s, to.size);
        break;
    case np_treeval_type_special_char_ptr:
        to.type = np_treeval_type_special_char_ptr;		
        to.value.ush = from.value.ush;
        to.size = sizeof(uint8_t);
        break;
    case np_treeval_type_char:
        to.type = np_treeval_type_char;
        to.value.c = from.value.c;
        to.size = sizeof(char);
        break;
    case np_treeval_type_unsigned_char:
        to.type = np_treeval_type_unsigned_char;
        to.value.uc = from.value.uc;
        to.size = sizeof(unsigned char);
        break;
    case np_treeval_type_unsigned_short:
        to.type = np_treeval_type_unsigned_short;
        to.value.ush = from.value.ush;
        to.size = sizeof(uint8_t);
        break;
    case np_treeval_type_unsigned_int:
        to.type = np_treeval_type_unsigned_int;
        to.value.ui = from.value.ui;
        to.size = sizeof(uint16_t);
        break;
    case np_treeval_type_unsigned_long:
        to.type = np_treeval_type_unsigned_long;
        to.value.ul = from.value.ul;
        to.size = sizeof(uint32_t);
        break;
#ifdef x64
    case np_treeval_type_unsigned_long_long:
        to.type = np_treeval_type_unsigned_long_long;
        to.value.ull = from.value.ull;
        to.size = sizeof(uint64_t);
        break;
#endif
    case np_treeval_type_uint_array_2:
        to.type = np_treeval_type_uint_array_2;
        to.value.a2_ui[0] = from.value.a2_ui[0];
        to.value.a2_ui[1] = from.value.a2_ui[1];
        to.size = 2 * sizeof(uint16_t);
        break;
        // 		case np_treeval_type_float_array_2:  byte_size += 1 + 2*sizeof(float); break;
        // 		case np_treeval_type_char_array_8:   byte_size += 1 + 8*sizeof(char); break;
        // 		case np_treeval_type_unsigned_char_array_8: byte_size += 1 +8*sizeof(unsigned char); break;
    case np_treeval_type_bin:
        to.type = np_treeval_type_bin;
        to.value.bin = malloc(from.size);
        CHECK_MALLOC(to.value.bin);
        memcpy(to.value.bin, from.value.bin, from.size);
        to.size = from.size;
        break;
    case np_treeval_type_jrb_tree:
        to.type = np_treeval_type_jrb_tree;
        to.size = from.size;
        to.value.tree = np_tree_clone( from.value.tree);
        break;
    case np_treeval_type_dhkey:
        to.type = np_treeval_type_dhkey;
        memcpy(&to.value.dhkey, &from.value.dhkey, sizeof(np_dhkey_t));
        to.size = sizeof(np_dhkey_t);
        break;
    case np_treeval_type_hash:
        to.type = np_treeval_type_hash;
        to.value.bin = malloc(from.size);
        CHECK_MALLOC(to.value.bin)
        
        memcpy(to.value.bin, from.value.bin, from.size);
        to.size = from.size;
        break;
    case np_treeval_type_void:
        to.type = np_treeval_type_void;
        to.value.v = from.value.v;
        to.size = from.size;
        break;
    default:
        to.type = np_treeval_type_undefined;
        //log_msg(LOG_WARN,"unsupported copy operation for np_treeval type %"PRIu8,from.type);
        break;
    }
    return to;
}
/*
    @param:freeable: returns the information to free or not to free the result
*/
char* np_treeval_to_str(np_treeval_t val, bool* freeable) {
    log_trace_msg(LOG_TRACE, "start: char* np_treeval_to_str(np_treeval_t val) {");

    int len = 0;
    char* result = NULL;
    if(freeable  != NULL) *freeable = false;
    uint32_t hex_len;
    switch (val.type) {
        // length is always 1 (to identify the type) + the length of the type
        case np_treeval_type_short:
            len = snprintf(NULL, 0, "%d", val.value.sh);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%d", val.value.sh);
            }
            break;
        case np_treeval_type_int:
            len = snprintf(NULL, 0, "%d", val.value.i);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%d", val.value.i);
            }
            break;
        case np_treeval_type_long:
            len = snprintf(NULL, 0, "%d", val.value.l);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%d", val.value.l);
            }
            break;
#ifdef x64
        case np_treeval_type_long_long:
            len = snprintf(NULL, 0, "%"PRIu64, val.value.ll);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%"PRIu64, val.value.ll);
            }
            break;
#endif
        case np_treeval_type_float:
            len = snprintf(NULL, 0, "%f", val.value.f);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%f", val.value.f);
            }
            break;
        case np_treeval_type_double:
            len = snprintf(NULL, 0, "%f", val.value.d);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%f", val.value.d);
            }
            break;
        case np_treeval_type_char_ptr:
            return val.value.s;
            break;
        case np_treeval_type_special_char_ptr:
            return (char*) _np_tree_get_special_str( val.value.ush);
            break;
        case np_treeval_type_char:
        case np_treeval_type_unsigned_char:
            return &val.value.c;
            break;
        case np_treeval_type_unsigned_short:
            len = snprintf(NULL, 0, "%u", val.value.ush);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%u", val.value.ush);
            }
            break;
        case np_treeval_type_unsigned_int:
            len = snprintf(NULL, 0, "%u", val.value.ui);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%u", val.value.ui);
            }
            break;
        case np_treeval_type_unsigned_long:
            len = snprintf(NULL, 0, "%u", val.value.ul);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%u", val.value.ul);
            }
            break;
#ifdef x64
        case np_treeval_type_unsigned_long_long:
            len = snprintf(NULL, 0, "%"PRIu64, val.value.ull);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) 	*freeable = true;
                snprintf(result, len+1, "%"PRIu64, val.value.ull);
            }
            break;
#endif
        case np_treeval_type_uint_array_2:
            len = snprintf(NULL, 0, "%u,%u", val.value.a2_ui[0], val.value.a2_ui[1]);
            if (0 < len) {
                result = malloc(len+1);
                CHECK_MALLOC(result);
                if (freeable != NULL) *freeable = true;
                snprintf(result, len+1, "%u,%u", val.value.a2_ui[0], val.value.a2_ui[1]);
            }
            break;
// 		case np_treeval_type_float_array_2:  byte_size += 1 + 2*sizeof(float); break;
// 		case np_treeval_type_char_array_8:   byte_size += 1 + 8*sizeof(char); break;
// 		case np_treeval_type_unsigned_char_array_8: byte_size += 1 +8*sizeof(unsigned char); break;
        case np_treeval_type_void:
            return "--> pointer";
            break;
        case np_treeval_type_hash:
        case np_treeval_type_bin:
            hex_len = val.size * 2 + 1;
            char* hex_str = malloc(hex_len+2);
            hex_str[0] = '0';
            hex_str[1] = 'x';
            if (freeable != NULL) *freeable = true;
            sodium_bin2hex(hex_str+2, hex_len, val.value.bin, val.size);
            return hex_str;
            break;
        case np_treeval_type_jrb_tree:
            if (freeable != NULL) * freeable = true;
            char * info_str = NULL;
            np_tree_elem_t * tmp = NULL;
            bool free_key, free_value;
            char *key, *value;			
			info_str = np_str_concatAndFree(info_str, "--> SUBTREE: (");
            RB_FOREACH(tmp, np_tree_s, (val.value.tree))
            {
                key = np_treeval_to_str(tmp->key, &free_key);
                value = np_treeval_to_str(tmp->val, &free_value);
                info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
                if (free_value) free(value);
                if (free_key) free(key);
            }
			info_str = np_str_concatAndFree(info_str, ") ");
            return info_str ;
            break;
        case np_treeval_type_dhkey:
            result = malloc(65);
            CHECK_MALLOC(result);
            if (freeable != NULL) *freeable = true;
            np_id2str((np_id*)&val.value.dhkey, result);
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
    j.type = np_treeval_type_int;
    j.size = sizeof(int16_t);
    return j;
}

np_treeval_t np_treeval_new_l (int32_t l)
{
    np_treeval_t j;
    j.value.l = l;
    j.type = np_treeval_type_long;
    j.size = sizeof(int32_t);
    return j;
}
#ifdef x64
np_treeval_t np_treeval_new_ll (int64_t ll)
{
    np_treeval_t j;
    j.value.ll = ll;
    j.type = np_treeval_type_long_long;
    j.size = sizeof(int64_t);
    return j;
}
#endif
np_treeval_t np_treeval_new_f (float f)
{
    np_treeval_t j;
    j.value.f = f;
    j.type = np_treeval_type_float;
    j.size = sizeof(float);
    return j;
}

np_treeval_t np_treeval_new_d (double d)
{
    np_treeval_t j;
    j.value.d = d;
    j.type = np_treeval_type_double;
    j.size = sizeof(double);
    return j;
}

np_treeval_t np_treeval_new_v (void *v)
{
    np_treeval_t j;
    j.value.v = v;
    j.type = np_treeval_type_void;
    return j;
}

np_treeval_t np_treeval_new_s(char *s)
{
    np_treeval_t j;
    uint8_t idx = 0;
    if (_np_tree_is_special_str( s, &idx)) {
        np_treeval_t k = np_treeval_new_ss(idx);
        memcpy(&j, &k, sizeof(np_treeval_t));
    }
    else {
        j.size = strlen(s);
        j.value.s = s; // strndup(s, j.size);
        j.type = np_treeval_type_char_ptr;
    }
    return j;
}

np_treeval_t np_treeval_new_ss(uint8_t idx)
{
    np_treeval_t j;	
    
    j.size = sizeof(uint8_t);
    j.value.ush = idx;
    j.type = np_treeval_type_special_char_ptr;

    return j;
}

np_treeval_t np_treeval_new_c (char c)
{
    np_treeval_t j;
    j.value.c = c;
    j.type = np_treeval_type_char;
    j.size = sizeof(char);
    return j;
}

np_treeval_t np_treeval_new_uc (unsigned char uc)
{
    np_treeval_t j;
    j.value.uc = uc;
    j.type = np_treeval_type_unsigned_char;
    j.size = sizeof(unsigned char);
    return j;
}

np_treeval_t np_treeval_new_sh (int8_t sh)
{
    np_treeval_t j;
    j.value.sh = sh;
    j.type = np_treeval_type_short;
    j.size = sizeof(int8_t);
    return j;
}

np_treeval_t np_treeval_new_ush (uint8_t ush)
{
    np_treeval_t j;
    j.value.ush = ush;
    j.type = np_treeval_type_unsigned_short;
    j.size = sizeof(uint8_t);
    return j;
}

np_treeval_t np_treeval_new_ui (uint16_t i)
{
    np_treeval_t j;
    j.value.ui = i;
    j.type = np_treeval_type_unsigned_int;
    j.size = sizeof(uint16_t);
    return j;
}

np_treeval_t np_treeval_new_ul (uint32_t ul)
{
    np_treeval_t j;
    j.value.ul = ul;
    j.type = np_treeval_type_unsigned_long;
    j.size = sizeof(uint32_t);
    return j;
}

#ifdef x64
np_treeval_t np_treeval_new_ull (uint64_t ull)
{
    np_treeval_t j;
    j.value.ull = ull;
    j.type = np_treeval_type_unsigned_long_long;
    j.size = sizeof(uint64_t);
    return j;
}
#endif

np_treeval_t np_treeval_new_bin (void* data, uint32_t ul)
{
    np_treeval_t j;

    j.value.bin = data; 
    j.size = ul;
    j.type = np_treeval_type_bin;

    return j;
}

np_treeval_t np_treeval_new_dhkey (np_dhkey_t dhkey)
{
    np_treeval_t j;

    j.value.dhkey = dhkey;
    j.type = np_treeval_type_dhkey;
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
    j.type = np_treeval_type_uint_array_2;
    j.size = 2*sizeof(uint16_t);
    return j;
}

np_treeval_t np_treeval_new_farray (float f0, float f1)
{
    np_treeval_t j;
    j.value.farray[0] = f0;
    j.value.farray[1] = f1;
    j.type = np_treeval_type_float_array_2;
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

    j.type = np_treeval_type_char_array_8;

    return j;
}

np_treeval_t np_treeval_new_carray_nnt (char *carray)
{
    np_treeval_t j;
    memcpy (j.value.carray, carray, 8);
    j.type = np_treeval_type_unsigned_char_array_8;
    return j;
}

np_treeval_t np_treeval_new_tree(np_tree_t* tree)
{
    log_trace_msg(LOG_TRACE, "start: np_treeval_t np_treeval_new_tree(np_tree_t* tree){");
    np_treeval_t j;
    j.value.tree = tree;
    j.size = tree->byte_size;
    j.type = np_treeval_type_jrb_tree;
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
    j.type = np_treeval_type_hash;

    return j;
}

int16_t np_treeval_i (np_treeval_t j)
{
    return j.value.i;
}

int32_t np_treeval_l (np_treeval_t j)
{
    return j.value.l;
}
#ifdef x64
int64_t np_treeval_ll (np_treeval_t j)
{
    return j.value.ll;
}
#endif
float np_treeval_f (np_treeval_t j)
{
    return j.value.f;
}

double np_treeval_d (np_treeval_t j)
{
    return j.value.d;
}

void *np_treeval_v (np_treeval_t j)
{
    return j.value.v;
}

char *np_treeval_str (np_treeval_t j)
{
    return j.value.s;
}

char np_treeval_c (np_treeval_t j)
{
    return j.value.c;
}

unsigned char np_treeval_uc (np_treeval_t j)
{
    return j.value.uc;
}

int8_t np_treeval_sh (np_treeval_t j)
{
    return j.value.sh;
}

uint8_t np_treeval_ush (np_treeval_t j)
{
    return j.value.ush;
}

uint16_t np_treeval_ui (np_treeval_t j)
{
    return j.value.ui;
}

uint32_t np_treeval_ul (np_treeval_t j)
{
    return j.value.ul;
}

#ifdef x64
uint64_t np_treeval_ull (np_treeval_t j)
{
    return j.value.ull;
}
#endif

// int16_t* np_treeval_iarray (np_treeval_t j)
//{
//    return j.value.a2_ui;
//}

float* np_treeval_farray (np_treeval_t j)
{
    return j.value.farray;
}

char* np_treeval_carray (np_treeval_t j)
{
    return j.value.carray;
}

char* np_treeval_h (np_treeval_t j)
{
    return j.value.bin;
}


uint32_t np_treeval_get_byte_size(np_treeval_t ele)
{
    log_trace_msg(LOG_TRACE, "start: uint32_t np_treeval_get_byte_size(np_treeval_t ele){");
    uint32_t byte_size = 0;

    switch(ele.type)
    {
        case np_treeval_type_short: 					byte_size += 1 + sizeof(int8_t); break;
        case np_treeval_type_int: 						byte_size += 1 + sizeof(int16_t); break;
        case np_treeval_type_long: 						byte_size += 1 + sizeof(int32_t); break;
#ifdef x64
        case np_treeval_type_long_long:					byte_size += 1 + sizeof(int64_t); break;
#endif
        case np_treeval_type_float: 					byte_size += 1 + sizeof(float); break;
        case np_treeval_type_double: 					byte_size += 1 + sizeof(double); break;
        case np_treeval_type_char_ptr: 					byte_size += sizeof(uint8_t)/*str marker*/ + sizeof(uint32_t)/*size of str*/ + ele.size /*string*/ + sizeof(char)/*terminator*/; break;
        case np_treeval_type_char: 						byte_size += 1 + sizeof(char); break;
        case np_treeval_type_unsigned_char:				byte_size += 1 + sizeof(unsigned char); break;
        case np_treeval_type_unsigned_short:			byte_size += 1 + sizeof(uint8_t); break;
        case np_treeval_type_unsigned_int:				byte_size += 1 + sizeof(uint16_t); break;
        case np_treeval_type_unsigned_long:				byte_size += 1 + sizeof(uint32_t); break;
#ifdef x64
        case np_treeval_type_unsigned_long_long:		byte_size += 1 + sizeof(uint64_t); break;
#endif
        case np_treeval_type_uint_array_2:				byte_size += 1 + 2 * sizeof(uint16_t); break;
        case np_treeval_type_float_array_2:				byte_size += 1 + 2 * sizeof(float); break;
        case np_treeval_type_char_array_8:				byte_size += 1 + 8 * sizeof(char); break;
        case np_treeval_type_unsigned_char_array_8:		byte_size += 1 + 8 * sizeof(unsigned char); break;
        case np_treeval_type_void: 						byte_size += 1 + sizeof(void*); break;
        case np_treeval_type_bin: 						byte_size += 1 + sizeof(uint32_t) + ele.size; break;
        case np_treeval_type_hash: 						byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + ele.size; break;
        case np_treeval_type_jrb_tree:					byte_size += sizeof(uint8_t)/*ext32 marker*/ + sizeof(uint32_t)/*size of ext32*/ + sizeof(uint8_t) /*type of ext32*/ + ele.value.tree->byte_size; break;
        case np_treeval_type_dhkey:						byte_size += sizeof(uint8_t)/*ext32 marker*/ + sizeof(uint32_t)/*size of ext32*/ + sizeof(uint8_t) /*type of ext32*/ + (/*size of dhkey*/8 * (sizeof(uint8_t) /*uint32 marker*/+ sizeof(uint32_t)/*uint32 value*/)); break;
        case np_treeval_type_special_char_ptr:			byte_size += sizeof(uint8_t)/*ext32 marker*/ + sizeof(uint32_t)/*size of ext32*/ + sizeof(uint8_t) /*type of ext32*/ + (/*size of special string (1:1 replacement on target)*/ sizeof(uint8_t)/*uint8 marker*/ + sizeof(uint8_t)/*uint8 value*/); break; 
        //default:                  log_msg(LOG_ERROR, "unsupported length calculation for value / type %"PRIu8"", ele.type ); break;
    }

    return byte_size;
}
