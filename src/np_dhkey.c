//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
#include "np_dhkey.h"

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

#include "np_legacy.h"

#include "sodium.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_util.h"
#include "np_treeval.h"
#include "np_keycache.h"
#include "np_aaatoken.h"
#include "np_network.h"
#include "np_node.h"
#include "np_msgproperty.h"


static np_dhkey_t __dhkey_min;
static np_dhkey_t __dhkey_half;
static np_dhkey_t __dhkey_max;


char* _np_dhkey_generate_hash (const char* key_in)
{
    unsigned char md_value[32]; //  = (unsigned char *) malloc (32);

    // TODO: move it to KECCAK because of possible length extension attack ???
    crypto_hash_sha256(md_value, (unsigned char*) key_in, strlen(key_in));

    // log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, md_value);
    // long form - could be used to add addiitonal configuration parameter
    //    crypto_hash_sha256_state state;
    //    crypto_hash_sha256_init(&state);
    //    crypto_hash_sha256_update(&state, key_in, sizeof(key_in));
    //    crypto_hash_sha256_final(&state, tmp);
    //    log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, tmp);
    char* digest_out = (char *) malloc (65);
    CHECK_MALLOC(digest_out);

    sodium_bin2hex(digest_out, 65, md_value, 32);

    return digest_out;
}

np_dhkey_t np_dhkey_create_from_hostport(const char* strOrig, const char* port)
{
    char name[256];
    snprintf (name, 256, "%s:%s", strOrig, port);	

    char* digest = _np_dhkey_generate_hash (name);

    np_dhkey_t tmp = np_dhkey_create_from_hash(digest);

    free (digest);
    return tmp;
}

np_dhkey_t np_dhkey_create_from_hash(const char* strOrig)
{
    log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_create_from_hash(const char* strOrig){");
    np_dhkey_t kResult = { 0 };
    np_str_id(*(np_id*)&kResult, strOrig);
    return kResult;
}

void _np_dhkey_encode(NP_UNUSED np_state_t* context, np_tree_t* jrb, np_dhkey_t* key)
{
    log_trace_msg(LOG_TRACE, "start: void _np_dhkey_encode( context, np_tree_t* jrb, np_dhkey_t* key){");
    // log_msg(LOG_KEY | LOG_WARN, "encoding key %0lu %0lu %0lu %0lu", key->t[0], key->t[1], key->t[2], key->t[3]);

    np_tree_insert_str( jrb, "_np.key.0", np_treeval_new_ul(key->t[0]));
    np_tree_insert_str( jrb, "_np.key.1", np_treeval_new_ul(key->t[1]));
    np_tree_insert_str( jrb, "_np.key.2", np_treeval_new_ul(key->t[2]));
    np_tree_insert_str( jrb, "_np.key.3", np_treeval_new_ul(key->t[3]));
    np_tree_insert_str( jrb, "_np.key.4", np_treeval_new_ul(key->t[4]));
    np_tree_insert_str( jrb, "_np.key.5", np_treeval_new_ul(key->t[5]));
    np_tree_insert_str( jrb, "_np.key.6", np_treeval_new_ul(key->t[6]));
    np_tree_insert_str( jrb, "_np.key.7", np_treeval_new_ul(key->t[7]));
}

void _np_dhkey_decode(np_tree_t* jrb, np_dhkey_t* key)
{
    log_trace_msg(LOG_TRACE, "start: void _np_dhkey_decode(np_tree_t* jrb, np_dhkey_t* key){");
    key->t[0] = np_tree_find_str(jrb, "_np.key.0")->val.value.ul;
    key->t[1] = np_tree_find_str(jrb, "_np.key.1")->val.value.ul;
    key->t[2] = np_tree_find_str(jrb, "_np.key.2")->val.value.ul;
    key->t[3] = np_tree_find_str(jrb, "_np.key.3")->val.value.ul;
    key->t[4] = np_tree_find_str(jrb, "_np.key.4")->val.value.ul;
    key->t[5] = np_tree_find_str(jrb, "_np.key.5")->val.value.ul;
    key->t[6] = np_tree_find_str(jrb, "_np.key.6")->val.value.ul;
    key->t[7] = np_tree_find_str(jrb, "_np.key.7")->val.value.ul;
}

void _np_dhkey_assign (np_dhkey_t* k1, const np_dhkey_t* const k2)
{
    for (uint8_t i = 0; i < 8; i++)
        k1->t[i] = k2->t[i];
}

bool _np_dhkey_equal (const np_dhkey_t* const k1, const np_dhkey_t* const k2)
{
    for (uint8_t i = 0; i < 8; i++)
        if (k1->t[i] != k2->t[i])
            return false;
    return true;
}

int8_t _np_dhkey_cmp (const np_dhkey_t* const k1, const np_dhkey_t* const k2)
{	
    if (k1 == NULL) return -1;
    if (k2 == NULL) return  1;

    for (uint8_t i = 0; i < 8; i++)
    {
        if 		(k1->t[i] > k2->t[i]) return ( 1);
        else if (k1->t[i] < k2->t[i]) return (-1);
    }
    return (0);
}

void _np_dhkey_add (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2)
{
    // we dont care about buffer overflow, since we are adding hashes
    // since we are using uint64_t we always stay in valid data
    for (uint8_t i = 0; i < 8 ; i++)
    {
        result->t[i] = op1->t[i] + op2->t[i];
    }
}

void _np_dhkey_sub (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2)
{
    for (uint8_t i = 0; i < 8; i++)
    {
        result->t[i] = op1->t[i] - op2->t[i];
    }
}

bool  _np_dhkey_init (NP_UNUSED np_state_t* context)
{
    uint32_t half = (UINT_MAX >> 1) + 1;
    for (uint8_t i = 0; i < 8; i++)
    {
        __dhkey_max.t[i]  = UINT_MAX;
        __dhkey_half.t[i] = half;
        __dhkey_min.t[i]  = 0;
        log_debug_msg(LOG_KEY | LOG_DEBUG,
                "dhkey_max[%d] %"PRIu32" / dhkey_half[%d] %"PRIu32" / dhkey_half[%d] %"PRIu32,
                i, __dhkey_max.t[i],
                i, __dhkey_half.t[i],
                i, __dhkey_min.t[i]
        );
    }

    return true;
}
void _np_dhkey_destroy (np_state_t* context){
    //nothing to implement for now
}


np_dhkey_t np_dhkey_min(NP_UNUSED np_state_t* context)  {
    log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_fmin()  {"); return __dhkey_min;  };
np_dhkey_t np_dhkey_half(NP_UNUSED np_state_t* context) {
    log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_half() {"); return __dhkey_half; };
np_dhkey_t np_dhkey_max(NP_UNUSED np_state_t* context)  {
    log_trace_msg(LOG_TRACE, "start: np_dhkey_t np_dhkey_fmax()  {"); return __dhkey_max;  };

// TODO: the distance of two hash keys could be implemented much better
void _np_dhkey_distance (np_dhkey_t* diff, const np_dhkey_t* const k1, const np_dhkey_t* const k2)
{	
    _np_dhkey_sub(diff, k1, k2);		
}


bool _np_dhkey_between (const np_dhkey_t* const test, const np_dhkey_t* const left, const np_dhkey_t* const right, const bool includeBounds)
{
    bool ret = false;
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".start._dhkey_between");

    int8_t comp_lt = _np_dhkey_cmp (left, test);
    int8_t comp_tr = _np_dhkey_cmp (test, right);

    /* it's on one of the edges */
    if (comp_lt == 0 || comp_tr == 0) {
        ret = includeBounds ;
    }
    // it is a 'default' compare (test has to be between left and right)
    else if (_np_dhkey_cmp(left, right) <  0) {		
        ret = (comp_lt <= 0 && comp_tr <= 0);
    }
    /* it is an 'outer circle' compare: 
    min to max builds a circle for all values. 
    we search for a value between:
        1) the value on the far right(aka the current left one) 
        2) and the value on the far left(aka the current rigth one)
    */
    else {		
        ret = ( _np_dhkey_cmp(left, test) <= 0 || _np_dhkey_cmp(test, right) <= 0);
    }

    log_trace_msg ( LOG_TRACE | LOG_KEY, ".end  ._dhkey_between");
    return (ret);
}

void _np_dhkey_midpoint (np_dhkey_t* mid, const np_dhkey_t* key)
{
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".start._dhkey_midpoint");
    if   (_np_dhkey_cmp (key, &__dhkey_half) < 0) _np_dhkey_add (mid, key, &__dhkey_half);
    else  	                                    _np_dhkey_sub (mid, key, &__dhkey_half);
    // mid->valid = false;
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".end  ._dhkey_midpoint");
}

/*
 * calculates the position within the routing table where a new entry will be inserted.
 */
uint16_t _np_dhkey_index (const np_dhkey_t* mykey, const np_dhkey_t* otherkey)
{
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".start._dhkey_index");
    uint16_t i = 0, max_len = 64;

    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t bit_mask = 0xf0000000;
        for (uint8_t j = 0; j < 8; ++j)
        {
            uint32_t t1 = mykey->t[k]    & bit_mask;
            uint32_t t2 = otherkey->t[k] & bit_mask;
            //log_debug_msg(LOG_KEY | LOG_DEBUG, "key_index: %d me: %08"PRIx32" other: %08"PRIx32" mask: %08"PRIx32, i, t1, t2, bit_mask);
            if (t1 != t2)
            {
                log_trace_msg ( LOG_TRACE | LOG_KEY, ".end  ._dhkey_index");
                return i;
            }
            else
            {
                bit_mask = bit_mask >> 4;
            }
            i++;
        }
    }

    if (i == max_len) i = max_len - 1;
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".end  ._dhkey_index");
    return i;
}
/*
    Returns a specific position from the dhkey

    param index_of_key: desired index to get the value from
    return: the value of the key at position index_of_key
*/
uint8_t _np_dhkey_hexalpha_at (np_state_t* context, const np_dhkey_t* key, const int8_t index_of_key)
{
    log_trace_msg ( LOG_TRACE | LOG_KEY, ".start._dhkey_hexalpha_at");
    uint8_t j = 1;
    uint32_t answer = 0;

    const uint8_t tuple_size = 32;			// tuple is defined in np_dhkey_s
    const uint8_t size_of_element = 4;		// element is 4 bit 
    const uint8_t elements_in_tuple = tuple_size / size_of_element; // 8
    

    uint8_t tuple      = index_of_key / elements_in_tuple; // array index of tuple
    uint8_t tuple_rest = index_of_key % elements_in_tuple; // position in tuple

    log_debug_msg(LOG_KEY | LOG_DEBUG, "lookup_pos: %"PRIi8"-> key[%"PRIu8"]: %08"PRIx32" mod %"PRIu8, index_of_key, tuple, key->t[tuple], tuple_rest);

    // shift the bitmask in a way only the desired element is preserved
    uint32_t bit_mask = 0xf0000000;
    for (; j <= tuple_rest; ++j)
    {		
        bit_mask = bit_mask >> size_of_element;
    }
    log_debug_msg(LOG_KEY | LOG_DEBUG, "bitmask: %08"PRIx32, bit_mask);
    // filter with bitmask
    answer = key->t[tuple] & bit_mask;
    log_debug_msg(LOG_KEY | LOG_DEBUG, "bitmask & key->[%"PRIu8"]: %08"PRIx32, tuple, answer);

    // the answer may now be shifted till the element is on the right side of the register
    for (; j < elements_in_tuple; ++j)
    {
        // shift result to the end of the number
        answer = answer >> size_of_element;
    }
    log_debug_msg(LOG_KEY | LOG_DEBUG, "final answer: %"PRIu32" (%0"PRIx32")", answer, answer);

    log_trace_msg ( LOG_TRACE | LOG_KEY, ".end  ._dhkey_hexalpha_at");	
    return (uint8_t) answer;
}



void _np_dhkey_str(const np_dhkey_t* k, char* key_string)
{
    
    np_id_str(key_string, *(np_id*)k);
} 
void _np_str_dhkey(const char* key_string,  np_dhkey_t* k)
{    
    np_str_id(*(np_id*)k, key_string);
} 
