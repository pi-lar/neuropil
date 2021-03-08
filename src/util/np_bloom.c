//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <math.h>

#include "util/np_bloom.h"

#include "neuropil.h"

#include "neuropil_log.h"
#include "np_log.h"
#include "np_util.h"
#include "util/np_tree.h"

// bloom filter based on np_dhkey_t / np_dhkey_t
// we treat the np_dhkey_t as (8 * uint32_t) -> 8 distinct hash values -> pobability of false positive approx 1 in 1024
// _size of bit array :  256 -> max _free_items per bloom filter is  18
// _size of bit array :  512 -> max _free_items per bloom filter is  35
// _size of bit array : 1024 -> max _free_items per bloom filter is  70
// _size of bit array : 2048 -> max _free_items per bloom filter is 140

np_bloom_t* _np_standard_bloom_create(size_t bit_size)
{
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = standard_bf;
    res->_size = bit_size;
    res->_d = 1;
    res->_p = 0;
    res->_num_blocks = 1;
    
    res->_bitset = calloc(1, (bit_size/8)*res->_d);
    // simplified max elements calculation
    res->_free_items = bit_size / 16;
    // real calculation would be (see also: https://hur.st/bloomfilter/?n=&p=1024&m=256&k=8):
    // res->_free_items = ceil(m / (-k / log(1 - exp(log(p) / k))))
    // res->_free_items = ceil(bloom filter size/ (-hash_funcs / log(1 - exp(log(false positive ) / hash_funcs))))
    // res->_free_items = ceil(bit_size         / (-8          / log(1 - exp(log(1/1024)                     / 8         ))));
    // res->_free_items = ceil(bit_size         / (-8          / log(1 - exp(-3,0102999566                   / 8         ))));
    // res->_free_items = ceil(bit_size         / (-8          / log(1 - 0,686404967                                      )));
    // res->_free_items = ceil(bit_size         / (-8          / -0,5036308247                                             ));
    
    return res;
}

void _np_bloom_free(np_bloom_t* bloom) 
{
    free(bloom->_bitset);
    free(bloom);
}

void _np_standard_bloom_add(np_bloom_t* bloom, np_dhkey_t id)
{    
    if (bloom->_free_items == 0) abort();
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        // log_msg(LOG_DEBUG, "bap: %d\n", _bit_array_pos);
        uint32_t _local_pos     = (_bit_array_pos) / 8;
        // log_msg(LOG_DEBUG, " lp: %d\n", _local_pos);
        uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8) );
        // log_msg(LOG_DEBUG, " bm: %x\n", _bitmask);
        bloom->_bitset[_local_pos] |= _bitmask;
// #ifdef DEBUG
        // char test_string[65];
        // np_id_str(test_string, &bloom->_bitset[0]);
        // log_msg(LOG_DEBUG, "add  : %s --> pos=%3d (%02x <-> %02x)\n", test_string, _local_pos, _bitmask, bloom->_bitset[_local_pos]);
// #endif
    }
    
// #ifdef DEBUG
    // char test_string[65];
    // np_id_str(test_string, bloom->_bitset);
    // log_msg(LOG_DEBUG, "final: %s\n", test_string);
// #endif
    
    bloom->_free_items--;
}

bool _np_standard_bloom_check(np_bloom_t* bloom, np_dhkey_t id)
{    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t _local_pos     = (_bit_array_pos) / 8;
        uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8) );
        uint8_t  result = bloom->_bitset[_local_pos] & _bitmask;
        
        if ( 0 == result ) {
// #ifdef DEBUG
            // char test_string[65];
            // for (uint16_t i = 0; i < bloom->_size/8; i+=32) {
            // np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%d: check: %s --> pos=%3d (%02x <-> %02x)\n", i, test_string, _local_pos, _bitmask, bloom->_bitset[_local_pos]);
            // }
// #endif
            return (false);
        }
    }
    return (true);
}

bool _np_standard_bloom_intersect(np_bloom_t* result, np_bloom_t* first)
{
    assert(first->_type == standard_bf);
    assert(first->_type == result->_type);
    assert(first->_size == result->_size);
    assert(first->_d == result->_d);
    assert(first->_num_blocks == result->_num_blocks);

    // simplified max elements calculation
    result->_free_items = 0; // not altered, we cannot further intersect this filter
    uint16_t i = 0;
    for (uint16_t k = 0; k < result->_size/8*result->_d; ++k)
    {
        result->_bitset[k] &= first->_bitset[k];
        if (result->_bitset[k] > 0) i++;
    }
    return (i > 0) ? true : false;
}

void _np_standard_bloom_union(np_bloom_t* result, np_bloom_t* first)
{
    assert(first->_type == standard_bf);
    assert(first->_type == result->_type);
    assert(first->_size == result->_size);
    assert(first->_d == result->_d);
    assert(first->_num_blocks == result->_num_blocks);

    // simplified max elements calculation
    assert(first->_free_items + result->_free_items >= result->_size/16);
    result->_free_items += (first->_free_items - result->_size/16);
    
    for (uint16_t k = 0; k < result->_size/8*result->_d; ++k)
    {
        result->_bitset[k] |= first->_bitset[k];
    }
}

void _np_standard_bloom_clear(np_bloom_t* res)
{
    // res->_type = standard_bf;
    // res->_d = 1;
    // res->_p = 0;
    // res->_num_blocks = 1;
    res->_bitset = calloc(1, (res->_size/8)*res->_d);
    res->_free_items = res->_size / 16;
    
    memset(res->_bitset, 0, res->_num_blocks*res->_size*res->_d/8);
}

np_bloom_t* _np_stable_bloom_create(size_t size, uint8_t d, uint8_t p)
{    
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = stable_bf;
    res->_size = size;
    
    res->_d = d;
    res->_p = p;
    res->_num_blocks = 1;
    
    res->_bitset = calloc(1, (size/8)*res->_d);
    // simplified max elements calculation
    res->_free_items = size / 16;
    
    return res;
}

void _np_stable_bloom_add(np_bloom_t* bloom, np_dhkey_t id)
{
    uint32_t _as_number = 0;
    uint32_t _killed_bits = 0;
    
    if (bloom->_free_items == 0) abort();
    
    for (uint8_t p = 0; p < bloom->_p; ++p)
    {
        // shameless stolen from bind9 random() implementation
#if RAND_MAX >= 0xfffff
        /* We have at least 20 bits.  Use lower 16 excluding lower most 4 */
        _as_number = ((rand() >> 4) & 0xffff) | ((rand() << 12) & 0xffff0000);
#elif RAND_MAX >= 0x7fff
        /* We have at least 15 bits.  Use lower 10/11 excluding lower most 4 */
        _as_number = ((rand() >> 4) & 0x000007ff) | ((rand() << 7) & 0x003ff800) | ((rand() << 18) & 0xffc00000);
#endif
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
        uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t* _current_val   = &bloom->_bitset[_local_pos];
        if (*_current_val > 0) {
            (*_current_val)--; _killed_bits++;
            if (_killed_bits % (bloom->_p/8) ) bloom->_free_items++;
        }
    }
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t  _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t  _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t*  _current_val   = &bloom->_bitset[_local_pos];
        (*_current_val) |=  ((1 << bloom->_d) - 1 );
        
// #ifdef DEBUG
// char test_string[65];
// for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
// np_id_str(test_string, &bloom->_bitset[i]);
// log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos]);
// }
// #endif

    }
    bloom->_free_items--;
}

bool _np_stable_bloom_check(np_bloom_t* bloom, np_dhkey_t id)
{
    bool ret = true;
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t  _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t  _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t*  _current_val = &bloom->_bitset[_local_pos];
        if ( 0 == (*_current_val) ) ret = false;
        // #ifdef DEBUG
        // char test_string[65];
        // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
        //   np_id_str(test_string, &bloom->_bitset[i]);
        // log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos]);
        // }
        // #endif
    }
    
    _np_stable_bloom_add(bloom, id);
    return (ret);
}

np_bloom_t* _np_scalable_bloom_create(size_t size) 
{    
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = scalable_bf;
    res->_size = size;
    res->_d = 1;
    res->_p = 0;
    res->_num_blocks = 1;
    
    res->_bitset = calloc(res->_num_blocks, (size/8)*res->_d);
    res->_free_items = res->_size / 16;
    
    return res;
}

void _np_scalable_bloom_add(np_bloom_t* bloom, np_dhkey_t id)
{
    if (bloom->_free_items == 0)
    {
        uint16_t x = (bloom->_size/8*bloom->_d) * bloom->_num_blocks;
        bloom->_num_blocks++;
        bloom->_bitset = realloc(bloom->_bitset, (bloom->_size/8*bloom->_d) * bloom->_num_blocks);
        bloom->_free_items += bloom->_size/16;
        memset(bloom->_bitset+x, 0, bloom->_size/8*bloom->_d);
    }
    uint16_t bitset_offset = (bloom->_num_blocks-1)*bloom->_size/8*bloom->_d;
    for (uint8_t k = 0; k < 8; ++k)
    {
        // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        // log_msg(LOG_DEBUG, "bap: %d\n", _bit_array_pos);
        uint32_t _local_pos     = ((_bit_array_pos) / 8);
        // log_msg(LOG_DEBUG, " lp: %d\n", _local_pos);
        uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8) );
        // log_msg(LOG_DEBUG, " bm: %x\n", _bitmask);
        (bloom->_bitset+bitset_offset)[_local_pos] |= _bitmask;
// #ifdef DEBUG
        // char test_string[65];
        // np_id_str(test_string, &(bloom->_bitset+bitset_offset)[0]);
        // log_msg(LOG_DEBUG, "add  : %s --> pos=%3d (%02x <-> %02x)", test_string, _local_pos, _bitmask, (bloom->_bitset+bitset_offset)[_local_pos]);
// #endif
    
    }
    
// #ifdef DEBUG
// char test_string[65];
// np_id_str(test_string, &(bloom->_bitset+bitset_offset)[0]);
// log_msg(LOG_DEBUG, "final: %s", test_string);
// #endif
    
    bloom->_free_items--;
}

bool _np_scalable_bloom_check(np_bloom_t* bloom, np_dhkey_t id)
{
    bool ret_val = true;
    
    for (uint8_t j=0; j < bloom->_num_blocks; j++) {
        uint16_t bitset_offset = (j)*bloom->_size/8*bloom->_d;
        ret_val = true;
        for (uint8_t k = 0; k < 8; ++k)
        {
            uint32_t _bit_array_pos = id.t[k] % bloom->_size;
            uint32_t _local_pos     = (_bit_array_pos) / 8;
            uint8_t  _bitmask       = (0x80 >> (_bit_array_pos % 8) );
            uint8_t  result = (bloom->_bitset+bitset_offset)[_local_pos] & _bitmask;
            
            if ( 0 == result ) {
// #ifdef DEBUG
                // char test_string[65];
                // for (uint16_t i = 0; i < bloom->_size/8; i+=32) {
                // np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%d: check: %s --> pos=%3d (%02x <-> %02x)\n", i, test_string, _local_pos, _bitmask, bloom->_bitset[_local_pos]);
                // }
// #endif
                ret_val = false;
            }
        }
        if (ret_val) return (ret_val);
    }
    return (ret_val);
}

np_bloom_t* _np_decaying_bloom_create(size_t size, uint8_t d, uint8_t p) 
{
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = decaying_bf;
    res->_size = size;

    res->_d = d;
    res->_p = p;
    
    res->_bitset = calloc(1, (size/8)*res->_d);
    // simplified max elements calculation
    res->_free_items = size / 16;
    res->_num_blocks = 1;
    
    return res;
}

void _np_decaying_bloom_decay(np_bloom_t* bloom)
{
    uint32_t _zero_bits = 0;
    for (uint16_t k = 0; k < bloom->_size * bloom->_d / 8; ++k)
    {
        uint8_t*  _current_val   = &bloom->_bitset[k];
        // if (*_current_val > 0) (*_current_val) = ((*_current_val) - bloom->_p);
        if (*_current_val > 0) 
        {
            (*_current_val) = ((*_current_val) >> bloom->_p);
        }
        if (*_current_val == 0) _zero_bits++;
    }

    // adjust for left over bits when calculating free items
    bloom->_free_items =  _zero_bits / 16;

// #ifdef DEBUG
// char test_string[65];
// for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
// np_id_str(test_string, &bloom->_bitset[i]);
// log_msg(LOG_DEBUG, "%3d:   age: %s \n", i, test_string);
// }
// #endif
}

void _np_decaying_bloom_add(np_bloom_t* bloom, np_dhkey_t id)
{   
    if (bloom->_free_items == 0) abort();
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t* _current_val   = &bloom->_bitset[_local_pos];
        (*_current_val) |=  (1 << (bloom->_d - 1) );
        
// #ifdef DEBUG
// char test_string[65];
// for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
// np_id_str(test_string, &bloom->_bitset[i]);
// log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos]);
// }
// #endif
   
    }
    bloom->_free_items--;
}

bool _np_decaying_bloom_check(np_bloom_t* bloom, np_dhkey_t id)
{
    bool ret = true;
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t* _current_val   = &bloom->_bitset[_local_pos];
        if ( 0 == (*_current_val) ) ret = false;
        // #ifdef DEBUG
        // char test_string[65];
        // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
        //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos]);
        // }
        // #endif
    }
    return (ret);
}

float _np_decaying_bloom_get_heuristic(np_bloom_t* bloom, np_dhkey_t id)
{
    float ret = 0.0;
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = id.t[k] % bloom->_size;
        uint32_t _local_pos     = _bit_array_pos * bloom->_d / 8;
        uint8_t* _current_val   = &bloom->_bitset[_local_pos];
        
        if   ( 0 == (*_current_val) ) { ret = 0.0; break; }

        uint8_t n = 1;
        while ( (*_current_val>>n) > 0) n++;
        ret = ret > ((float) n)/bloom->_d ? ret : ((float) n)/bloom->_d;
        
        // #ifdef DEBUG
        // char test_string[65];
        // for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
        //   np_id_str(test_string, &bloom->_bitset[i]); log_msg(LOG_DEBUG, "%3d:   add: %s --> pos=%3d (%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos]);
        // }
        // #endif
    }
    return (ret);
}

// neuropil bloom filter size calculation:
// p(nbf) = (1-e^(- n/m))^k        // many thanks for the formulas!
// p(nbf) = (1-e^(- n/m))^4        // k = 4 --> four 3dbf per filter
// p(nbf) = (1-e^(-32/m))^4        // n = 32 --> target to insert 32 elements per filter
// p(nbf) = (1-e^(-32/(3*5*7)))^4  // m = X*Y*Z --> 3*5*7 (?)
// p(nbf) = 0,004762637855         // error probablilty would be 4 in 1000, too low imho
// p(nbf) = (1-e^(-32/(3*5*11)))^4 // m = X*Y*Z --> 3*5*11 (?)
// p(nbf) = 0,0009658999622        // better, approx one in 1000 
// p(nbf) = (1-e^(-32/(3*5*13)))^4 // m = X*Y*Z --> 3*5*13
// p(nbf) = 0,000524653516         // better, approx one in 2000 but still possible to transport
//                                 // one neuropil bf (32 different subjects) with one message chunk

#define SCALE3D_X   3
#define SCALE3D_Y   5
#define SCALE3D_Z  13

#define SCALE3D_FREE_ITEMS 32 // upper limit of items per neuropil bloom filter

np_bloom_t* _np_neuropil_bloom_create() 
{
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = neuropil_bf;
    res->_size = SCALE3D_X*SCALE3D_Y*SCALE3D_Z; // size of each block
    res->_d    = 16; // size of counting and aging bit field (1byte aging and 1byte counting)
    res->_p    =  0; // 
    res->_num_blocks = 4;
    
    res->_bitset = calloc(res->_num_blocks, res->_size*res->_d/8);  //
    // simplified max elements calculation
    res->_free_items = SCALE3D_FREE_ITEMS;
    
    return res;
}

void _np_neuropil_bloom_clear(np_bloom_t* res)
{
    res->_type = neuropil_bf;
    res->_size = SCALE3D_X*SCALE3D_Y*SCALE3D_Z; // size of each block
    res->_d    = 16; // size of counting and aging bit field (1byte aging and 1byte counting)
    res->_p    =  0; // 
    res->_num_blocks = 4;
    
    memset(res->_bitset, 0, res->_num_blocks*res->_size*res->_d/8);
    res->_free_items = SCALE3D_FREE_ITEMS;
}

void _np_neuropil_bloom_add(np_bloom_t* bloom, np_dhkey_t id)
{    
    if (bloom->_free_items == 0) abort();

    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d)/8;

    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = (id.t[k]%SCALE3D_X+1) * (id.t[k]%SCALE3D_Y+1) * (id.t[k]%SCALE3D_Z+1);
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];
        (*_current_age) |=  (1 << (bloom->_d/2 - 1) );
        (*_current_count)++;
        
#ifdef DEBUG
        /*char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d:   add: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }*/
#endif
        if ((k+1)%2 == 0) block_index++;
    }
    // fprintf(stdout, "\n");
    bloom->_free_items--;
}

void _np_neuropil_bloom_remove(np_bloom_t* bloom, np_dhkey_t id)
{    
    if (bloom->_free_items == 0) abort();

    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d)/8;

    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = (id.t[k]%SCALE3D_X+1) * (id.t[k]%SCALE3D_Y+1) * (id.t[k]%SCALE3D_Z+1);
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];
        (*_current_age) =  (*_current_age) >> 1;
        (*_current_count)--;
        
#ifdef DEBUG
        /*char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d:   add: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }*/
#endif
        if ((k+1)%2 == 0) block_index++;
    }
    // fprintf(stdout, "\n");
    bloom->_free_items++;
}

bool _np_neuropil_bloom_check(np_bloom_t* bloom, np_dhkey_t id)
{
    bool ret = true;
    
    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d/8);

    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = ( (id.t[k]%SCALE3D_X+1) * (id.t[k]%SCALE3D_Y+1) * (id.t[k]%SCALE3D_Z+1) );
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];

        // check both field for bit being set
        if ( 0 == (*_current_age) || *_current_count == 0) ret = false;

#ifdef DEBUG
        /*char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d: check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }*/
#endif
        if ((k+1)%2 == 0) block_index++;
    }
#ifdef DEBUG
    // fprintf(stdout, "\n");
#endif
    return (ret);
}

void _np_neuropil_bloom_age_decrement(np_bloom_t* bloom) 
{
    uint16_t block_size = (bloom->_size*bloom->_d/8);

    for (uint16_t k = 0; k < block_size * bloom->_num_blocks; k +=2 )
    {
        uint8_t* _current_age                             = &bloom->_bitset[k];
        if (*_current_age > bloom->_d/2) (*_current_age) -= bloom->_d/2; // ((*_current_age) >> 1);
        else                             (*_current_age)  = 0;
    }
}

void _np_neuropil_bloom_count_decrement(np_bloom_t* bloom) 
{
    uint16_t block_size = (bloom->_size*bloom->_d/8);

    for (uint16_t k = 0; k < block_size * bloom->_num_blocks; k +=2 )
    {
        uint8_t* _current_count  = &bloom->_bitset[k+1];
        if (*_current_count > 0) (*_current_count)--;
    }
    bloom->_free_items++;
}

float _np_neuropil_bloom_get_heuristic(np_bloom_t* bloom, np_dhkey_t id)
{
    float ret = 1.0;
    
    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d/8);

    for (uint8_t k = 0; k < 8; ++k)
    {
        uint32_t _bit_array_pos = ( (id.t[k]%SCALE3D_X+1) * (id.t[k]%SCALE3D_Y+1) * (id.t[k]%SCALE3D_Z+1) );
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t _current_age   = bloom->_bitset[_local_pos  ];
        uint8_t _current_count = bloom->_bitset[_local_pos+1];
        
        if   ( 0 == _current_count) { ret = 0.0; break; }
        ret = ret < ((float) _current_age)/(256) ? ret : ((float) _current_age)/(256);
        
#ifdef DEBUG
        /*char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d: check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }*/
#endif

        if ((k+1)%2 == 0) block_index++;
    }
    return (ret);
}

bool _np_neuropil_bloom_intersect(np_bloom_t* result, np_bloom_t* to_intersect)
{
    assert(result->_type == neuropil_bf);
    assert(result->_type == to_intersect->_type);
    assert(result->_size == SCALE3D_X*SCALE3D_Y*SCALE3D_Z);
    assert(result->_size == to_intersect->_size);
    assert(result->_d    == to_intersect->_d);
    assert(result->_num_blocks == to_intersect->_num_blocks);    
    assert(to_intersect->_free_items + result->_free_items >= SCALE3D_FREE_ITEMS);

    result->_free_items = 0; // an intersection cannot be used for further data addition
    uint16_t i = 0;
    for (uint16_t k = 0; k < result->_num_blocks*result->_size*result->_d/8; k+=2)
    {
        result->_bitset[k  ] &= to_intersect->_bitset[k  ];
        if ((result->_bitset[k  ] > 0)) { // only add if an "age" is left
            result->_bitset[k+1] += to_intersect->_bitset[k+1];
            i++;
        }
        /*
        fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                        result->_bitset[k  ], result->_bitset[k+1],
                        to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
        */
    }
    return (i > 0) ? true : false;
}

bool _np_neuropil_bloom_intersect_test(np_bloom_t* result, np_bloom_t* to_intersect)
{
    assert(result->_type == neuropil_bf);
    assert(result->_type == to_intersect->_type);
    assert(result->_size == SCALE3D_X*SCALE3D_Y*SCALE3D_Z);
    assert(result->_size == to_intersect->_size);
    assert(result->_d    == to_intersect->_d);
    assert(result->_num_blocks == to_intersect->_num_blocks);

    uint16_t i = 0, j = 0;
    
    for (uint16_t k = 0; k < result->_num_blocks*result->_size*result->_d/8; k+=2)
    {
        // only test whether to_intersect is contained in result
        if (result->_bitset[k  ] > 0 && to_intersect->_bitset[k  ] > 0)
        { // only add if an "age" is left
            i += to_intersect->_bitset[k+1];
            if (result->_bitset[k+1] >= to_intersect->_bitset[k+1]) j += to_intersect->_bitset[k+1];
        }
        /*
        fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                        result->_bitset[k  ], result->_bitset[k+1],
                        to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
        */
    }

    return (i == 8 && j == 8) ? true : false;
}

float _np_neuropil_bloom_intersect_age(np_bloom_t* result, np_bloom_t* to_intersect)
{
    assert(result->_type == neuropil_bf);
    assert(result->_type == to_intersect->_type);
    assert(result->_size == SCALE3D_X*SCALE3D_Y*SCALE3D_Z);
    assert(result->_size == to_intersect->_size);
    assert(result->_d    == to_intersect->_d);
    assert(result->_num_blocks == to_intersect->_num_blocks);

    float ret = 1.0;
    uint8_t i = 0;

    for (uint16_t k = 0; k < result->_num_blocks*result->_size*result->_d/8; k+=2)
    {
        // only test whether to_intersect is contained in result
        if (to_intersect->_bitset[k  ] > 0)
        {
            i += to_intersect->_bitset[k+1];
            if (result->_bitset[k  ] > 0)
            {   // only add if an "age" is left
                ret = (ret < (((float) result->_bitset[k  ])/(256)) ) ? ret : ((float) result->_bitset[k  ])/(256);
            }
            else 
            if (result->_bitset[k  ] == 0)
            {
                ret = 0.0;
            }
        }
        /*
        fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                        result->_bitset[k  ], result->_bitset[k+1],
                        to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
        */
    }

    if (i == 0) ret = 0.0;

    return ret;
}

void _np_neuropil_bloom_union(np_bloom_t* result, np_bloom_t* to_add)
{
    assert(result->_type == neuropil_bf);
    assert(result->_type == to_add->_type);
    assert(result->_size == SCALE3D_X*SCALE3D_Y*SCALE3D_Z);
    assert(result->_size == to_add->_size);
    assert(result->_d    == to_add->_d);
    assert(result->_num_blocks == to_add->_num_blocks);
    assert(result->_free_items + to_add->_free_items >= SCALE3D_FREE_ITEMS);

    result->_free_items = result->_free_items - SCALE3D_FREE_ITEMS + to_add->_free_items;

    for (uint16_t k = 0; k < result->_num_blocks*result->_size*result->_d/8; k+=2)
    {   
        result->_bitset[k  ] |= to_add->_bitset[k  ];
        result->_bitset[k+1] += to_add->_bitset[k+1];
        /*      
        fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                        result->_bitset[k  ], result->_bitset[k+1],
                        to_add->_bitset[k  ], to_add->_bitset[k+1]); 
        */
    }
}

void _np_neuropil_bloom_serialize(np_bloom_t* filter, unsigned char** to, uint16_t* to_size)
{
    np_tree_t* data = np_tree_create();

    np_tree_insert_int(data, -1, np_treeval_new_ui(filter->_free_items));

    for (uint16_t k = 0; k < filter->_num_blocks*filter->_size*filter->_d/8; k+=2)
    {
        if ( (filter->_bitset[k  ] > 0) &&
             (filter->_bitset[k+1] > 0)  )
        {
            np_tree_insert_int(data, k, np_treeval_new_iarray(filter->_bitset[k  ], 
                                                              filter->_bitset[k+1]) );
        }
    }

    *to      = malloc(data->byte_size);
    *to_size = data->byte_size;
    np_tree2buffer(NULL, data, *to);
    
    np_tree_free(data);
}

void _np_neuropil_bloom_deserialize(np_bloom_t* filter, unsigned char * from, uint16_t from_size)
{
    np_tree_t* data = np_tree_create();
    np_buffer2tree(NULL, from, data);

    filter->_free_items = np_tree_find_int(data, -1)->val.value.ui;
    np_tree_del_int(data, -1);

    np_tree_elem_t* iter = RB_MIN(np_tree_s, data);
    while (iter != NULL) 
    {
        uint16_t pos = iter->key.value.ui;
        assert(pos >= 0);
        assert(pos < filter->_num_blocks*filter->_size*filter->_d/8);
        filter->_bitset[pos  ] = (uint8_t) iter->val.value.a2_ui[0];
        filter->_bitset[pos+1] = (uint8_t) iter->val.value.a2_ui[1];

        iter = RB_NEXT(np_tree_s, data, iter);
    }
    np_tree_free(data);
}
