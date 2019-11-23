//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <math.h>

#include "np_bloom.h"

#include "neuropil.h"

#include "np_log.h"
#include "np_util.h"

// bloom filter based on np_id / np_dhkey_t
// we treat the np_id as (8 * uint32_t) -> 8 distinct hash values -> pobability of false positive approx 1 in 1024
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

void _np_standard_bloom_add(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number;
    
    if (bloom->_free_items == 0) abort();
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

bool _np_standard_bloom_check(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number;
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

    for (uint16_t k = 0; k < result->_size/8*result->_d; ++k)
    {
        result->_bitset[k] &= first->_bitset[k];
    }
}

bool _np_standard_bloom_union(np_bloom_t* result, np_bloom_t* first)
{
    assert(first->_type == standard_bf);
    assert(first->_type == result->_type);
    assert(first->_size == result->_size);
    assert(first->_d == result->_d);
    assert(first->_num_blocks == result->_num_blocks);

    // simplified max elements calculation
    assert(first->_free_items + result->_free_items >= result->_size/16);
    result->_free_items = first->_free_items - result->_size/16; 
    
    uint32_t _as_number;
    for (uint16_t k = 0; k < result->_size/8*result->_d; ++k)
    {
        result->_bitset[k] |= first->_bitset[k];
    }
}

np_bloom_t* _np_stable_bloom_create(size_t size, uint8_t d, uint8_t p)
{    
    np_bloom_t* res = (np_bloom_t*) calloc(1, sizeof(np_bloom_t));
    res->_type = stable_bf;
    res->_size = size;
    
    res->_d = d;
    res->_p = p;
    
    res->_bitset = calloc(1, (size/8)*res->_d);
    // simplified max elements calculation
    res->_free_items = size / 16;
    res->_num_blocks = 1;
    
    return res;
}

void _np_stable_bloom_add(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number = 0;
    static uint32_t _killed_bits = 0;
    
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
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t  _bit_array_pos = (_as_number) % bloom->_size;
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

bool _np_stable_bloom_check(np_bloom_t* bloom, np_id id)
{
    bool ret = true;
    
    uint32_t _as_number = 0;
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t  _bit_array_pos = (_as_number) % bloom->_size;
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

void _np_scalable_bloom_add(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number;
    
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
        memcpy (&_as_number, &id[k*4], 4);
        // log_msg(LOG_DEBUG, "n  : %u\n", _as_number);
        uint32_t _bit_array_pos = ((_as_number) % bloom->_size);
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

bool _np_scalable_bloom_check(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number;
    bool ret_val = true;
    
    for (uint8_t j=0; j < bloom->_num_blocks; j++) {
        uint16_t bitset_offset = (j)*bloom->_size/8*bloom->_d;
        ret_val = true;
        for (uint8_t k = 0; k < 8; ++k)
        {
            memcpy (&_as_number, &id[k*4], 4);
            uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

np_bloom_t* _np_decaying_bloom_create(size_t size, uint8_t d, uint8_t p) {
    
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
    for (uint16_t k = 0; k < bloom->_size * bloom->_d / 8; ++k)
    {
        uint8_t*  _current_val   = &bloom->_bitset[k];
        // if (*_current_val > 0) (*_current_val) = ((*_current_val) - bloom->_p);
        (*_current_val) = ((*_current_val) >> bloom->_p);
    }
// #ifdef DEBUG
// char test_string[65];
// for (uint16_t i = 0; i < bloom->_size/8*bloom->_d; i+=32 ) {
// np_id_str(test_string, &bloom->_bitset[i]);
// log_msg(LOG_DEBUG, "%3d:   age: %s \n", i, test_string);
// }
// #endif
}

void _np_decaying_bloom_add(np_bloom_t* bloom, np_id id)
{
    uint32_t _as_number = 0;
    
    if (bloom->_free_items == 0) abort();
    
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

bool _np_decaying_bloom_check(np_bloom_t* bloom, np_id id)
{
    bool ret = true;
    
    uint32_t _as_number = 0;
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

float _np_decaying_bloom_get_heuristic(np_bloom_t* bloom, np_id id)
{
    float ret = 0.0;
    
    uint32_t _as_number = 0;
    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = (_as_number) % bloom->_size;
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

// until somebody finds out that this is too small ...
#define SCALE3D_X  3
#define SCALE3D_Y  5
#define SCALE3D_Z  7

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
    
    memset(res->_bitset, res->_num_blocks*res->_size*res->_d/8, 0);
    res->_free_items = SCALE3D_FREE_ITEMS;
}

void _np_neuropil_bloom_add(np_bloom_t* bloom, np_id id)
{    
    if (bloom->_free_items == 0) abort();

    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d)/8;
    uint32_t _as_number = 0;

    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = ((_as_number%SCALE3D_X)+1) * ((_as_number%SCALE3D_Y)+1) * ((_as_number%SCALE3D_Z)+1);
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];
        (*_current_age) |=  (1 << (bloom->_d/2 - 1) );
        (*_current_count)++;

#ifdef DEBUG
        char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d:   add: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }
#endif
        if ((k+1)%2 == 0) block_index++;
    }
    fprintf(stdout, "\n");
    bloom->_free_items--;
}

bool _np_neuropil_bloom_check(np_bloom_t* bloom, np_id id)
{
    bool ret = true;
    
    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d/8);

    uint32_t _as_number = 0;

    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = ((_as_number%SCALE3D_X)+1) * ((_as_number%SCALE3D_Y)+1) * ((_as_number%SCALE3D_Z)+1);
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];

        // check both field for bit being set
        if ( 0 == (*_current_age) || _current_count == 0) ret = false;

#ifdef DEBUG
        char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d: check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }
#endif
        if ((k+1)%2 == 0) block_index++;
    }
#ifdef DEBUG
    fprintf(stdout, "\n");
#endif
    return (ret);
}

void _np_neuropil_bloom_age_decrement(np_bloom_t* bloom) 
{
    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d/8);
    uint32_t _as_number = 0;

    for (uint16_t k = 0; k < block_size*4; k +=2 )
    {
        uint8_t* _current_age                 = &bloom->_bitset[k];
        if (_current_age > 0) (*_current_age) = ((*_current_age) >> 1);
    }
}

float _np_neuropil_bloom_get_heuristic(np_bloom_t* bloom, np_id id)
{
    float ret = 0.0;
    
    uint8_t block_index = 1;
    uint16_t block_size = (bloom->_size*bloom->_d/8);
    uint32_t _as_number = 0;

    for (uint8_t k = 0; k < 8; ++k)
    {
        memcpy (&_as_number, &id[k*4], 4);
        uint32_t _bit_array_pos = ((_as_number%SCALE3D_X)+1) * ((_as_number%SCALE3D_Y)+1) * ((_as_number%SCALE3D_Z)+1);
        uint32_t _local_pos     = (block_index-1)*block_size + (_bit_array_pos-1)*2;
        uint8_t* _current_age   = &bloom->_bitset[_local_pos  ];
        uint8_t* _current_count = &bloom->_bitset[_local_pos+1];
        
        if   ( 0 == (*_current_age) || 0 == _current_count) { ret = 0.0; break; }

        uint8_t n = 1;
        while ( (*_current_age>>n) > 0) n++;
        ret = ret > ((float) n)/(bloom->_d/2) ? ret : ((float) n)/(bloom->_d/2);
        
#ifdef DEBUG
        char test_string[65];
        for (uint16_t i = (block_index-1)*block_size; i < block_index*block_size; i+=32 ) {
          np_id_str(test_string, &bloom->_bitset[i]); 
          fprintf(stdout, "%3d: check: %s --> pos=%3d (%02x%02x)\n", i, test_string, _local_pos, bloom->_bitset[_local_pos*2], bloom->_bitset[_local_pos*2+1]);
        }
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

    for (uint16_t k = 0; k < result->_num_blocks*result->_size*result->_d/8; k+=2)
    {
        uint8_t* _current_age   = &result->_bitset[k  ];
        uint8_t* _current_count = &result->_bitset[k+1];
        
        result->_bitset[k  ] &= to_intersect->_bitset[k  ];
        if ((result->_bitset[k  ] > 0)) { // only add if an "age" is left
            result->_bitset[k+1] += to_intersect->_bitset[k+1];
        }
        /*
        fprintf(stdout, "%4d:union: %02x%02x --> %02x%02x\n", k,
                        result->_bitset[k  ], result->_bitset[k+1],
                        to_intersect->_bitset[k  ], to_intersect->_bitset[k+1]);
        */
    }    
    return true;
}

bool _np_neuropil_bloom_union(np_bloom_t* result, np_bloom_t* to_add)
{
    assert(to_add->_type == neuropil_bf);
    assert(to_add->_type == to_add->_type);
    assert(to_add->_size == SCALE3D_X*SCALE3D_Y*SCALE3D_Z);
    assert(to_add->_size == result->_size);
    assert(to_add->_d == result->_d);
    assert(to_add->_num_blocks == result->_num_blocks);
    assert(to_add->_free_items + result->_free_items >= SCALE3D_FREE_ITEMS);

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
    return true;
}

