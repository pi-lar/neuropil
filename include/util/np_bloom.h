//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_BLOOMFILTER_H_
#define _NP_BLOOMFILTER_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include <math.h>

#include "neuropil.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct np_bloom_s np_bloom_t;

    typedef np_bloom_t* (*bloom_factory_create)  (const char* bloom_type, size_t size);
    typedef void        (*bloom_free          )  (np_bloom_t *bloom);
    typedef void        (*bloom_clear         )  (np_bloom_t *bloom);

    typedef void        (*bloom_add           )  (np_bloom_t *bloom, np_dhkey_t s);
    typedef bool        (*bloom_check         )  (np_bloom_t *bloom, np_dhkey_t s);

    typedef void        (*bloom_union         )  (np_bloom_t *result, np_bloom_t *bloom_l);
    typedef bool        (*bloom_intersect     )  (np_bloom_t *result, np_bloom_t *bloom_l);

    enum bloom_filter_type {
        standard_bf = 0,
        stable_bf,
        scalable_bf,
        decaying_bf,
        counting_bf,
        neuropil_bf,
    };

    struct np_bloom_optable_s {
        bloom_clear     clear_cb;
        bloom_add       add_cb;
        bloom_check     check_cb;
        bloom_union     union_cb;
        bloom_intersect intersect_cb;
    };

    // bloom filter structure, basically a bitset with additional properties
    struct np_bloom_s {
        // design time variables
        enum bloom_filter_type _type;
        // uint8_t _hash_funcs = 8; // fixed for neuropil, always working on np_dhkey_t
        size_t   _size; // size of the bitset (256 = 256 bits = 32 byte)
        uint8_t  _d; // number of bits per item
        uint8_t  _p; // prone rate (number of items to decrement) for stable bloom filter
        // or decaying rate/shift for attenuated bloom filter

        // runtime variables
        uint8_t* _bitset; // ponter to bitset
        uint8_t _num_blocks; // for scalable bloom filter
        uint16_t _free_items; // item counter for bitste (initial value is max, decremented per insert)

        struct  np_bloom_optable_s op; // list of operations availabe for bloom filter
    };

    // bloom filter based on np_dhkey_t
    // we treat the np_dhkey_t as (8 * uint32_t) -> 8 distinct hash values -> pobability of false positive approx 1 in 1024

    // _size of bit array :  256 -> max _items per bloom filter is  18
    // _size of bit array :  512 -> max _items per bloom filter is  35
    // _size of bit array : 1024 -> max _items per bloom filter is  70
    // _size of bit array : 2048 -> max _items per bloom filter is 140

    NP_API_INTERN
    void _np_bloom_free(np_bloom_t* bloom);

    // a standard bloom filter
    NP_API_INTERN
    np_bloom_t* _np_standard_bloom_create(size_t bit_size);
    NP_API_INTERN
    void _np_standard_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_standard_bloom_check(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_standard_bloom_intersect(np_bloom_t* result, np_bloom_t* first);
    NP_API_INTERN
    void _np_standard_bloom_union(np_bloom_t* result, np_bloom_t* first);
    NP_API_INTERN
    void _np_standard_bloom_clear(np_bloom_t* res);

    // stable bloom filter
    NP_API_INTERN
    np_bloom_t* _np_stable_bloom_create(size_t size, uint8_t d, uint8_t p);
    NP_API_INTERN
    void _np_stable_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_stable_bloom_check(np_bloom_t* bloom, np_dhkey_t id);

    // scalable bloom filter
    NP_API_INTERN
    np_bloom_t* _np_scalable_bloom_create(size_t size);
    NP_API_INTERN
    void _np_scalable_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_scalable_bloom_check(np_bloom_t* bloom, np_dhkey_t id);

    // decaying bloom filter
    NP_API_INTERN
    np_bloom_t* _np_decaying_bloom_create(size_t size, uint8_t d, uint8_t p);
    NP_API_INTERN
    void _np_decaying_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_decaying_bloom_check(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    void _np_decaying_bloom_decay(np_bloom_t* bloom);
    NP_API_INTERN
    float _np_decaying_bloom_get_heuristic(np_bloom_t* bloom, np_dhkey_t id);

    // counting bloom filter
    NP_API_INTERN
    np_bloom_t* _np_counting_bloom_create(size_t size, uint8_t d, uint8_t p);
    NP_API_INTERN
    void _np_counting_bloom_clear(np_bloom_t* res);
    NP_API_INTERN
    void _np_counting_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    void _np_counting_bloom_remove(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    bool _np_counting_bloom_check(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    void _np_counting_bloom_containment(np_bloom_t* first, np_bloom_t* second, float* result);

    // neuropil bloom filter (mix of counting / attenuated bf)
    NP_API_INTERN
    np_bloom_t* _np_neuropil_bloom_create();
    NP_API_INTERN
    void _np_neuropil_bloom_clear(np_bloom_t* res);

    NP_API_INTERN
    void _np_neuropil_bloom_add(np_bloom_t* bloom, np_dhkey_t id);
    NP_API_INTERN
    void _np_neuropil_bloom_remove(np_bloom_t* bloom, np_dhkey_t id);

    NP_API_INTERN
    bool _np_neuropil_bloom_check(np_bloom_t* bloom, np_dhkey_t id);

    NP_API_INTERN
    void _np_neuropil_bloom_age_decrement(np_bloom_t* bloom);
    NP_API_INTERN
    void _np_neuropil_bloom_count_decrement(np_bloom_t* bloom);

    NP_API_INTERN
    float _np_neuropil_bloom_get_heuristic(np_bloom_t* bloom, np_dhkey_t id);

    NP_API_INTERN
    bool _np_neuropil_bloom_intersect(np_bloom_t* result, np_bloom_t* first);
    NP_API_INTERN
    bool _np_neuropil_bloom_intersect_test(np_bloom_t* result, np_bloom_t* to_intersect);
    NP_API_INTERN
    bool _np_neuropil_bloom_intersect_ignore_age(np_bloom_t* result, np_bloom_t* to_intersect);
    NP_API_INTERN
    float _np_neuropil_bloom_intersect_age(np_bloom_t* result, np_bloom_t* to_intersect);
    NP_API_INTERN
    void _np_neuropil_bloom_union(np_bloom_t* result, np_bloom_t* first);

    NP_API_INTERN
    void _np_neuropil_bloom_similarity(np_bloom_t* first, np_bloom_t* second, float* result);
    NP_API_INTERN
    void _np_neuropil_bloom_containment(np_bloom_t* first, np_bloom_t* second, bool* result);
    NP_API_INTERN
    int _np_neuropil_bloom_cmp(np_bloom_t* a, np_bloom_t* b);

    NP_API_INTERN
    void _np_neuropil_bloom_serialize(np_bloom_t* filter, unsigned char ** to, uint16_t* to_size);
    NP_API_INTERN
    void _np_neuropil_bloom_deserialize(np_bloom_t* filter, unsigned char * from, uint16_t from_size);
    NP_API_INTERN
    void _np_neuropil_bloom_compress(np_bloom_t* filter, unsigned char** to, size_t* to_size);

#ifdef __cplusplus
}
#endif

#endif // _NP_BLOOMFILTER_H_
