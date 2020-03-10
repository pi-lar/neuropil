//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_PHEROMONE_TABLE_H
#define _NP_PHEROMONE_TABLE_H

#include <stdint.h>
#include <assert.h>

#include "np_dhkey.h"
#include "np_bloom.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * a pheromone table is used to store a set of bloom filter in a scalable and efficient way.
 * 
 * On the first level we use a simple hash partitioning scheme (modulo 257) by simply using 
 * inserting bloom filter into the right slot. Within this slot we use an array of 32 neuropil 
 * bloom filter. The first element contains the union of the remaining 31 bloom filter. This enables
 * us to query this set of bloom filter very fast. In theory we could append more arrays, but 
 * right now this is not planned. If you would like to do so, please take care of the probability
 * calculations involved).
 */

    // the pheromone struct defines the data we would liek to store in our table
    typedef struct np_pheromone_s 
    {
        // the _subject should just be a bloom filter, so that we can do a "union_cb"
        np_dhkey_t *_subject;    // the subject of the intent/message
        np_bloom_t *_subj_bloom; // bloom attr filter
        int16_t _pos;

        np_key_ptr _sender;     // the next hop we received an intent
        np_key_ptr _receiver;   // the next hop we received an intent

        np_sll_t(np_key_ptr, _send_list);
        np_sll_t(np_key_ptr, _recv_list);

        np_bloom_t _attr_bloom; // bloom attr filter (if full intent arrived)
    } np_pheromone_t;

    NP_API_INTERN
    bool _np_pheromone_inhale(np_state_t* context, np_pheromone_t pheromone);
    NP_API_INTERN
    void _np_pheromone_inhale_scent(np_state_t* context, uint16_t pos, np_bloom_t scent);

    NP_API_INTERN
    void _np_pheromone_snuffle(np_state_t* context, sll_return(np_key_ptr) result_list, np_dhkey_t to_check, float* target_probability, bool find_sender, bool find_receiver);
    NP_API_INTERN
    void _np_pheromone_snuffle_receiver(np_state_t* context, sll_return(np_key_ptr) result_list, np_dhkey_t to_check, float* target_probability);
    NP_API_INTERN
    void _np_pheromone_snuffle_sender(np_state_t* context, sll_return(np_key_ptr) result_list, np_dhkey_t to_check, float* target_probability);

    NP_API_INTERN
    void _np_pheromone_exhale(np_state_t* context);

    NP_API_INTERN
    void _np_pheromone_serialize(np_pheromone_t pheromone, void* buffer);
    NP_API_INTERN
    void _np_pheromone_deserialize(void* buffer, np_pheromone_t* pheromone);

#ifdef __cplusplus
}
#endif

#endif // _NP_PHEROMONE_TABLE_H
