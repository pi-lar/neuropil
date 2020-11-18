//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include "np_pheromones.h"

#include "util/np_bloom.h"
#include "np_constants.h"
#include "np_dhkey.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_settings.h"


int8_t np_dhkey_t_sll_compare_type(np_dhkey_t const a, np_dhkey_t const b)
{ return _np_dhkey_cmp(&a, &b); }

NP_SLL_GENERATE_IMPLEMENTATION(np_dhkey_t);


typedef struct np_pheromone_entry_s
{
    np_pheromone_t _pheromone[32];
    uint16_t _count;
} np_pheromone_entry_t;

np_module_struct(pheromones)
{
    np_state_t* context;
    np_pheromone_entry_t* pheromones[257];

    struct np_bloom_optable_s _op;
};

void __init_pheromones(np_state_t* context) 
{
    np_module_malloc(pheromones);
    np_module(pheromones)->context = context;

    char mutex_str[64];
    snprintf(mutex_str, 63, "%s:%p", "urn:np:pheromones:access", context);

    struct np_bloom_optable_s _op =
        {
            .add_cb       = _np_neuropil_bloom_add,
            .check_cb     = _np_neuropil_bloom_check,
            .clear_cb     = _np_neuropil_bloom_clear,
            .union_cb     = _np_neuropil_bloom_union,
            .intersect_cb = _np_neuropil_bloom_intersect
        };
    np_module(pheromones)->_op = _op;
}

bool _np_pheromone_inhale(np_state_t* context, np_pheromone_t pheromone) 
{
    if (np_module_not_initiated(pheromones))
    {
        __init_pheromones(context);
    }

    bool ret = false;

    if (pheromone._subject == NULL && 
        pheromone._subj_bloom == NULL)
    {   
        return false;
    }

    if (pheromone._subject != NULL)
    {   // set the bloom filter bits to "max" if a "complete" dhkey is given
        if (pheromone._subj_bloom == NULL) {
            pheromone._subj_bloom = _np_neuropil_bloom_create();
            pheromone._subj_bloom->op = np_module(pheromones)->_op;
        } else {
            np_module(pheromones)->_op.clear_cb(pheromone._subj_bloom);
        }
        np_module(pheromones)->_op.add_cb(pheromone._subj_bloom, *pheromone._subject);
    }

    ASSERT(pheromone._pos != 0, "invalid pheromone index value");

    uint16_t index = 256;
    if (pheromone._pos > 0 ) index =  pheromone._pos - 1;
    if (pheromone._pos < 0 ) index = -pheromone._pos - 1;
    // log_debug_msg(LOG_DEBUG, "adding pheromone entries at index %d --> %u", pheromone._pos, index);

    ASSERT(index >= 0 && index < 257, "pheromone index out of range");

    _LOCK_MODULE(np_pheromones_t)
    {
        bool update_filter = false;
        
        np_pheromone_entry_t* _entry = np_module(pheromones)->pheromones[index];
        if (_entry == NULL)
        {
            np_pheromone_entry_t* _new = (np_pheromone_entry_t*) calloc(1, sizeof(np_pheromone_entry_t) );
            CHECK_MALLOC(_new);
            _new->_count = 1;
            _new->_pheromone[0]._subj_bloom = _np_neuropil_bloom_create();
            _new->_pheromone[0]._subj_bloom->op = np_module(pheromones)->_op;
            log_debug_msg(LOG_DEBUG, "added new pheromone_entry_t at index %3d", index);

            np_module(pheromones)->pheromones[index] = _entry = _new;
        }

        uint16_t i = 1;
        while ( i < _entry->_count) 
        {
            if (_np_neuropil_bloom_intersect_test(_entry->_pheromone[i]._subj_bloom, pheromone._subj_bloom) )
            {
                float old_age = _np_neuropil_bloom_intersect_age(_entry->_pheromone[i]._subj_bloom, pheromone._subj_bloom);
                float new_age = _np_neuropil_bloom_intersect_age(pheromone._subj_bloom, _entry->_pheromone[i]._subj_bloom);
    
                np_dhkey_t _null = {0};

                if (pheromone._pos < 0                                && 
                    !_np_dhkey_equal(&pheromone._sender, &_null)       )
                {
                    if (sll_contains(np_dhkey_t, _entry->_pheromone[i]._send_list, pheromone._sender, np_dhkey_t_sll_compare_type)) {
                        sll_remove(np_dhkey_t, _entry->_pheromone[i]._send_list, pheromone._sender, np_dhkey_t_sll_compare_type);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }
                    sll_prepend(np_dhkey_t, _entry->_pheromone[i]._send_list, pheromone._sender);
                    update_filter = true;
                    
                    if (sll_size(_entry->_pheromone[i]._send_list) > NP_ROUTE_LEAFSET_SIZE ) 
                    {
                        sll_tail(np_dhkey_t, _entry->_pheromone[i]._send_list);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }

                    np_module(pheromones)->_op.union_cb(_entry->_pheromone[i]._subj_bloom, pheromone._subj_bloom);

                    log_debug_msg(LOG_DEBUG, "added send pheromone entry at index %3d:%2d --> %u (%.3f/%.3f) -- > %u", 
                                      pheromone._pos, index, i, old_age, new_age, _entry->_pheromone[i]._subj_bloom->_free_items);
                }
                
                if (pheromone._pos > 0                              && 
                    !_np_dhkey_equal(&pheromone._receiver, &_null)   )
                {   
                    if (sll_contains(np_dhkey_t, _entry->_pheromone[i]._recv_list, pheromone._receiver, np_dhkey_t_sll_compare_type)) {
                        sll_remove(np_dhkey_t, _entry->_pheromone[i]._recv_list, pheromone._receiver, np_dhkey_t_sll_compare_type);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }
                    sll_prepend(np_dhkey_t, _entry->_pheromone[i]._recv_list, pheromone._receiver);
                    update_filter = true;

                    if (sll_size(_entry->_pheromone[i]._recv_list) > NP_ROUTE_LEAFSET_SIZE ) 
                    {
                        sll_tail(np_dhkey_t, _entry->_pheromone[i]._recv_list);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }

                    np_module(pheromones)->_op.union_cb(_entry->_pheromone[i]._subj_bloom, pheromone._subj_bloom);
                    
                    log_debug_msg(LOG_DEBUG, "added recv pheromone entry at index %3d:%2d --> %u (%.3f/%.3f) --> %u", 
                                      pheromone._pos, index, i, old_age, new_age, _entry->_pheromone[i]._subj_bloom->_free_items);
                }

                if (update_filter) 
                {
                    // to update heuristic/age value
                    np_module(pheromones)->_op.union_cb(_entry->_pheromone[0]._subj_bloom, pheromone._subj_bloom);
                    _np_neuropil_bloom_count_decrement(_entry->_pheromone[0]._subj_bloom);
                    // yes, this is ugly! on purpose:
                    _entry->_pheromone[0]._subj_bloom->_free_items = _entry->_count;
                    // update of a bloom filter at this stage would hit the free item counter, which is unwanted.
                    // this counter is already in place at the top level bloom filter. We do not need it here! 
                    // Even if double entries occur, the filter should still be intact because we have some buffer 
                    // probability left
                    log_debug_msg(LOG_DEBUG, "update 0-pheromone at index %3d:%2d / %d --> %u", index, i, _entry->_pheromone[i]._subj_bloom->_free_items, _entry->_pheromone[0]._subj_bloom->_free_items);
                }
                break;
            }
            else {
                log_debug_msg(LOG_DEBUG, "intersect failed for pheromone at index %3d:%2d / %d --> %u", index, i, _entry->_pheromone[i]._subj_bloom->_free_items, _entry->_pheromone[0]._subj_bloom->_free_items);
            }
            i++;
        }

        // if (i >= 32) return update_filter;
        // sanity check for full filter
        ASSERT( i > 0 && i < 32, "insertion index out of range");

        if (i == _entry->_count && !update_filter)
        {
            np_module(pheromones)->_op.union_cb(_entry->_pheromone[0]._subj_bloom, pheromone._subj_bloom);

            sll_init(np_dhkey_t, _entry->_pheromone[i]._send_list);
            sll_init(np_dhkey_t, _entry->_pheromone[i]._recv_list);

            if (pheromone._pos > 0) {
                sll_prepend(np_dhkey_t, _entry->_pheromone[i]._recv_list, pheromone._receiver);
            }
            if (pheromone._pos < 0) {
                sll_prepend(np_dhkey_t, _entry->_pheromone[i]._send_list, pheromone._sender);
            }

            _entry->_pheromone[i]._subject        = pheromone._subject;
            _entry->_pheromone[i]._pos            = index;
            _entry->_pheromone[i]._subj_bloom     = _np_neuropil_bloom_create();
            np_module(pheromones)->_op.union_cb(_entry->_pheromone[i]._subj_bloom, pheromone._subj_bloom);

            _entry->_count++;
            _entry->_pheromone[0]._subj_bloom->_free_items = _entry->_count;

            update_filter = true;

            if (pheromone._pos < 0)
                log_debug_msg(LOG_DEBUG, "added send pheromone at index %3d:%2d / %d %p/%p", index, i, pheromone._subj_bloom->_free_items, pheromone._sender, _entry->_pheromone[i]._send_list);
            else 
                log_debug_msg(LOG_DEBUG, "added recv pheromone at index %3d:%2d / %d %p/%p", index, i, pheromone._subj_bloom->_free_items, pheromone._receiver, _entry->_pheromone[i]._recv_list);
        }
        ret = (update_filter) ? true : false;
    }
    return ret;
}

void _np_pheromone_snuffle(np_state_t* context, sll_return(np_dhkey_t) result_list, np_dhkey_t to_check, float* target_probability, bool find_sender, bool find_receiver) 
{
    if (np_module_not_initiated(pheromones))
    {
        __init_pheromones(context);
    }

    uint16_t index = to_check.t[0] % 257;
    ASSERT(index >= 0 && index < 257, "pheromone index out of range");

    _LOCK_MODULE(np_pheromones_t)
    {
        np_pheromone_entry_t* _entry = np_module(pheromones)->pheromones[index];
        if (_entry != NULL && np_module(pheromones)->_op.check_cb(_entry->_pheromone[0]._subj_bloom, to_check) )
        {
            log_debug_msg(LOG_DEBUG, "found potential pheromone at index %3d", index);
            float new_probability = _np_neuropil_bloom_get_heuristic(_entry->_pheromone[0]._subj_bloom, to_check);
        
            if (*target_probability <= new_probability) {
                
                if (*target_probability < new_probability)
                {
                    *target_probability = new_probability;
                    log_debug_msg(LOG_DEBUG, "target probability of pheromone set to: %f", new_probability);
                }

                for (uint8_t i = 1; i < _entry->_count; i++)
                {
                    if (np_module(pheromones)->_op.check_cb(_entry->_pheromone[i]._subj_bloom, to_check) )
                    {
                        if (find_sender && sll_size(_entry->_pheromone[i]._send_list) > 0) {
                            np_dhkey_t_sll_clone(_entry->_pheromone[i]._send_list, result_list);
                            log_debug_msg(LOG_DEBUG, "added %d send pheromones from index (%3d:%2d) to result list %p", sll_size(result_list), index, i, result_list);
                        }

                        if (find_receiver && sll_size(_entry->_pheromone[i]._recv_list) > 0) {
                            np_dhkey_t_sll_clone(_entry->_pheromone[i]._recv_list, result_list);
                            log_debug_msg(LOG_DEBUG, "added %d recv pheromones from index (%3d:%2d) to result list %p", sll_size(result_list), index, i, result_list);
                        }
                    }
                    else 
                    {
                        log_debug_msg(LOG_DEBUG, "checking next pheromone in set at index %3d", index);
                    }
                }
            }
            else{
                log_debug_msg(LOG_DEBUG, "target probability (%f) of pheromone not met, have: %f", *target_probability, new_probability);
            }
        } else {
            log_debug_msg(LOG_DEBUG, "target probability of pheromone set to: 0.0, index %3d is empty", index);
            *target_probability = 0.0;
        }
    }
}

void _np_pheromone_snuffle_receiver(np_state_t* context, sll_return(np_dhkey_t) result_list, np_dhkey_t to_check, float* target_probability) 
{
    _np_pheromone_snuffle(context, result_list, to_check, target_probability, false, true);
}

void _np_pheromone_snuffle_sender(np_state_t* context, sll_return(np_dhkey_t) result_list, np_dhkey_t to_check, float* target_probability) 
{
    _np_pheromone_snuffle(context, result_list, to_check, target_probability, true, false);
}

void _np_pheromone_exhale(np_state_t* context)
{
    if (np_module_not_initiated(pheromones))
    {
        __init_pheromones(context);
    }

    uint32_t _random_number = 0;
    // shameless stolen from bind9 random() implementation
#if RAND_MAX >= 0xfffff
    /* We have at least 20 bits.  Use lower 16 excluding lower most 4 */
    _random_number = ((rand() >> 4) & 0xffff) | ((rand() << 12) & 0xffff0000);
#elif RAND_MAX >= 0x7fff
    /* We have at least 15 bits.  Use lower 10/11 excluding lower most 4 */
    _random_number = ((rand() >> 4) & 0x000007ff) | ((rand() << 7) & 0x003ff800) | ((rand() << 18) & 0xffc00000);
#endif

    _LOCK_MODULE(np_pheromones_t)
    {
        np_pheromone_entry_t* _entry = np_module(pheromones)->pheromones[_random_number % 257]; 
        if (_entry != NULL)
        {
            // np_module(pheromones)->_op.clear_cb(_entry->_pheromone[0]._subj_bloom);
            _np_neuropil_bloom_age_decrement(_entry->_pheromone[0]._subj_bloom);

            uint8_t i = 1;
            while ( i < _entry->_count) 
            {   
                _np_neuropil_bloom_age_decrement(_entry->_pheromone[i]._subj_bloom);

                float _age = _np_neuropil_bloom_intersect_age(_entry->_pheromone[0]._subj_bloom, _entry->_pheromone[i]._subj_bloom);
                log_debug_msg(LOG_DEBUG, "decreased pheromone strength (index %3d:%2d) age now %f",
                                        _random_number%257, i, _age);

                if (_age == 0.0)
                {
                    log_debug_msg(LOG_ERROR, "decreased pheromone strength (index %3d:%2d) age now %f",
                                             _random_number%257, i, _age);

                    sll_free(np_dhkey_t, _entry->_pheromone[i]._recv_list);
                    sll_free(np_dhkey_t, _entry->_pheromone[i]._send_list);

                    _np_bloom_free(_entry->_pheromone[i]._subj_bloom);

                    // TODO: use memmove?
                    uint8_t j = i;
                    while(j < _entry->_count)
                    {
                        _entry->_pheromone[j] = _entry->_pheromone[j+1];
                        j++;
                    }
                    memset(&_entry->_pheromone[j], 0, sizeof(np_pheromone_t));

                    _entry->_count--;
                    _entry->_pheromone[0]._subj_bloom->_free_items = _entry->_count;

                    log_debug_msg(LOG_DEBUG, "removed pheromone at index %3d:%2d)",
                                             _random_number%257, i);
                }
                else 
                {
                    if (sll_size(_entry->_pheromone[i]._recv_list) > 1 ) 
                    {
                        sll_tail(np_dhkey_t, _entry->_pheromone[i]._recv_list);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }
                    if (sll_size(_entry->_pheromone[i]._send_list) > 1 ) 
                    {
                        sll_tail(np_dhkey_t, _entry->_pheromone[i]._send_list);
                        _np_neuropil_bloom_count_decrement(_entry->_pheromone[i]._subj_bloom);
                    }

                    log_debug_msg(LOG_DEBUG, "decreased pheromone strength (index %3d:%2d) age now %f --> %u",
                                      _random_number%257, i, _age,  _entry->_pheromone[i]._subj_bloom->_free_items);

                    i++;
                }
            }
        }
    }
}
