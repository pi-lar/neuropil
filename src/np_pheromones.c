//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_pheromones.h"

#include <inttypes.h>

#include "neuropil_log.h"

#include "util/np_bloom.h"

#include "np_constants.h"
#include "np_dhkey.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_settings.h"
#include "np_statistics.h"

int8_t np_dhkey_t_sll_compare_type(np_dhkey_t const a, np_dhkey_t const b) {
  return _np_dhkey_cmp(&a, &b);
}

typedef struct np_pheromone_entry_s {
  np_pheromone_t _pheromone[32];
  uint16_t       _count;
} np_pheromone_entry_t;

np_module_struct(pheromones) {
  np_state_t           *context;
  np_pheromone_entry_t *pheromones[257];

  struct np_bloom_optable_s _op;
};

struct np_pheromone_details_s {
  np_dhkey_t peer_id;
  double     insert_ts;
};

bool __np_pheromones_periodic_log(np_state_t               *context,
                                  NP_UNUSED np_util_event_t event) {
  uint64_t _count            = 0;
  uint64_t _free_items       = 0;
  uint64_t _free_items_total = 0;
  _LOCK_MODULE(np_pheromones_t) {
    for (int i = 0; i < 257; i++) {
      np_pheromone_entry_t *e = np_module(pheromones)->pheromones[i];
      if (e != NULL) {
        _count += e->_count;

        for (int p = 0; p < e->_count; p++) {
          if (e->_pheromone[p]._subj_bloom != NULL) {
            _free_items += e->_pheromone[p]._subj_bloom->_free_items;
            _free_items_total += 64; // SCALE3D_FREE_ITEMS;

            log_info(LOG_EXPERIMENT,
                     "[pheromone bloom %" PRId32 "/%" PRId32
                     " capacity] count:%" PRIu16 " _free_items:%" PRIu16
                     " _free_items_total:%" PRIu64 " fill: %f",
                     i,
                     p,
                     e->_count,
                     e->_pheromone[p]._subj_bloom->_free_items,
                     64, // SCALE3D_FREE_ITEMS;
                     1 - (e->_pheromone[p]._subj_bloom->_free_items / (64.0)));
          }
        }
      }
    }
  }
  if (_free_items_total > 0) {
    log_info(LOG_EXPERIMENT,
             "[pheromone capacity] total count:%" PRIu64 " _free_items:%" PRIu64
             " _free_items_total:%" PRIu64 " fill: %f",
             _count,
             _free_items,
             _free_items_total,
             1 - (_free_items / (_free_items_total + .0)));
  }

  return true;
}

void __init_pheromones(np_state_t *context) {
  np_module_malloc(pheromones);
  np_module(pheromones)->context = context;

  char mutex_str[64];
  snprintf(mutex_str, 63, "%s:%p", "urn:np:pheromones:access", context);

  struct np_bloom_optable_s _op = {.add_cb   = _np_neuropil_bloom_add,
                                   .check_cb = _np_neuropil_bloom_check,
                                   .clear_cb = _np_neuropil_bloom_clear,
                                   .union_cb = _np_neuropil_bloom_union,
                                   .intersect_cb =
                                       _np_neuropil_bloom_intersect};
  np_module(pheromones)->_op    = _op;
  np_jobqueue_submit_event_periodic(context,
                                    NP_PRIORITY_LOWEST,
                                    0,
                                    60,
                                    __np_pheromones_periodic_log,
                                    "__np_pheromones_periodic_log");
}

int16_t
_np_pheromone_calc_table_position(np_dhkey_t                  target,
                                  enum np_pheromone_direction direction) {
  switch (direction) {
  case np_pheromone_direction_receiver:
    return -(target.t[0] % 257) - 1;
  case np_pheromone_direction_sender:
    return (target.t[0] % 257) + 1;
  default:
    ASSERT(false, "direction argument not known");
    break;
  }
}

bool _np_pheromone_inhale_target(np_state_t *context,
                                 np_dhkey_t  target,
                                 np_dhkey_t  pheromone_source,
                                 bool        find_sender,
                                 bool        find_receiver) {

  if (np_module_not_initiated(pheromones)) {
    __init_pheromones(context);
  }

  np_bloom_t *_scent = _np_neuropil_bloom_create();
  _np_neuropil_bloom_add(_scent, target);

  bool ret = find_sender | find_receiver;

  np_pheromone_t _pheromone = {0};
  _pheromone._subj_bloom    = _scent;

  if (find_sender) {
    _pheromone._receiver = pheromone_source;
    _pheromone._pos =
        _np_pheromone_calc_table_position(target,
                                          np_pheromone_direction_sender);
  }
  if (find_receiver) {
    _pheromone._sender = pheromone_source;
    _pheromone._pos =
        _np_pheromone_calc_table_position(target,
                                          np_pheromone_direction_receiver);
  }
  ret &= _np_pheromone_inhale(context, _pheromone);
  _np_bloom_free(_scent);
  return ret;
}

bool __np_remove_dhkey(NP_UNUSED np_state_t *context,
                       np_sll_t(void_ptr, list),
                       struct np_pheromone_details_s *value) {

  sll_iterator(void_ptr) iter       = sll_first(list);
  sll_iterator(void_ptr) remove_pos = NULL;

  while (iter != NULL) {
    struct np_pheromone_details_s *tmp = iter->val;
    if (_np_dhkey_equal(&tmp->peer_id, &value->peer_id)) {
      remove_pos = iter;
    }
    sll_next(iter);
  }

  if (remove_pos) {
    free(remove_pos->val);
    sll_delete(void_ptr, list, remove_pos);
    return true;
  }
  return false;
}

bool __np_remove_oldest_dhkey(NP_UNUSED np_state_t *context,
                              np_sll_t(void_ptr, list),
                              NP_UNUSED struct np_pheromone_details_s *value) {

  sll_iterator(void_ptr) iter       = sll_first(list);
  sll_iterator(void_ptr) remove_pos = sll_first(list);

  if (iter == NULL) return false;

  double compare_result =
      ((struct np_pheromone_details_s *)sll_first(list)->val)->insert_ts;

  while (iter != NULL) {
    struct np_pheromone_details_s *tmp = iter->val;
    if (tmp->insert_ts < compare_result) {
      remove_pos = iter;
    }
    sll_next(iter);
  }
  if (remove_pos) {
    free(remove_pos->val);
    sll_delete(void_ptr, list, remove_pos);
    return true;
  }
  return false;
}

bool __np_insert_dhkey(np_state_t *context,
                       np_sll_t(void_ptr, list),
                       struct np_pheromone_details_s *new_value) {
  np_dhkey_t current_distance = {0};
  np_dhkey_t new_distance     = {0};

  // _np_dhkey_hamming_distance(&new_distance,
  //                            &context->my_node_key->dhkey,
  //                            &new_value);
  _np_dhkey_distance(&new_distance,
                     &context->my_node_key->dhkey,
                     &new_value->peer_id);

  struct np_pheromone_details_s *new = NULL;
  sll_iterator(void_ptr) insert_pos  = NULL;
  sll_iterator(void_ptr) iter        = sll_first(list);
  int8_t compare_result              = 1;

  while (iter != NULL) {
    struct np_pheromone_details_s *tmp = iter->val;
    _np_dhkey_distance(&current_distance,
                       &context->my_node_key->dhkey,
                       &tmp->peer_id);
    compare_result = _np_dhkey_cmp(&new_distance, &current_distance);
    if (compare_result < 0) {
      // new distance is "nearer" in hash distance metrics
      insert_pos = iter;
      sll_next(iter);
    } else break;
  }

  if (compare_result != 0) {
    new = malloc(sizeof(*new));
    _np_dhkey_assign(&new->peer_id, &new_value->peer_id);
    new->insert_ts = np_time_now();
  }

  if (compare_result < 0) {
    sll_insert(void_ptr, list, new, insert_pos);
  }
  if (compare_result > 0) {
    sll_prepend(void_ptr, list, new);
  }
  return true;
}

bool _np_pheromone_inhale(np_state_t *context, np_pheromone_t pheromone) {
  if (np_module_not_initiated(pheromones)) {
    __init_pheromones(context);
  }
  // _np_pheromone_exhale(context);

  bool ret = false;

  if (pheromone._subject == NULL && pheromone._subj_bloom == NULL) {
    return false;
  }

  if (pheromone._subject != NULL) { // set the bloom filter bits to "max" if a
                                    // "complete" dhkey is given
    if (pheromone._subj_bloom == NULL) {
      pheromone._subj_bloom     = _np_neuropil_bloom_create();
      pheromone._subj_bloom->op = np_module(pheromones)->_op;
    } else {
      np_module(pheromones)->_op.clear_cb(pheromone._subj_bloom);
    }
    np_module(pheromones)
        ->_op.add_cb(pheromone._subj_bloom, *pheromone._subject);
  }

  ASSERT(pheromone._pos != 0, "invalid pheromone index value");

  uint16_t index = 256;
  if (pheromone._pos > 0) index = pheromone._pos - 1;
  if (pheromone._pos < 0) index = -pheromone._pos - 1;

  ASSERT(index >= 0 && index < 257, "pheromone index out of range");

  _LOCK_MODULE(np_pheromones_t) {
    bool update_filter = false;

    np_pheromone_entry_t *_entry = np_module(pheromones)->pheromones[index];
    if (_entry == NULL) {
      np_pheromone_entry_t *_new =
          (np_pheromone_entry_t *)calloc(1, sizeof(np_pheromone_entry_t));
      CHECK_MALLOC(_new);
      _new->_count                        = 1;
      _new->_pheromone[0]._subj_bloom     = _np_neuropil_bloom_create();
      _new->_pheromone[0]._subj_bloom->op = np_module(pheromones)->_op;
      log_debug_msg(LOG_PHEROMONE,
                    "added new pheromone_entry_t at index %3d:",
                    index);

      np_module(pheromones)->pheromones[index] = _entry = _new;
    }

    uint16_t i = 1;

    np_module(pheromones)->_op.clear_cb(_entry->_pheromone[0]._subj_bloom);
    while (i < _entry->_count) {
      if (_np_neuropil_bloom_intersect_test(_entry->_pheromone[i]._subj_bloom,
                                            pheromone._subj_bloom)) {
        float old_age =
            _np_neuropil_bloom_intersect_age(_entry->_pheromone[i]._subj_bloom,
                                             pheromone._subj_bloom);
        float new_age =
            _np_neuropil_bloom_intersect_age(pheromone._subj_bloom,
                                             _entry->_pheromone[i]._subj_bloom);

        np_dhkey_t _null = {0};

        if (pheromone._pos < 0 &&
            !_np_dhkey_equal(&pheromone._sender, &_null)) {
          struct np_pheromone_details_s tmp = {.peer_id = pheromone._sender};
          if (__np_remove_dhkey(context,
                                _entry->_pheromone[i]._send_list,
                                &tmp)) {
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
          }
          __np_insert_dhkey(context, _entry->_pheromone[i]._send_list, &tmp);
          update_filter = true;

          if (sll_size(_entry->_pheromone[i]._send_list) >
              NP_PHEROMONES_MAX_NEXTHOP_KEYS) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._send_list,
                                     &tmp);
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
            log_debug_msg(LOG_PHEROMONE, "removed tail from _send_list");
          }
          np_module(pheromones)
              ->_op.union_cb(_entry->_pheromone[i]._subj_bloom,
                             pheromone._subj_bloom);

          log_debug_msg(LOG_PHEROMONE,
                        "added send pheromone entry at index %3d:%2d --> %u "
                        "(%.3f/%.3f) -- > %d",
                        pheromone._pos,
                        index,
                        i,
                        old_age,
                        new_age,
                        sll_size(_entry->_pheromone[i]._send_list));
        }

        if (pheromone._pos > 0 &&
            !_np_dhkey_equal(&pheromone._receiver, &_null)) {
          struct np_pheromone_details_s tmp = {.peer_id = pheromone._receiver};
          if (__np_remove_dhkey(context,
                                _entry->_pheromone[i]._recv_list,
                                &tmp)) {
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
          }
          __np_insert_dhkey(context, _entry->_pheromone[i]._recv_list, &tmp);
          update_filter = true;

          if (sll_size(_entry->_pheromone[i]._recv_list) >
              NP_PHEROMONES_MAX_NEXTHOP_KEYS) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._recv_list,
                                     &tmp);
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
            log_debug_msg(LOG_PHEROMONE, "removed tail from _recv_list");
          }
          np_module(pheromones)
              ->_op.union_cb(_entry->_pheromone[i]._subj_bloom,
                             pheromone._subj_bloom);

          log_debug_msg(LOG_PHEROMONE,
                        "added recv pheromone entry at index %3d:%2d --> %u "
                        "(%.3f/%.3f) --> %d",
                        pheromone._pos,
                        index,
                        i,
                        old_age,
                        new_age,
                        sll_size(_entry->_pheromone[i]._recv_list));
        }
      } else {
        log_debug_msg(
            LOG_PHEROMONE,
            "intersect failed for pheromone at index %3d:%2d / %d --> %u",
            index,
            i,
            _entry->_pheromone[i]._subj_bloom->_free_items,
            _entry->_pheromone[0]._subj_bloom->_free_items);
      }

      // Assert ERROR: C 5 + 57 = 62
      ASSERT(_entry->_pheromone[0]._subj_bloom->_free_items +
                     _entry->_pheromone[i]._subj_bloom->_free_items >=
                 64,
             "C %" PRIu32 " + %" PRIu32 " = %" PRIu32,
             _entry->_pheromone[0]._subj_bloom->_free_items,
             _entry->_pheromone[i]._subj_bloom->_free_items,
             _entry->_pheromone[0]._subj_bloom->_free_items +
                 _entry->_pheromone[i]._subj_bloom->_free_items);
      // to update heuristic/age value
      np_module(pheromones)
          ->_op.union_cb(_entry->_pheromone[0]._subj_bloom,
                         _entry->_pheromone[i]._subj_bloom);
      // yes, this is ugly! on purpose:
      _entry->_pheromone[0]._subj_bloom->_free_items = 64;
      /*SCALE3D_FREE_ITEMS*/
      // update of a bloom filter at this stage would hit the free item
      // counter, which is unwanted. this counter is already in place at the
      // top level bloom filter. We do not need it here! Even if double
      // entries occur, the filter should still be intact because we have some
      // buffer probability left
      log_debug_msg(LOG_PHEROMONE,
                    "update 0-pheromone at index %3d:%2d / %d --> %u",
                    index,
                    i,
                    _entry->_pheromone[i]._subj_bloom->_free_items,
                    _entry->_pheromone[0]._subj_bloom->_free_items);

      i++;
    }

    // if (i >= 32) return update_filter;
    // sanity check for full filter
#ifdef DEBUG
    ASSERT(i > 0 && i < 32, "insertion index out of range. i: %" PRIu16, i);
#else
    if (!(i > 0 && i < 32)) {
      log_info(LOG_PHEROMONE, "insertion index out of range.");
      return false;
    }
#endif
    if (i == _entry->_count && !update_filter) {
      ASSERT((_entry->_pheromone[0]._subj_bloom->_free_items +
              pheromone._subj_bloom->_free_items) >= 64,
             "D");
      np_module(pheromones)
          ->_op.union_cb(_entry->_pheromone[0]._subj_bloom,
                         pheromone._subj_bloom);

      sll_init(void_ptr, _entry->_pheromone[i]._send_list);
      sll_init(void_ptr, _entry->_pheromone[i]._recv_list);

      if (pheromone._pos > 0) {
        struct np_pheromone_details_s tmp = {.peer_id = pheromone._receiver};
        __np_insert_dhkey(context, _entry->_pheromone[i]._recv_list, &tmp);
        log_debug_msg(LOG_PHEROMONE,
                      "added recv pheromone at index %3d:%2d / %d %p/%d",
                      index,
                      i,
                      pheromone._subj_bloom->_free_items,
                      pheromone._receiver,
                      sll_size(_entry->_pheromone[i]._recv_list));
      } else if (pheromone._pos < 0) {
        struct np_pheromone_details_s tmp = {.peer_id = pheromone._sender};
        __np_insert_dhkey(context, _entry->_pheromone[i]._send_list, &tmp);
        log_debug_msg(LOG_PHEROMONE,
                      "added send pheromone at index %3d:%2d / %d %p/%d",
                      index,
                      i,
                      pheromone._subj_bloom->_free_items,
                      pheromone._sender,
                      sll_size(_entry->_pheromone[i]._send_list));

      } else {
        ASSERT(pheromone._pos != 0, "_pos should never be 0.")
      }

      _entry->_pheromone[i]._subject    = pheromone._subject;
      _entry->_pheromone[i]._pos        = index;
      _entry->_pheromone[i]._subj_bloom = _np_neuropil_bloom_create();
      ASSERT(_entry->_pheromone[i]._subj_bloom->_free_items +
                     pheromone._subj_bloom->_free_items >=
                 64,
             "E");
      np_module(pheromones)
          ->_op.union_cb(_entry->_pheromone[i]._subj_bloom,
                         pheromone._subj_bloom);

      _entry->_count++;
      update_filter = true;
    }
    ret = (update_filter) ? true : false;
  }
  _np_statistics_increment_pheromones_inhale();
  return ret;
}

void _np_pheromone_snuffle(np_state_t *context,
                           sll_return(np_dhkey_t) result_list,
                           np_dhkey_t to_check,
                           float     *target_probability,
                           bool       find_sender,
                           bool       find_receiver) {
  if (np_module_not_initiated(pheromones)) {
    __init_pheromones(context);
  }

  uint16_t index = to_check.t[0] % 257;
  ASSERT(index >= 0 && index < 257, "pheromone index out of range");

  _LOCK_MODULE(np_pheromones_t) {
    np_pheromone_entry_t *_entry = np_module(pheromones)->pheromones[index];
    if (_entry != NULL &&
        np_module(pheromones)
            ->_op.check_cb(_entry->_pheromone[0]._subj_bloom, to_check)) {
      log_debug_msg(LOG_PHEROMONE,
                    "found potential pheromone at index %3" PRIu16 ":",
                    index);
      float new_probability =
          _np_neuropil_bloom_get_heuristic(_entry->_pheromone[0]._subj_bloom,
                                           to_check);

      if (*target_probability <= new_probability) {

        if (*target_probability < new_probability) {
          *target_probability = new_probability;
          log_debug_msg(LOG_PHEROMONE,
                        "target probability of pheromone set to: %f",
                        new_probability);
        }

        for (uint8_t i = 1; i < _entry->_count; i++) {
          if (np_module(pheromones)
                  ->_op.check_cb(_entry->_pheromone[i]._subj_bloom, to_check)) {
            sll_iterator(void_ptr) iter = NULL;
            if (find_sender) {
              iter = sll_first(_entry->_pheromone[i]._send_list);
            }
            if (find_receiver) {
              iter = sll_first(_entry->_pheromone[i]._recv_list);
            }
            while (iter != NULL) {
              struct np_pheromone_details_s *tmp = iter->val;
              sll_append(np_dhkey_t, result_list, tmp->peer_id);
              sll_next(iter);
            }
            log_debug_msg(LOG_PHEROMONE,
                          "added %" PRIsizet
                          " %s%s pheromones from index (%3" PRIu16 ":%2" PRIu8
                          ") to result list %p",
                          sll_size(result_list),
                          find_sender ? "send" : "",
                          find_receiver ? "recv" : "",
                          index,
                          i,
                          result_list);
          } else {
            log_debug_msg(LOG_PHEROMONE,
                          "checking next pheromone in set at index %3" PRIu16,
                          index);
          }
        }
      } else {
        log_debug_msg(LOG_PHEROMONE,
                      "target probability (%f) of pheromone not met, have: %f",
                      *target_probability,
                      new_probability);
      }
    } else {
      log_debug_msg(
          LOG_PHEROMONE,
          "target probability of pheromone set to: 0.0, index %3" PRIu16
          ": is empty",
          index);
      *target_probability = 0.0;
    }
  }
}

void _np_pheromone_snuffle_receiver(np_state_t *context,
                                    sll_return(np_dhkey_t) result_list,
                                    np_dhkey_t to_check,
                                    float     *target_probability) {
  _np_pheromone_snuffle(context,
                        result_list,
                        to_check,
                        target_probability,
                        false,
                        true);
}

void _np_pheromone_snuffle_sender(np_state_t *context,
                                  sll_return(np_dhkey_t) result_list,
                                  np_dhkey_t to_check,
                                  float     *target_probability) {
  _np_pheromone_snuffle(context,
                        result_list,
                        to_check,
                        target_probability,
                        true,
                        false);
}

void _np_pheromone_exhale(np_state_t *context) {
  if (np_module_not_initiated(pheromones)) {
    __init_pheromones(context);
  }

  uint32_t _random_number = 0;
  // shameless stolen from bind9 random() implementation
#if RAND_MAX >= 0xfffff
  /* We have at least 20 bits.  Use lower 16 excluding lower most 4 */
  _random_number = ((rand() >> 4) & 0xffff) | ((rand() << 12) & 0xffff0000);
#elif RAND_MAX >= 0x7fff
  /* We have at least 15 bits.  Use lower 10/11 excluding lower most 4 */
  _random_number = ((rand() >> 4) & 0x000007ff) | ((rand() << 7) & 0x003ff800) |
                   ((rand() << 18) & 0xffc00000);
#endif

  _LOCK_MODULE(np_pheromones_t) {
    np_pheromone_entry_t *_entry =
        np_module(pheromones)->pheromones[_random_number % 257];
    if (_entry != NULL) {
      // np_module(pheromones)->_op.clear_cb(_entry->_pheromone[0]._subj_bloom);
      _np_neuropil_bloom_age_decrement(_entry->_pheromone[0]._subj_bloom);

      uint8_t i = 1;
      while (i < _entry->_count) {
        _np_neuropil_bloom_age_decrement(_entry->_pheromone[i]._subj_bloom);

        float _age =
            _np_neuropil_bloom_intersect_age(_entry->_pheromone[0]._subj_bloom,
                                             _entry->_pheromone[i]._subj_bloom);
        log_debug_msg(LOG_PHEROMONE,
                      "decreased pheromone strength (index %3d:%2d) age now %f",
                      _random_number % 257,
                      i,
                      _age);

        if (_age == 0.0) {
          log_debug_msg(
              LOG_ERROR,
              "decreased pheromone strength (index %3d:%2d) age now %f",
              _random_number % 257,
              i,
              _age);

          while (sll_size(_entry->_pheromone[i]._recv_list) != 0) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._recv_list,
                                     NULL);
          }
          sll_free(void_ptr, _entry->_pheromone[i]._recv_list);

          while (sll_size(_entry->_pheromone[i]._send_list) != 0) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._send_list,
                                     NULL);
          }
          sll_free(void_ptr, _entry->_pheromone[i]._send_list);

          _np_bloom_free(_entry->_pheromone[i]._subj_bloom);

          // TODO: use memmove?
          uint8_t j = i;
          while (j < _entry->_count) {
            _entry->_pheromone[j] = _entry->_pheromone[j + 1];
            j++;
          }
          if (j < 32 /*count of possible _entry->_pheromone elements*/) {
            memset(&_entry->_pheromone[j], 0, sizeof(np_pheromone_t));
          }
          _entry->_count--;

          log_debug_msg(LOG_PHEROMONE,
                        "removed pheromone at index %3d:%2d)",
                        _random_number % 257,
                        i);
        } else {
          if (sll_size(_entry->_pheromone[i]._recv_list) > 1) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._recv_list,
                                     NULL);
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
          }
          if (sll_size(_entry->_pheromone[i]._send_list) > 1) {
            __np_remove_oldest_dhkey(context,
                                     _entry->_pheromone[i]._send_list,
                                     NULL);
            _np_neuropil_bloom_count_decrement(
                _entry->_pheromone[i]._subj_bloom);
          }

          log_debug_msg(LOG_PHEROMONE,
                        "decreased pheromone strength (index %3d:%2d) age "
                        "now %f --> %u",
                        _random_number % 257,
                        i,
                        _age,
                        _entry->_pheromone[i]._subj_bloom->_free_items);

          i++;
        }
      }
    }
  }
  _np_statistics_increment_pheromones_exhale();
}
