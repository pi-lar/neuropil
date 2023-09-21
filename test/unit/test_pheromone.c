//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "../test_macros.c"

#include "neuropil.h"

#include "np_key.h"
#include "np_pheromones.h"
#include "np_util.h"

TestSuite(np_pheromone_t);

Test(
    np_pheromone_t,
    _pheromone_set,
    .description = "test the functions to add a dhkey to the pheromone table") {
  np_dhkey_t _null = {0};
  CTX() {
    struct np_bloom_optable_s neuropil_operations = {
        .add_cb       = _np_neuropil_bloom_add,
        .check_cb     = _np_neuropil_bloom_check,
        .clear_cb     = _np_neuropil_bloom_clear,
        .union_cb     = _np_neuropil_bloom_union,
        .intersect_cb = _np_neuropil_bloom_intersect,
    };

    //  char test_string[65];
    np_dhkey_t test1 = np_dhkey_create_from_hostport("test_1", "0");
    //  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", "0");
    //  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    np_dhkey_t test3 = np_dhkey_create_from_hostport("test_3", "0");
    //  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    np_dhkey_t test4 = np_dhkey_create_from_hostport("test_4", "0");
    //  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    np_dhkey_t test5 = np_dhkey_create_from_hostport("test_5", "0");
    //  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);

    // add a full dhkey to our pheromone table
    np_pheromone_t t1  = {._subject    = &test1,
                          ._subj_bloom = NULL,
                          ._pos        = 0,
                          ._sender     = context->my_node_key->dhkey,
                          ._receiver   = _null};
    t1._subj_bloom     = _np_neuropil_bloom_create();
    t1._subj_bloom->op = neuropil_operations;
    t1._subj_bloom->op.add_cb(t1._subj_bloom, test1);
    t1._pos = -(test1.t[0] % 257) - 1;
    _np_pheromone_inhale(context, t1);

    // add only the dhkey scent to our pheromone table
    np_pheromone_t t2  = {._subject    = {0},
                          ._subj_bloom = NULL,
                          ._pos        = 0,
                          ._sender     = context->my_node_key->dhkey,
                          ._receiver   = _null};
    t2._subj_bloom     = _np_neuropil_bloom_create();
    t2._subj_bloom->op = neuropil_operations;
    t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
    t2._pos = -(test2.t[0] % 257) - 1;
    _np_pheromone_inhale(context, t2);

    // add only the dhkey scent to our pheromone table
    np_pheromone_t t3  = {._subject    = {0},
                          ._subj_bloom = NULL,
                          ._pos        = 0,
                          ._sender     = _null,
                          ._receiver   = context->my_node_key->dhkey};
    t3._subj_bloom     = _np_neuropil_bloom_create();
    t3._subj_bloom->op = neuropil_operations;
    t3._subj_bloom->op.add_cb(t3._subj_bloom, test3);
    t3._pos = (test3.t[0] % 257) + 1;

    // decrease the scent a bit before inserting
    _np_neuropil_bloom_age_decrement(t3._subj_bloom);
    _np_neuropil_bloom_age_decrement(t3._subj_bloom);

    _np_pheromone_inhale(context, t3);
    _np_pheromone_inhale(context, t3);

    float target_probability = 0.0;

    np_sll_t(np_dhkey_t, result_list) = NULL;
    sll_init(np_dhkey_t, result_list);

    // now we can sniff for the message scent in our pheromone table
    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test4,
                                 &target_probability);
    cr_expect(0 == sll_size(result_list),
              "expect the list result set to have no entry");
    cr_expect(0.0 == target_probability,
              "expect the probability to be           1.0");
    sll_clear(np_dhkey_t, result_list);

    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test1,
                                 &target_probability);
    cr_expect(1 == sll_size(result_list),
              "expect the list result set to have  1 entry");
    cr_expect(0.5 == target_probability, "expect the probability to be 0.5");
    sll_clear(np_dhkey_t, result_list);
    target_probability = 0.0;

    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test2,
                                 &target_probability);
    cr_expect(1 == sll_size(result_list),
              "expect the list result set to have  1 entry");
    cr_expect(0.5 == target_probability, "expect the probability to be 0.5");
    sll_clear(np_dhkey_t, result_list);
    target_probability = 0.0;

    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test3,
                                 &target_probability);
    cr_expect(0 == sll_size(result_list),
              "expect the list result set to have no entry");
    _np_pheromone_snuffle_receiver(context,
                                   result_list,
                                   test3,
                                   &target_probability);
    cr_expect(1 == sll_size(result_list),
              "expect the list result set to have  1 entry");
    cr_expect(0.5 > target_probability,
              "expect the probability to be less than 0.5");
    cr_expect(target_probability > 0.0,
              "expect the probability to be more than 0.0");
    sll_clear(np_dhkey_t, result_list);
    target_probability = 0.0;

    // forget about scents in our pheromone table
    for (uint16_t i = 0; i < 257; i++)
      _np_pheromone_exhale(context);

    // then sniff again, the scent trail has weakened
    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test1,
                                 &target_probability);
    cr_expect(1 == sll_size(result_list),
              "expect the list result set to have  1 entry");
    cr_expect(1.0 > target_probability,
              "expect the probability to be less than 1.0");
    cr_expect(target_probability > 0.0,
              "expect the probability to be more than 0.0");
    sll_clear(np_dhkey_t, result_list);
    target_probability = 0.0;

    _np_pheromone_snuffle_receiver(context,
                                   result_list,
                                   test1,
                                   &target_probability);
    cr_expect(0 == sll_size(result_list),
              "expect the list result set to have no entry");
    cr_expect(1.0 > target_probability,
              "expect the probability to be less than 1.0");
    cr_expect(target_probability > 0.0,
              "expect the probability to be more than 0.0");
    sll_clear(np_dhkey_t, result_list);

    target_probability = 0.0;
    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test3,
                                 &target_probability);
    cr_expect(0 == sll_size(result_list),
              "expect the list result set to have no entry");
    _np_pheromone_snuffle_receiver(context,
                                   result_list,
                                   test3,
                                   &target_probability);
    cr_expect(1 == sll_size(result_list),
              "expect the list result set to have  1 entry");
    cr_expect(0.8 > target_probability,
              "expect the probability to be less than 0.8");
    cr_expect(target_probability > 0.0,
              "expect the probability to be more than 0.0");
    sll_clear(np_dhkey_t, result_list);

    target_probability = 0.0;
    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test2,
                                 &target_probability);
    sll_clear(np_dhkey_t, result_list);
    float old_target = target_probability;
    fprintf(stdout, "%f\n", old_target);

    t2._pos          = -t2._pos;
    np_dhkey_t _null = {0};
    _np_dhkey_assign(&t2._sender, &_null);
    t2._receiver = context->my_node_key->dhkey;

    _np_neuropil_bloom_age_decrement(t2._subj_bloom);
    _np_pheromone_inhale(context, t2);

    _np_pheromone_snuffle_receiver(context,
                                   result_list,
                                   test2,
                                   &target_probability);
    cr_expect(old_target < target_probability,
              "expect the probability to be higher than before");
    fprintf(stdout, "%f\n", target_probability);

    _np_pheromone_snuffle_sender(context,
                                 result_list,
                                 test2,
                                 &target_probability);
    cr_expect(old_target < target_probability,
              "expect the probability to be higher than before");
    fprintf(stdout, "%f\n", target_probability);
  }
}

Test(np_pheromone_t,
     _pheromone_exhale,
     .description =
         "test the functions to exhale a dhkey from the pheromone table") {
  np_dhkey_t _null = {0};
  CTX() {
    struct np_bloom_optable_s neuropil_operations = {
        .add_cb       = _np_neuropil_bloom_add,
        .check_cb     = _np_neuropil_bloom_check,
        .clear_cb     = _np_neuropil_bloom_clear,
        .union_cb     = _np_neuropil_bloom_union,
        .intersect_cb = _np_neuropil_bloom_intersect,
    };

    log_debug(LOG_INFO, "--- pheromone exhale test part 1 ---");
    for (uint16_t i = 0; i < 512; i++) {
      char *random_bytes[32];
      randombytes_buf(random_bytes, 32);

      np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", random_bytes);
      // add only the dhkey scent to our pheromone table
      np_pheromone_t t2  = {._subject    = {0},
                            ._subj_bloom = NULL,
                            ._pos        = 0,
                            ._sender     = test2,
                            ._receiver   = _null};
      t2._subj_bloom     = _np_neuropil_bloom_create();
      t2._subj_bloom->op = neuropil_operations;
      t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
      t2._pos = -(test2.t[0] % 257) - 1;

      // cr_expect(true == _np_pheromone_inhale(context, t2), "expect that the
      // new item could be inserted into the pheromone table");
      cr_expect(true == _np_pheromone_inhale(context, t2),
                "expect that the new item could be inserted into the pheromone "
                "table");

      _np_bloom_free(t2._subj_bloom);

      for (uint16_t j = 0; j < 6; j++)
        _np_pheromone_exhale(context);
    }

    log_debug(LOG_INFO, "--- pheromone exhale test part 2 ---");
    for (uint16_t j = 0; j < 32768; j++)
      _np_pheromone_exhale(context);

    log_debug(LOG_INFO, "--- pheromone exhale test part 3 ---");
    for (uint16_t i = 0; i < 32768; i++) {
      char *random_bytes[32];
      randombytes_buf(random_bytes, 32);

      np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", random_bytes);
      // add only the dhkey scent to our pheromone table
      np_pheromone_t t2  = {._subject    = {0},
                            ._subj_bloom = NULL,
                            ._pos        = 0,
                            ._sender     = test2,
                            ._receiver   = _null};
      t2._subj_bloom     = _np_neuropil_bloom_create();
      t2._subj_bloom->op = neuropil_operations;
      t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
      t2._pos = -(test2.t[0] % 257) - 1;

      // cr_expect(true == _np_pheromone_inhale(context, t2), "expect that the
      // new item could be inserted into the pheromone table");
      if (false == _np_pheromone_inhale(context, t2))
        log_debug(LOG_INFO,
                  "expected that the new item could be inserted into the "
                  "pheromone table");

      _np_bloom_free(t2._subj_bloom);

      for (uint16_t j = 0; j < 6; j++)
        _np_pheromone_exhale(context);
    }
  }
}

Test(np_pheromone_t,
     _pheromone_sendrecv,
     .description =
         "test the functions to add sender and receiver dhkey to the pheromone "
         "table") {
  np_dhkey_t _null = {0};
  CTX() {
    struct np_bloom_optable_s neuropil_operations = {
        .add_cb       = _np_neuropil_bloom_add,
        .check_cb     = _np_neuropil_bloom_check,
        .clear_cb     = _np_neuropil_bloom_clear,
        .union_cb     = _np_neuropil_bloom_union,
        .intersect_cb = _np_neuropil_bloom_intersect,
    };

    char *random_bytes[32];
    randombytes_buf(random_bytes, 32);

    for (uint16_t i = 0; i < 512; i++) {
      np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", random_bytes);
      // add only the dhkey scent to our pheromone table
      np_pheromone_t t2  = {._subject    = {0},
                            ._subj_bloom = NULL,
                            ._pos        = 0,
                            ._sender     = test2,
                            ._receiver   = _null};
      t2._subj_bloom     = _np_neuropil_bloom_create();
      t2._subj_bloom->op = neuropil_operations;
      t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
      t2._pos = -(test2.t[0] % 257) - 1;

      cr_expect(true == _np_pheromone_inhale(context, t2),
                "expect that the new item could be inserted into the pheromone "
                "table");

      _np_bloom_free(t2._subj_bloom);

      np_pheromone_t t3  = {._subject    = {0},
                            ._subj_bloom = NULL,
                            ._pos        = 0,
                            ._sender     = _null,
                            ._receiver   = test2};
      t3._subj_bloom     = _np_neuropil_bloom_create();
      t3._subj_bloom->op = neuropil_operations;
      t3._subj_bloom->op.add_cb(t3._subj_bloom, test2);
      t3._pos = (test2.t[0] % 257) + 1;

      cr_expect(true == _np_pheromone_inhale(context, t3),
                "expect that the new item could be inserted into the pheromone "
                "table");

      _np_bloom_free(t3._subj_bloom);

      for (uint16_t j = 0; j < 6; j++)
        _np_pheromone_exhale(context);
    }
  }
}

/**
 * @brief test the pheromone table to hold a minimum count of different
 * subjects.
 *         1. Add random dhkey as sender or receiver, or both to pheromone
 * table. 1.2. Exhale a few times for each added dhkey
 *         2. Check if dhkeys still can be 'found' in pheromone table.
 */
Test(np_pheromone_t,
     _pheromone_minimum_subject_capacity,
     .description =
         "test the pheromone table to hold a minimum count of different "
         "subjects") {
  uint32_t _capacity_selector[] = {1250};
  uint32_t _exhale_selector[]   = {
      // 0,1,2,3,4,5,6,7,8,10//,15,20,30,40,//200,300,400
      1};

  CTX() {
    for (uint32_t exhale_selector = 0;
         exhale_selector < ARRAY_SIZE(_exhale_selector);
         exhale_selector++) {
      for (uint32_t capacity_selector = 0;
           capacity_selector < ARRAY_SIZE(_capacity_selector);
           capacity_selector++) {

        uint32_t minimim_capacity = _capacity_selector[capacity_selector];

        uint32_t   exhale           = 0;
        char      *random_bytes[32] = {0};
        char       tmp_dhkey_s[65]  = {0};
        np_dhkey_t subject[minimim_capacity];

        uint32_t i = 0;
        while (i < minimim_capacity) {
          randombytes_buf(random_bytes, 31);
          // generate a random subject
          np_dhkey_t current_subject = subject[i] =
              np_dhkey_create_from_hostport("test_2", random_bytes);

          // add only the dhkey scent to our pheromone table
          // add scent as receiver
          if (i % 2 == 0) {
            cr_assert(true == _np_pheromone_inhale_target(context,
                                                          current_subject,
                                                          current_subject,
                                                          false,
                                                          true),
                      "expect that the new item could be inserted into the "
                      "pheromone table. reached capacity at %" PRIu32,
                      i);

            /* if( i % 3 == 0) {
                 cr_assert(true == _np_pheromone_inhale_target(context,
             current_subject, current_subject, true, false), "expect that the
             new item could be inserted into the pheromone table. reached
             capacity at %"PRIu32,i
                 );
             }*/
          } else {
            cr_assert(true == _np_pheromone_inhale_target(context,
                                                          current_subject,
                                                          current_subject,
                                                          true,
                                                          false),
                      "expect that the new item could be inserted into the "
                      "pheromone table. reached capacity at %" PRIu32,
                      i);
          }

          for (uint32_t j = 0;
               j < _exhale_selector[exhale_selector] -
                       1 /*currently we exhale one time on inhale*/;
               j++) {
            _np_pheromone_exhale(context);
            exhale++;
          }

          i++;
        }

        float target_probability  = .2;
        np_sll_t(np_dhkey_t, tmp) = NULL;
        np_dhkey_t tmp_dhkey;
        uint32_t   ok_entries   = 0;
        uint32_t   fail_entries = 0;

        for (i = 0; i < minimim_capacity; i++) {
          np_dhkey_t tmp_dhkey = subject[i];
          _np_dhkey_str(&tmp_dhkey, tmp_dhkey_s);

          float tp1 = target_probability, tp2 = target_probability;

          bool has_receiver = false, has_sender = false;

          sll_init(np_dhkey_t, tmp);
          _np_pheromone_snuffle_receiver(context, tmp, tmp_dhkey, &tp1);
          has_receiver = sll_size(tmp) >= 1;
          sll_free(np_dhkey_t, tmp);

          sll_init(np_dhkey_t, tmp);
          _np_pheromone_snuffle_sender(context, tmp, tmp_dhkey, &tp2);
          has_sender = sll_size(tmp) >= 1;
          sll_free(np_dhkey_t, tmp);

          if ((i % 2 == 0 && has_sender) || (i % 2 != 0 && has_receiver))
            ok_entries++;
          else fail_entries++;
        }
        double ok_percentage = ok_entries / (.0 + minimim_capacity);
        // cr_log(CR_LOG_WARNING ,

        /*
        fprintf(stdout,"Pheromonetable info correct matches: %6.2f%% capacity:
        %9"PRIu32" exhaled %9"PRIu32" times (factor: %5"PRIu32") ok_entries:
        %9"PRIu32" fail_entries: %9"PRIu32"\n", ok_percentage*100,
        minimim_capacity, exhale, _exhale_selector[exhale_selector], ok_entries,
        fail_entries
        );
        */
        cr_expect(ok_percentage >= .99,
                  "Pheromonetable cannot handle capacity. correct matches: "
                  "%6.2f%% exhaled %9" PRIu32 " times ok_entries: %9" PRIu32
                  " fail_entries: %9" PRIu32 " total: %9" PRIu32 "\n",
                  ok_percentage * 100,
                  exhale,
                  ok_entries,
                  fail_entries,
                  ok_entries + fail_entries);
      }
    }
  }
}