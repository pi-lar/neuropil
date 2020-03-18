//                                                                                                                          
// neuropil is copyright 2016-2019 by pi-lar GmbH                                                                          
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details                           
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "neuropil.h"
#include "np_key.h"
#include "np_pheromones.h"
#include "np_util.h"

#include "../test_macros.c"

TestSuite(np_pheromone_t);

Test(np_pheromone_t, _pheromone_set, .description="test the functions to add a dhkey to the pheromone table")
{
	CTX() 
    {
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
        np_pheromone_t t1 = { ._subject = &test1,
                              ._subj_bloom = NULL,
                              ._pos = 0,
                              ._sender=context->my_node_key->dhkey, 
                              ._receiver=NULL,
                              ._attr_bloom={0} };
        t1._subj_bloom = _np_neuropil_bloom_create();
        t1._subj_bloom->op = neuropil_operations;
        t1._subj_bloom->op.add_cb(t1._subj_bloom, test1);
        t1._pos = -(test1.t[0] % 257)-1;
        _np_pheromone_inhale(context, t1);

        // add only the dhkey scent to our pheromone table
        np_pheromone_t t2 = { ._subject = {0},
                              ._subj_bloom = NULL,
                              ._pos = 0,
                              ._sender=context->my_node_key->dhkey, 
                              ._receiver=NULL,
                              ._attr_bloom={0} };
        t2._subj_bloom = _np_neuropil_bloom_create();
        t2._subj_bloom->op = neuropil_operations;
        t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
        t2._pos = -(test2.t[0] % 257)-1;
        _np_pheromone_inhale(context, t2);

        // add only the dhkey scent to our pheromone table
        np_pheromone_t t3 = { ._subject = {0},
                              ._subj_bloom = NULL,
                              ._pos = 0,
                              ._sender=NULL,
                              ._receiver=context->my_node_key->dhkey,
                              ._attr_bloom={0} };
        t3._subj_bloom = _np_neuropil_bloom_create();
        t3._subj_bloom->op = neuropil_operations;
        t3._subj_bloom->op.add_cb(t3._subj_bloom, test3);
        t3._pos = (test3.t[0] % 257)+1;

        // decrease the scent a bit before inserting
        _np_neuropil_bloom_age_decrement(t3._subj_bloom);
        _np_neuropil_bloom_age_decrement(t3._subj_bloom);

        _np_pheromone_inhale(context, t3);
        _np_pheromone_inhale(context, t3);

        float target_probability = 0.0;

        np_sll_t(np_dhkey_t, result_list) = NULL;
        sll_init(np_dhkey_t, result_list);

        // now we can sniff for the message scent in our pheromone table
        _np_pheromone_snuffle_sender(context, result_list, test4, &target_probability);
        cr_expect(0 == sll_size(result_list), "expect the list result set to have no entry");
        cr_expect(0.0 == target_probability, "expect the probability to be           1.0");
        sll_clear(np_dhkey_t, result_list);

        _np_pheromone_snuffle_sender(context, result_list, test1, &target_probability);
        cr_expect(1 == sll_size(result_list), "expect the list result set to have  1 entry");
        cr_expect(0.5 == target_probability, "expect the probability to be 0.5");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        _np_pheromone_snuffle_sender(context, result_list, test2, &target_probability);
        cr_expect(1 == sll_size(result_list), "expect the list result set to have  1 entry");
        cr_expect(0.5 == target_probability, "expect the probability to be 0.5");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        _np_pheromone_snuffle_sender(context, result_list, test3, &target_probability);
        cr_expect(0 == sll_size(result_list), "expect the list result set to have no entry");
        _np_pheromone_snuffle_receiver(context, result_list, test3, &target_probability);
        cr_expect(1 == sll_size(result_list), "expect the list result set to have  1 entry");
        cr_expect(0.5 > target_probability, "expect the probability to be less than 0.5");
        cr_expect(target_probability > 0.0, "expect the probability to be more than 0.0");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        // forget about scents in our pheromone table
        for (uint16_t i = 0; i < 257; i++) _np_pheromone_exhale(context);

        // then sniff again, the scent trail has weakened 
        _np_pheromone_snuffle_sender(context, result_list, test1, &target_probability);
        cr_expect(1 == sll_size(result_list), "expect the list result set to have  1 entry");
        cr_expect(1.0 >  target_probability, "expect the probability to be less than 1.0");
        cr_expect(target_probability > 0.0, "expect the probability to be more than 0.0");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        _np_pheromone_snuffle_receiver(context, result_list, test1, &target_probability);
        cr_expect(0 == sll_size(result_list), "expect the list result set to have no entry");
        cr_expect(1.0 >  target_probability, "expect the probability to be less than 1.0");
        cr_expect(target_probability > 0.0, "expect the probability to be more than 0.0");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        _np_pheromone_snuffle_sender(context, result_list, test3, &target_probability);
        cr_expect(0 == sll_size(result_list), "expect the list result set to have no entry");
        _np_pheromone_snuffle_receiver(context, result_list, test3, &target_probability);
        cr_expect(1 == sll_size(result_list), "expect the list result set to have  1 entry");
        cr_expect(0.8 > target_probability, "expect the probability to be less than 0.8");
        cr_expect(target_probability > 0.0, "expect the probability to be more than 0.0");
        sll_clear(np_dhkey_t, result_list);
        target_probability = 0.0;

        _np_pheromone_snuffle_sender(context, result_list, test2, &target_probability);
        sll_clear(np_dhkey_t, result_list);
        float old_target = target_probability;
        // fprintf(stdout, "%f\n", old_target);
        t2._pos = -t2._pos;
        np_dhkey_t _null = {0};
        _np_dhkey_assign(&t2._sender, &_null); 
        t2._receiver=context->my_node_key->dhkey;

        _np_neuropil_bloom_age_decrement(t2._subj_bloom);
        _np_pheromone_inhale(context, t2);

        _np_pheromone_snuffle_receiver(context, result_list, test2, &target_probability);
        cr_expect(old_target < target_probability, "expect the probability to be higher than before");
        // fprintf(stdout, "%f\n", target_probability);
        _np_pheromone_snuffle_sender(context, result_list, test2, &target_probability);
        cr_expect(old_target < target_probability, "expect the probability to be higher than before");
        // fprintf(stdout, "%f\n", target_probability);

    }
}


Test(np_pheromone_t, _pheromone_exhale, .description="test the functions to exhale a dhkey from the pheromone table")
{
	CTX() 
    {
        struct np_bloom_optable_s neuropil_operations = {
            .add_cb       = _np_neuropil_bloom_add,
            .check_cb     = _np_neuropil_bloom_check,
            .clear_cb     = _np_neuropil_bloom_clear,
            .union_cb     = _np_neuropil_bloom_union,
            .intersect_cb = _np_neuropil_bloom_intersect,
        };

        log_debug(LOG_INFO, "--- pheromone exhale test part 1 ---");
        for (uint16_t i = 0; i < 512; i++) 
        {
            char* random_bytes[32];
            randombytes_buf(random_bytes, 32);

            np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", random_bytes);
            // add only the dhkey scent to our pheromone table
            np_pheromone_t t2 = { ._subject = {0},
                                  ._subj_bloom = NULL,
                                  ._pos = 0,
                                  ._sender=test2, 
                                  ._receiver=NULL,
                                  ._attr_bloom={0} };
            t2._subj_bloom = _np_neuropil_bloom_create();
            t2._subj_bloom->op = neuropil_operations;
            t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
            t2._pos = -(test2.t[0] % 257)-1;

            // cr_expect(true == _np_pheromone_inhale(context, t2), "expect that the new item could be inserted into the pheromone table");
            cr_expect(true == _np_pheromone_inhale(context, t2), "expect that the new item could be inserted into the pheromone table");

            _np_bloom_free(t2._subj_bloom);

            for (uint16_t j = 0; j < 6; j++) 
                _np_pheromone_exhale(context);
        }

        log_debug(LOG_INFO, "--- pheromone exhale test part 2 ---");
        for (uint16_t j = 0; j < 8192; j++) 
            _np_pheromone_exhale(context);

        log_debug(LOG_INFO, "--- pheromone exhale test part 3 ---");
        for (uint16_t i = 0; i < 8192; i++) 
        {
            char* random_bytes[32];
            randombytes_buf(random_bytes, 32);

            np_dhkey_t test2 = np_dhkey_create_from_hostport("test_2", random_bytes);
            // add only the dhkey scent to our pheromone table
            np_pheromone_t t2 = { ._subject = {0},
                                  ._subj_bloom = NULL,
                                  ._pos = 0,
                                  ._sender=test2, 
                                  ._receiver=NULL,
                                  ._attr_bloom={0} };
            t2._subj_bloom = _np_neuropil_bloom_create();
            t2._subj_bloom->op = neuropil_operations;
            t2._subj_bloom->op.add_cb(t2._subj_bloom, test2);
            t2._pos = -(test2.t[0] % 257)-1;

            // cr_expect(true == _np_pheromone_inhale(context, t2), "expect that the new item could be inserted into the pheromone table");
            if (false == _np_pheromone_inhale(context, t2))
                log_debug(LOG_INFO, "expected that the new item could be inserted into the pheromone table");

            _np_bloom_free(t2._subj_bloom);

            for (uint16_t j = 0; j < 6; j++) 
                _np_pheromone_exhale(context);
        }

    }
}