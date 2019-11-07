//                                                                                                                          
// neuropil is copyright 2016-2019 by pi-lar GmbH                                                                          
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details                           
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "neuropil.h"
#include "np_bloom.h"
#include "np_util.h"

#include "../test_macros.c"

TestSuite(np_bloom_t);

Test(np_bloom_t, _bloom_standard, .description="test the functions of the standard bloom filter")
{
    
    np_id test1, test2, test3, test4, test5;
//    char test_string[65];
    
    np_get_id(&test1, "test_1", 6);
//    np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test2, "test_2", 6);
//    np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test3, "test_3", 6);
//    np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test4, "test_4", 6);
//    np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test5, "test_5", 6);
//    np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);
    
    
    struct np_bloom_optable_s std_operations = {
        .add_cb       = _np_standard_bloom_add,
        .check_cb     = _np_standard_bloom_check,
        .clear_cb     = NULL,
        .union_cb     = NULL,
        .intersect_cb = NULL,
    };
    
//    fprintf(stdout, "###\n");
//    fprintf(stdout, "### Testing standard bloom filter now\n");
//    fprintf(stdout, "###\n");
    
    np_bloom_t* std_bloom = _np_standard_bloom_create(256);
    std_bloom->op = std_operations;
    
    std_bloom->op.add_cb(std_bloom, test1);
    std_bloom->op.add_cb(std_bloom, test2);
    std_bloom->op.add_cb(std_bloom, test3);
    
    cr_expect(true  == std_bloom->op.check_cb(std_bloom, test2), "expect that the id test2 is     found in bloom filter");
    cr_expect(false == std_bloom->op.check_cb(std_bloom, test4), "expect that the id test4 is not found in bloom filter");
    cr_expect(false == std_bloom->op.check_cb(std_bloom, test5), "expect that the id test5 is not found in bloom filter");
    
    _np_bloom_free(std_bloom);
}

Test(np_bloom_t, _bloom_stable, .description="test the functions of the stable bloom filter") {
    
    np_id test1, test2, test3, test4, test5;
//    char test_string[65];
    
    np_get_id(&test1, "test_1", 6);
//    np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test2, "test_2", 6);
//    np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test3, "test_3", 6);
//    np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test4, "test_4", 6);
//    np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test5, "test_5", 6);
//    np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);
    
    struct np_bloom_optable_s stable_operations = {
        .add_cb       = _np_stable_bloom_add,
        .check_cb     = _np_stable_bloom_check,
        .clear_cb     = NULL,
        .union_cb     = NULL,
        .intersect_cb = NULL,
    };
    
//    fprintf(stdout, "###\n");
//    fprintf(stdout, "### Testing stable bloom filter now\n");
//    fprintf(stdout, "###\n");
    
    np_bloom_t* stable_bloom = _np_stable_bloom_create(1024, 8, 16);
    stable_bloom->op = stable_operations;
    
    stable_bloom->op.add_cb(stable_bloom, test1);
    stable_bloom->op.add_cb(stable_bloom, test2);
    stable_bloom->op.add_cb(stable_bloom, test3);
    
    cr_expect(true  == stable_bloom->op.check_cb(stable_bloom, test1), "expect that the id test1 is     found in bloom filter");
    cr_expect(true  == stable_bloom->op.check_cb(stable_bloom, test2), "expect that the id test2 is     found in bloom filter");
    cr_expect(false == stable_bloom->op.check_cb(stable_bloom, test4), "expect that the id test4 is not found in bloom filter");
    cr_expect(false == stable_bloom->op.check_cb(stable_bloom, test5), "expect that the id test5 is not found in bloom filter");
    
    for (uint16_t i = 0; i < 100; i++) {
        
        np_get_id(&test4, np_uuid_create("test", i, NULL), 36);
//        np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
        
        cr_expect(false == stable_bloom->op.check_cb(stable_bloom, test4), "expect that the new element is not found");
        if (i%4)
            cr_expect(true  == stable_bloom->op.check_cb(stable_bloom, test2), "expect that the id test2 is     found in bloom filter");
    }
    _np_bloom_free(stable_bloom);
}

Test(np_bloom_t, _bloom_scalable, .description="test the functions of the scalable bloom filter") {
    
    np_id test1, test2, test3, test4, test5;
//    char test_string[65];
    
    np_get_id(&test1, "test_1", 6);
//    np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test2, "test_2", 6);
//    np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test3, "test_3", 6);
//    np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test4, "test_4", 6);
//    np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test5, "test_5", 6);
//    np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);
    
    struct np_bloom_optable_s scale_operations = {
        .add_cb       = _np_scalable_bloom_add,
        .check_cb     = _np_scalable_bloom_check,
        .clear_cb     = NULL,
        .union_cb     = NULL,
        .intersect_cb = NULL,
    };
    
//    fprintf(stdout, "###\n");
//    fprintf(stdout, "### Testing scalable bloom filter now\n");
//    fprintf(stdout, "###\n");
    
    np_bloom_t* scale_bloom = _np_scalable_bloom_create(256);
    scale_bloom->op = scale_operations;
    
    scale_bloom->op.add_cb(scale_bloom, test1);
    scale_bloom->op.add_cb(scale_bloom, test2);
    scale_bloom->op.add_cb(scale_bloom, test3);
    
    cr_expect(true  == scale_bloom->op.check_cb(scale_bloom, test1), "expect that the id test1 is     found in bloom filter");
    cr_expect(true  == scale_bloom->op.check_cb(scale_bloom, test2), "expect that the id test2 is     found in bloom filter");
    cr_expect(false == scale_bloom->op.check_cb(scale_bloom, test4), "expect that the id test4 is not found in bloom filter");
    cr_expect(false == scale_bloom->op.check_cb(scale_bloom, test5), "expect that the id test5 is not found in bloom filter");
    
    np_id test;
    
    for (uint16_t i = 0; i < 100; i++) {
        
        if (i%3) np_get_id(&test3, np_uuid_create("test", i, NULL), 36), memcpy(test, test3, 32);
        else if (i%5) np_get_id(&test4, np_uuid_create("test", i, NULL), 36), memcpy(test, test4, 32);
        else if (i%7) np_get_id(&test5, np_uuid_create("test", i, NULL), 36), memcpy(test, test5, 32);
        
//        np_id_str(test_string, test); fprintf(stdout, "%s\n", test_string);
        cr_expect(false == scale_bloom->op.check_cb(scale_bloom, test), "expect that the new element is not found");
        scale_bloom->op.add_cb(scale_bloom, test);
        cr_expect(true  == scale_bloom->op.check_cb(scale_bloom, test), "expect that the new element is     found in bloom filter after insert");
    }
    _np_bloom_free(scale_bloom);
}

Test(np_bloom_t, _bloom_decaying, .description="test the functions of the decaying bloom filter")
{
    
    np_id test1, test2, test3, test4, test5;
//    char test_string[65];
    
    np_get_id(&test1, "test_1", 6);
//    np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test2, "test_2", 6);
//    np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test3, "test_3", 6);
//    np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test4, "test_4", 6);
//    np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test5, "test_5", 6);
//    np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);
    
    
    struct np_bloom_optable_s decay_operations = {
        .add_cb       = _np_decaying_bloom_add,
        .check_cb     = _np_decaying_bloom_check,
        .clear_cb     = NULL,
        .union_cb     = NULL,
        .intersect_cb = NULL,
    };
    
//    fprintf(stdout, "###\n");
//    fprintf(stdout, "### Testing decaying bloom filter now\n");
//    fprintf(stdout, "###\n");
    
    np_bloom_t* decaying_bloom = _np_decaying_bloom_create(256, 8, 1);
    decaying_bloom->op = decay_operations;
    
    decaying_bloom->op.add_cb(decaying_bloom, test1);
    decaying_bloom->op.add_cb(decaying_bloom, test2);
    decaying_bloom->op.add_cb(decaying_bloom, test3);
    
    cr_expect(true  == decaying_bloom->op.check_cb(decaying_bloom, test2), "expect that the id test2 is     found in bloom filter");
    cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4), "expect that the id test4 is not found in bloom filter");
    cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5), "expect that the id test5 is not found in bloom filter");

    for (uint8_t i = 0; i < 10; i++) {

        _np_decaying_bloom_decay(decaying_bloom);
 
        if (i < 4) {
//            fprintf(stdout, "%f\n", _np_decaying_bloom_get_heuristic(decaying_bloom, test1));
            cr_expect( 0.5 <= _np_decaying_bloom_get_heuristic(decaying_bloom, test1), "checking the probability that a np_id has been found");
        } else {
//            fprintf(stdout, "%f\n", _np_decaying_bloom_get_heuristic(decaying_bloom, test1));
            cr_expect( 0.5 > _np_decaying_bloom_get_heuristic(decaying_bloom, test1), "checking the probability that a np_id has been found");
        }
        
        if (i < 7) {
            cr_expect(true  == decaying_bloom->op.check_cb(decaying_bloom, test2), "expect that the id test2 is     found in bloom filter");
            cr_expect(true  == decaying_bloom->op.check_cb(decaying_bloom, test1), "expect that the id test1 is     found in bloom filter");
            cr_expect(true  == decaying_bloom->op.check_cb(decaying_bloom, test3), "expect that the id test3 is     found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4), "expect that the id test4 is not found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5), "expect that the id test5 is not found in bloom filter");
            
        } else {
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test2), "expect that the id test2 is     found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test1), "expect that the id test1 is     found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test3), "expect that the id test3 is     found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test4), "expect that the id test4 is not found in bloom filter");
            cr_expect(false == decaying_bloom->op.check_cb(decaying_bloom, test5), "expect that the id test5 is not found in bloom filter");
        }
    }
    _np_bloom_free(decaying_bloom);
}

Test(np_bloom_t, _bloom_neuropil, .description="test the functions of the neuropil bloom filter")
{
    np_id test1, test2, test3, test4, test5;
//  char test_string[65];
    
    np_get_id(&test1, "test_1", 6);
//  np_id_str(test_string, test1); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test2, "test_2", 6);
//  np_id_str(test_string, test2); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test3, "test_3", 6);
//  np_id_str(test_string, test3); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test4, "test_4", 6);
//  np_id_str(test_string, test4); fprintf(stdout, "%s\n", test_string);
    
    np_get_id(&test5, "test_5", 6);
//  np_id_str(test_string, test5); fprintf(stdout, "%s\n", test_string);
    
    struct np_bloom_optable_s neuropil_operations = {
        .add_cb       = _np_neuropil_bloom_add,
        .check_cb     = _np_neuropil_bloom_check,
        .clear_cb     = NULL,
        .union_cb     = NULL,
        .intersect_cb = NULL,
    };
    
//    fprintf(stdout, "###\n");
//    fprintf(stdout, "### Testing neuropil bloom filter now\n");
//    fprintf(stdout, "###\n");
    
    np_bloom_t* neuropil_bloom = _np_neuropil_bloom_create();
    neuropil_bloom->op = neuropil_operations;
    
    neuropil_bloom->op.add_cb(neuropil_bloom, test1);
    neuropil_bloom->op.add_cb(neuropil_bloom, test2);
    neuropil_bloom->op.add_cb(neuropil_bloom, test3);
    
    cr_expect(true  == neuropil_bloom->op.check_cb(neuropil_bloom, test2), "expect that the id test2 is     found in bloom filter");
    cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4), "expect that the id test4 is not found in bloom filter");
    cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5), "expect that the id test5 is not found in bloom filter");

    for (uint8_t i = 0; i < 10; i++) {

        // fprintf(stdout, "%f\n", _np_neuropil_bloom_get_heuristic(neuropil_bloom, test1));
        _np_neuropil_bloom_age_decrement(neuropil_bloom);
 
        if (i < 4) {
            cr_expect( 0.5 <= _np_neuropil_bloom_get_heuristic(neuropil_bloom, test1), "checking the probability that a np_id has been found");
        } else {
            cr_expect( 0.5 > _np_neuropil_bloom_get_heuristic(neuropil_bloom, test1), "checking the probability that a np_id has been found");
        }
        
        if (i < 7) {
            cr_expect(true  == neuropil_bloom->op.check_cb(neuropil_bloom, test2), "expect that the id test2 is     found in bloom filter");
            cr_expect(true  == neuropil_bloom->op.check_cb(neuropil_bloom, test1), "expect that the id test1 is     found in bloom filter");
            cr_expect(true  == neuropil_bloom->op.check_cb(neuropil_bloom, test3), "expect that the id test3 is     found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4), "expect that the id test4 is not found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5), "expect that the id test5 is not found in bloom filter");
            
        } else {
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test2), "expect that the id test2 is     found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test1), "expect that the id test1 is     found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test3), "expect that the id test3 is     found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test4), "expect that the id test4 is not found in bloom filter");
            cr_expect(false == neuropil_bloom->op.check_cb(neuropil_bloom, test5), "expect that the id test5 is not found in bloom filter");
        }
    }

    _np_bloom_free(neuropil_bloom);
}
