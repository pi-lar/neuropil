//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "../test_macros.c"

#include "core/np_comp_msgproperty.h"
#include "util/np_bloom.h"
#include "util/np_minhash.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_dhkey.h"

TestSuite(np_minhash_t);

Test(np_minhash_t,
     _minhash_create,
     .description = "test the functions to create a minhash") {
  // minhash seed
  np_dhkey_t subject_dhkey =
      _np_msgproperty_dhkey(INBOUND, "urn:np:test:minhash:v4");
  np_minhash_t minhash      = {0};
  uint16_t     minhash_size = 16;

  np_minhash_init(&minhash, minhash_size, MIXHASH_MULTI, subject_dhkey);

  char text[] =
      "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
      "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, "
      "sed diam voluptua.";
  uint16_t   text_length   = strnlen(text, 255);
  np_tree_t *text_as_array = np_tree_create();
  uint16_t   count         = 0;

  uint16_t shingles = 5;
  char    *part[shingles];
  char    *delimiter = " ";

  part[0] = strtok(text, " .,");
  while (part[0] != NULL) {
    np_tree_insert_int(text_as_array, count, np_treeval_new_s(part[0]));
    // fprintf(stdout, "%s", part[0]);
    count++;
    part[0] = strtok(NULL, " ");
  }
  // fprintf(stdout, "\n");

  uint16_t        i   = 0;
  np_tree_elem_t *tmp = NULL;
  RB_FOREACH (tmp, np_tree_s, (text_as_array)) {
    part[4] = tmp->val.value.s;
    if (i >= (shingles - 1)) {
      char substring[255];
      snprintf(substring,
               255,
               "%s %s %s %s %s\n",
               part[0],
               part[1],
               part[2],
               part[3],
               part[4]);
      // fprintf(stdout, substring, strnlen(substring, 255));
      np_minhash_push(&minhash, &substring, strnlen(substring, 255));
    }

    part[0] = part[1];
    part[1] = part[2];
    part[2] = part[3];
    part[3] = part[4];
    i++;
  }

  uint32_t signature[minhash_size];
  np_minhash_signature(&minhash, &signature);

  for (uint32_t k = 0; k < minhash_size; k++) {
    // if ((k % 8) == 0) fprintf(stdout, "\n");
    // fprintf(stdout, "%16u ", signature[k]);
  }
  // fprintf(stdout, "\n");
}

Test(
    np_minhash_t,
    _minhash_compare_multi_shingle_1,
    .description = "test the minhash functions and compare several documents") {
  np_minhash_t minhash_1_1, minhash_1_2;
  np_minhash_t minhash_2_1, minhash_2_2;
  np_minhash_t minhash_3_1, minhash_3_2;

  np_dhkey_t seed_dhkey =
      _np_msgproperty_dhkey(INBOUND, "urn:np:test:minhash_compare:v1");

  uint16_t minhash_size = 32;
  uint16_t _no_shingles = 1;

  np_minhash_init(&minhash_1_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_1_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_2, minhash_size, MIXHASH_MULTI, seed_dhkey);

  char text_1[] =
      "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
      "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, "
      "sed diam voluptua.";
  char text_2[] =
      "At vero eos et accusam et justo duo dolores et ea rebum. Stet clita "
      "kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
  char text_3[] =
      "Lorem ipsum dolor sit amet, at vero eos et accusam, Stet clita kasd "
      "gubergren et dolore magna aliquyam erat, sed diam voluptua.";

  char      *delimiter       = " ,!."; // {} []
  np_tree_t *text_as_array_1 = np_tree_create();

  uint16_t count = 0;
  char    *part  = NULL;

  part = strtok(text_1, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_1, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_2 = np_tree_create();

  part = strtok(text_2, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_2, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_3 = np_tree_create();

  part = strtok(text_3, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_3, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  np_minhash_push_tree(&minhash_1_1, text_as_array_1, _no_shingles, true);
  np_minhash_push_tree(&minhash_1_2, text_as_array_1, _no_shingles, false);
  np_minhash_push_tree(&minhash_2_1, text_as_array_2, _no_shingles, true);
  np_minhash_push_tree(&minhash_2_2, text_as_array_2, _no_shingles, false);
  np_minhash_push_tree(&minhash_3_1, text_as_array_3, _no_shingles, true);
  np_minhash_push_tree(&minhash_3_2, text_as_array_3, _no_shingles, false);

  float result = 0.0;
  np_minhash_similarity(&minhash_1_1, &minhash_1_1, &result);
  cr_expect(1.0 == result, "expect the document similarity to be less than ");
  // fprintf(stdout, "similarity of documents 1.1 to 1.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_1_2, &result);
  cr_expect(0.45 < result,
            "expect the document similarity to be greater than 0.45");
  cr_expect(0.50 > result,
            "expect the document similarity to be less than 0.50");
  // fprintf(stdout, "similarity of documents 1.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_1, &result);
  cr_expect(0.40 < result,
            "expect the document similarity to be greater than 0.40");
  cr_expect(0.50 > result,
            "expect the document similarity to be less than 0.50");
  // fprintf(stdout, "similarity of documents 1.1 to 2.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_2, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 1.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_1, &result);
  cr_expect(0.6 < result,
            "expect the document similarity to be greater than 0.6");
  cr_expect(0.7 > result, "expect the document similarity to be less than 0.7");
  // fprintf(stdout, "similarity of documents 1.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_2, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 1.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_1_2, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 2.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_2_2, &result);
  cr_expect(0.5 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.6 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 2.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_1, &result);
  cr_expect(0.45 < result,
            "expect the document similarity to be greater than 0.45");
  cr_expect(0.55 > result,
            "expect the document similarity to be less than 0.55");
  // fprintf(stdout, "similarity of documents 2.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_2, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_2, &minhash_1_2, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_1_2, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_2_2, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_3_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 3.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_1_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 3.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_2_2, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  uint32_t signature[minhash_size];
  /*
      fprintf(stdout, "\n SIGNATURE 1.1: %p\n", &minhash_1_1);
      np_minhash_signature(&minhash_1_1, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 1.2: %p\n", &minhash_1_2);
      np_minhash_signature(&minhash_1_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 2.2: %p\n", &minhash_2_2);
      np_minhash_signature(&minhash_2_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 3.2: %p\n", &minhash_3_2);
      np_minhash_signature(&minhash_3_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      for (uint32_t k = 0; k < _lsh.bands; k++)
      {
          fprintf(stdout, "%d [%d]: \n", k, _lsh.num_entries[k]);
          for (uint32_t l = 1; l <= _lsh.entries; l++)
          {
              fprintf(stdout, "(%5d) %15u %15p ", l+k*_lsh.entries-1,
     _lsh.values[l+k*_lsh.entries-1].hash,
     _lsh.values[l+k*_lsh.entries-1].value);
          }
          fprintf(stdout, "\n");
      }
  */
  np_minhash_t minhash_test;
  np_minhash_init(&minhash_test, minhash_size, MIXHASH_MULTI, seed_dhkey);

  // at vero eos et accusam
  np_minhash_push(&minhash_test, "Lorem", 5);
  np_minhash_push(&minhash_test, "ipsum", 5);
  np_minhash_push(&minhash_test, "dolor", 5);
  np_minhash_push(&minhash_test, "sit", 3);
  np_minhash_push(&minhash_test, "amet", 4);

  np_minhash_similarity(&minhash_1_1, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 1.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_1_2, &minhash_test, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 1.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_1, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_2, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_1, &minhash_test, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 3.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_2, &minhash_test, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 3.2 to test minhash is %f\n",
  // result);
  /*
      fprintf(stdout, "\n SIGNATURE TEST: %p\n", &minhash_test);
      np_minhash_signature(&minhash_test, &signature);

      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");
  */
}

Test(
    np_minhash_t,
    _minhash_compare_single_shingle_1,
    .description = "test the minhash functions and compare several documents") {
  np_minhash_t minhash_1_1, minhash_1_2;
  np_minhash_t minhash_2_1, minhash_2_2;
  np_minhash_t minhash_3_1, minhash_3_2;

  np_dhkey_t seed_dhkey =
      _np_msgproperty_dhkey(INBOUND, "urn:np:test:minhash_compare:v1");

  uint16_t minhash_size = 256;
  uint16_t _no_shingles = 1;

  np_minhash_init(&minhash_1_1, minhash_size, MIXHASH_SINGLE, seed_dhkey);
  np_minhash_init(&minhash_2_1, minhash_size, MIXHASH_SINGLE, seed_dhkey);
  np_minhash_init(&minhash_1_2, minhash_size, MIXHASH_SINGLE, seed_dhkey);
  np_minhash_init(&minhash_2_2, minhash_size, MIXHASH_SINGLE, seed_dhkey);
  np_minhash_init(&minhash_3_1, minhash_size, MIXHASH_SINGLE, seed_dhkey);
  np_minhash_init(&minhash_3_2, minhash_size, MIXHASH_SINGLE, seed_dhkey);

  char text_1[] =
      "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
      "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, "
      "sed diam voluptua.";
  char text_2[] =
      "At vero eos et accusam et justo duo dolores et ea rebum. Stet clita "
      "kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
  char text_3[] =
      "Lorem ipsum dolor sit amet, at vero eos et accusam, Stet clita kasd "
      "gubergren et dolore magna aliquyam erat, sed diam voluptua.";

  char      *delimiter       = " ,!."; // {} []
  np_tree_t *text_as_array_1 = np_tree_create();

  uint16_t count = 0;
  char    *part  = NULL;

  part = strtok(text_1, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_1, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_2 = np_tree_create();

  part = strtok(text_2, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_2, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_3 = np_tree_create();

  part = strtok(text_3, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_3, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  np_minhash_push_tree(&minhash_1_1, text_as_array_1, _no_shingles, true);
  np_minhash_push_tree(&minhash_1_2, text_as_array_1, _no_shingles, false);
  np_minhash_push_tree(&minhash_2_1, text_as_array_2, _no_shingles, true);
  np_minhash_push_tree(&minhash_2_2, text_as_array_2, _no_shingles, false);
  np_minhash_push_tree(&minhash_3_1, text_as_array_3, _no_shingles, true);
  np_minhash_push_tree(&minhash_3_2, text_as_array_3, _no_shingles, false);

  float result = 0.0;
  np_minhash_similarity(&minhash_1_1, &minhash_1_1, &result);
  cr_expect(1.0 == result,
            "expect the document similarity to be equal to 1.0 ");
  // fprintf(stdout, "similarity of documents 1.1 to 1.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_1_2, &result);
  cr_expect(0.45 < result,
            "expect the document similarity to be greater than 0.45");
  cr_expect(0.50 > result,
            "expect the document similarity to be less than 0.50");
  // fprintf(stdout, "similarity of documents 1.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_1, &result);
  cr_expect(0.40 < result,
            "expect the document similarity to be greater than 0.40");
  cr_expect(0.50 > result,
            "expect the document similarity to be less than 0.50");
  // fprintf(stdout, "similarity of documents 1.1 to 2.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_2, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 1.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_1, &result);
  cr_expect(0.6 < result,
            "expect the document similarity to be greater than 0.6");
  cr_expect(0.7 > result, "expect the document similarity to be less than 0.7");
  // fprintf(stdout, "similarity of documents 1.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_2, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 1.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_1_2, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 2.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_2_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 2.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_1, &result);
  cr_expect(0.55 < result,
            "expect the document similarity to be greater than 0.55");
  cr_expect(0.60 > result,
            "expect the document similarity to be less than 0.6");
  // fprintf(stdout, "similarity of documents 2.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_2, &result);
  cr_expect(0.15 < result,
            "expect the document similarity to be greater than 0.15");
  cr_expect(0.25 > result,
            "expect the document similarity to be less than 0.25");
  // fprintf(stdout, "similarity of documents 2.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_2, &minhash_1_2, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_1_2, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_2_2, &result);
  cr_expect(0.15 < result,
            "expect the document similarity to be greater than 0.15");
  cr_expect(0.25 > result,
            "expect the document similarity to be less than 0.25");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_3_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 3.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_1_2, &result);
  cr_expect(0.35 < result,
            "expect the document similarity to be greater than 0.35");
  cr_expect(0.45 > result,
            "expect the document similarity to be less than 0.45");
  // fprintf(stdout, "similarity of documents 3.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_2_2, &result);
  cr_expect(0.3 < result,
            "expect the document similarity to be greater than 0.3");
  cr_expect(0.4 > result, "expect the document similarity to be less than 0.4");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  // uint32_t signature[minhash_size];

  // fprintf(stdout, "\n SIGNATURE 1.1: %p\n", &minhash_1_1);
  // np_minhash_signature(&minhash_1_1, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 1.2: %p\n", &minhash_1_2);
  // np_minhash_signature(&minhash_1_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 2.2: %p\n", &minhash_2_2);
  // np_minhash_signature(&minhash_2_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 3.2: %p\n", &minhash_3_2);
  // np_minhash_signature(&minhash_3_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // for (uint32_t k = 0; k < _lsh.bands; k++)
  // {
  //     fprintf(stdout, "%d [%d]: \n", k, _lsh.num_entries[k]);
  //     for (uint32_t l = 1; l <= _lsh.entries; l++)
  //     {
  //         fprintf(stdout, "(%5d) %15u %15p ", l+k*_lsh.entries-1,
  //         _lsh.values[l+k*_lsh.entries-1].hash,
  //         _lsh.values[l+k*_lsh.entries-1].value);
  //     }
  //     fprintf(stdout, "\n");
  // }

  np_minhash_t minhash_test;
  np_minhash_init(&minhash_test, minhash_size, MIXHASH_SINGLE, seed_dhkey);

  // at vero eos et accusam
  np_minhash_push(&minhash_test, "Lorem", 5);
  np_minhash_push(&minhash_test, "ipsum", 5);
  np_minhash_push(&minhash_test, "dolor", 5);
  np_minhash_push(&minhash_test, "sit", 3);
  np_minhash_push(&minhash_test, "amet", 4);

  np_minhash_similarity(&minhash_1_1, &minhash_test, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 1.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_1_2, &minhash_test, &result);
  cr_expect(0.15 < result,
            "expect the document similarity to be greater than 0.15");
  cr_expect(0.25 > result,
            "expect the document similarity to be less than 0.25");
  // fprintf(stdout, "similarity of documents 1.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_1, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_2, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_1, &minhash_test, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 3.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_2, &minhash_test, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 3.2 to test minhash is %f\n",
  // result);

  // fprintf(stdout, "\n SIGNATURE TEST: %p\n", &minhash_test);
  // np_minhash_signature(&minhash_test, &signature);

  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");
}

Test(
    np_minhash_t,
    _minhash_compare_datadependant_fix,
    .description = "test the minhash functions and compare several documents") {
  np_minhash_t minhash_1_1, minhash_1_2;
  np_minhash_t minhash_2_1, minhash_2_2;
  np_minhash_t minhash_3_1, minhash_3_2;

  np_dhkey_t seed_dhkey = {0};
  np_generate_subject(&seed_dhkey, "urn:np:test:minhash_compare:v1", 31);

  uint16_t minhash_size = 64;
  uint16_t _no_shingles = 1;

  np_minhash_init(&minhash_1_1,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);
  np_minhash_init(&minhash_1_2,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);
  np_minhash_init(&minhash_2_1,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);
  np_minhash_init(&minhash_2_2,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);
  np_minhash_init(&minhash_3_1,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);
  np_minhash_init(&minhash_3_2,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);

  char text_1[] =
      "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
      "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, "
      "sed diam voluptua.";
  char text_2[] =
      "At vero eos et accusam et justo duo dolores et ea rebum. Stet clita "
      "kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
  char text_3[] =
      "Lorem ipsum dolor sit amet, at vero eos et accusam, Stet clita kasd "
      "gubergren et dolore magna aliquyam erat, sed diam voluptua.";

  char      *delimiter       = " ,!."; // {} []
  np_tree_t *text_as_array_1 = np_tree_create();

  uint16_t count = 0;
  char    *part  = NULL;

  part = strtok(text_1, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_1, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_2 = np_tree_create();

  part = strtok(text_2, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_2, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_3 = np_tree_create();

  part = strtok(text_3, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_3, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  np_minhash_push_tree(&minhash_1_1, text_as_array_1, _no_shingles, true);
  np_minhash_push_tree(&minhash_1_2, text_as_array_1, _no_shingles, false);
  np_minhash_push_tree(&minhash_2_1, text_as_array_2, _no_shingles, true);
  np_minhash_push_tree(&minhash_2_2, text_as_array_2, _no_shingles, false);
  np_minhash_push_tree(&minhash_3_1, text_as_array_3, _no_shingles, true);
  np_minhash_push_tree(&minhash_3_2, text_as_array_3, _no_shingles, false);

  float result = 0.0;
  np_minhash_similarity(&minhash_1_1, &minhash_1_1, &result);
  cr_expect(1.0 == result,
            "expect the document similarity to be equal to 1.0 ");
  // fprintf(stdout, "similarity of documents 1.1 to 1.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_1_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 1.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_1, &result);
  cr_expect(0.70 < result,
            "expect the document similarity to be greater than 0.70");
  cr_expect(0.80 > result,
            "expect the document similarity to be less than 0.80");
  // fprintf(stdout, "similarity of documents 1.1 to 2.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 1.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_1, &result);
  cr_expect(0.6 < result,
            "expect the document similarity to be greater than 0.6");
  cr_expect(0.7 > result, "expect the document similarity to be less than 0.7");
  // fprintf(stdout, "similarity of documents 1.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 1.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_1_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_2_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_1, &result);
  cr_expect(0.60 < result,
            "expect the document similarity to be greater than 0.60");
  cr_expect(0.70 > result,
            "expect the document similarity to be less than 0.70");
  // fprintf(stdout, "similarity of documents 2.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_2, &minhash_1_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_1_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_2_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_3_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 3.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_1_2, &result);
  cr_expect(0.20 < result,
            "expect the document similarity to be greater than 0.20");
  cr_expect(0.30 > result,
            "expect the document similarity to be less than 0.30");
  // fprintf(stdout, "similarity of documents 3.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_2_2, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  // uint32_t signature[minhash_size];

  // fprintf(stdout, "\n SIGNATURE 1.1: %p\n", &minhash_1_1);
  // np_minhash_signature(&minhash_1_1, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 1.2: %p\n", &minhash_1_2);
  // np_minhash_signature(&minhash_1_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 2.1: %p\n", &minhash_2_1);
  // np_minhash_signature(&minhash_2_1, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 2.2: %p\n", &minhash_2_2);
  // np_minhash_signature(&minhash_2_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 3.1: %p\n", &minhash_3_1);
  // np_minhash_signature(&minhash_3_1, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // fprintf(stdout, "\n SIGNATURE 3.2: %p\n", &minhash_3_2);
  // np_minhash_signature(&minhash_3_2, &signature);
  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");

  // for (uint32_t k = 0; k < _lsh.bands; k++)
  // {
  //     fprintf(stdout, "%d [%d]: \n", k, _lsh.num_entries[k]);
  //     for (uint32_t l = 1; l <= _lsh.entries; l++)
  //     {
  //         fprintf(stdout, "(%5d) %15u %15p ", l+k*_lsh.entries-1,
  //         _lsh.values[l+k*_lsh.entries-1].hash,
  //         _lsh.values[l+k*_lsh.entries-1].value);
  //     }
  //     fprintf(stdout, "\n");
  // }

  np_minhash_t minhash_test;
  np_minhash_init(&minhash_test,
                  minhash_size,
                  MIXHASH_DATADEPENDANT_FIX,
                  seed_dhkey);

  // at vero eos et accusam
  np_minhash_push(&minhash_test, "Lorem", 5);
  np_minhash_push(&minhash_test, "ipsum", 5);
  np_minhash_push(&minhash_test, "dolor", 5);
  np_minhash_push(&minhash_test, "sit", 3);
  np_minhash_push(&minhash_test, "amet", 4);

  np_minhash_similarity(&minhash_1_1, &minhash_test, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 1.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_1_2, &minhash_test, &result);
  cr_expect(0.15 < result,
            "expect the document similarity to be greater than 0.15");
  cr_expect(0.25 > result,
            "expect the document similarity to be less than 0.25");
  // fprintf(stdout, "similarity of documents 1.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_1, &minhash_test, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_2, &minhash_test, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 2.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_1, &minhash_test, &result);
  cr_expect(0.05 > result,
            "expect the document similarity to be less than 0.05");
  // fprintf(stdout, "similarity of documents 3.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_2, &minhash_test, &result);
  cr_expect(0.2 < result,
            "expect the document similarity to be greater than 0.2");
  cr_expect(0.3 > result, "expect the document similarity to be less than 0.3");
  // fprintf(stdout, "similarity of documents 3.2 to test minhash is %f\n",
  // result);

  // fprintf(stdout, "\n SIGNATURE TEST: %p\n", &minhash_test);
  // np_minhash_signature(&minhash_test, &signature);

  // for (uint32_t k = 0; k < minhash_size; k++)
  // {
  //     if ((k % 8) == 0) fprintf(stdout, "\n");
  //     fprintf(stdout, "%16u ", signature[k]);
  // }
  // fprintf(stdout, "\n");
}

Test(
    np_minhash_t,
    _minhash_compare_tripple_shingle,
    .description = "test the minhash functions and compare several documents") {
  np_minhash_t minhash_1_1, minhash_1_2;
  np_minhash_t minhash_2_1, minhash_2_2;
  np_minhash_t minhash_3_1, minhash_3_2;

  np_dhkey_t seed_dhkey =
      _np_msgproperty_dhkey(INBOUND, "urn:np:test:minhash_compare:v1");

  uint16_t minhash_size = 32;
  uint16_t _no_shingles = 3;

  np_minhash_init(&minhash_1_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_1_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_2, minhash_size, MIXHASH_MULTI, seed_dhkey);

  char text_1[] =
      "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam "
      "nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, "
      "sed diam voluptua.";
  char text_2[] =
      "At vero eos et accusam et justo duo dolores et ea rebum. Stet clita "
      "kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet.";
  char text_3[] =
      "Lorem ipsum dolor sit amet, at vero eos et accusam, Stet clita kasd "
      "gubergren et dolore magna aliquyam erat, sed diam voluptua.";

  char      *delimiter       = " ,!."; // {} []
  np_tree_t *text_as_array_1 = np_tree_create();

  uint16_t count = 0;
  char    *part  = NULL;

  part = strtok(text_1, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_1, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_2 = np_tree_create();

  part = strtok(text_2, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_2, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_3 = np_tree_create();

  part = strtok(text_3, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_3, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  np_minhash_push_tree(&minhash_1_1, text_as_array_1, _no_shingles, true);
  np_minhash_push_tree(&minhash_1_2, text_as_array_1, _no_shingles, false);
  np_minhash_push_tree(&minhash_2_1, text_as_array_2, _no_shingles, true);
  np_minhash_push_tree(&minhash_2_2, text_as_array_2, _no_shingles, false);
  np_minhash_push_tree(&minhash_3_1, text_as_array_3, _no_shingles, true);
  np_minhash_push_tree(&minhash_3_2, text_as_array_3, _no_shingles, false);

  float result = 0.0;
  np_minhash_similarity(&minhash_1_1, &minhash_1_1, &result);
  cr_expect(1.0 == result, "expect the document similarity to be less than ");
  // fprintf(stdout, "similarity of documents 1.1 to 1.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_1_2, &result);
  cr_expect(0.45 < result,
            "expect the document similarity to be greater than 0.45");
  cr_expect(0.55 > result,
            "expect the document similarity to be less than 0.55");
  // fprintf(stdout, "similarity of documents 1.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_1, &result);
  cr_expect(0.35 < result,
            "expect the document similarity to be greater than 0.35");
  cr_expect(0.45 > result,
            "expect the document similarity to be less than 0.45");
  // fprintf(stdout, "similarity of documents 1.1 to 2.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_2_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 1.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_1, &result);
  cr_expect(0.35 < result,
            "expect the document similarity to be greater than 0.35");
  cr_expect(0.45 > result,
            "expect the document similarity to be less than 0.45");
  // fprintf(stdout, "similarity of documents 1.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_1_1, &minhash_3_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 1.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_1_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.1 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_2_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 2.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_1, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 2.1 to 3.1 is %f\n", result);

  np_minhash_similarity(&minhash_2_1, &minhash_3_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_2, &minhash_1_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_1_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_2_2, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_1, &minhash_3_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 3.1 to 3.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_1_2, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 3.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_2_2, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.05");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.15");
  // fprintf(stdout, "similarity of documents 3.1 to 2.2 is %f\n", result);

  uint32_t signature[minhash_size];
  /*
      fprintf(stdout, "\n SIGNATURE 1.1: %p\n", &minhash_1_1);
      np_minhash_signature(&minhash_1_1, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 1.2: %p\n", &minhash_1_2);
      np_minhash_signature(&minhash_1_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 2.2: %p\n", &minhash_2_2);
      np_minhash_signature(&minhash_2_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 3.2: %p\n", &minhash_3_2);
      np_minhash_signature(&minhash_3_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      for (uint32_t k = 0; k < _lsh.bands; k++)
      {
          fprintf(stdout, "%d [%d]: \n", k, _lsh.num_entries[k]);
          for (uint32_t l = 1; l <= _lsh.entries; l++)
          {
              fprintf(stdout, "(%5d) %15u %15p ", l+k*_lsh.entries-1,
     _lsh.values[l+k*_lsh.entries-1].hash,
     _lsh.values[l+k*_lsh.entries-1].value);
          }
          fprintf(stdout, "\n");
      }
  */
  np_minhash_t minhash_test;
  np_minhash_init(&minhash_test, minhash_size, MIXHASH_MULTI, seed_dhkey);

  // at vero eos et accusam
  np_minhash_push(&minhash_test, "Loremipsumdolor", 15);
  np_minhash_push(&minhash_test, "ipsumdolorsit", 13);
  np_minhash_push(&minhash_test, "dolorsitamet", 12);
  np_minhash_push(&minhash_test, "sitametLorem", 12);
  np_minhash_push(&minhash_test, "ametLoremipsum", 14);

  np_minhash_similarity(&minhash_1_1, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 1.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_1_2, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 1.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_1, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 2.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_2, &minhash_test, &result);
  cr_expect(0.05 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.15 > result,
            "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_1, &minhash_test, &result);
  cr_expect(0.0 <= result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 3.1 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_2, &minhash_test, &result);
  cr_expect(0.0 < result,
            "expect the document similarity to be greater than 0.0");
  cr_expect(0.1 > result, "expect the document similarity to be less than 0.1");
  // fprintf(stdout, "similarity of documents 3.2 to test minhash is %f\n",
  // result);
  /*
      fprintf(stdout, "\n SIGNATURE TEST: %p\n", &minhash_test);
      np_minhash_signature(&minhash_test, &signature);

      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");
  */
}

Test(np_minhash_t,
     _minhash_compare_odrl,
     .description =
         "test the minhash functions and compare several odrl policies") {
  np_minhash_t minhash_1_1, minhash_1_2;
  np_minhash_t minhash_2_1, minhash_2_2;
  np_minhash_t minhash_3_1, minhash_3_2;

  np_dhkey_t seed_dhkey =
      _np_msgproperty_dhkey(INBOUND, "urn:np:test:odrl_policy:compare");

  uint16_t minhash_size = 32;
  uint16_t _no_shingles = 2;

  np_minhash_init(&minhash_1_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_1_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_2_2, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_1, minhash_size, MIXHASH_MULTI, seed_dhkey);
  np_minhash_init(&minhash_3_2, minhash_size, MIXHASH_MULTI, seed_dhkey);

  char text_1[] =
      "{ \"@context\": \"http://www.w3.org/ns/odrl.jsonld\", \"@type\": "
      "\"Set\", \"uid\": \"http://example.com/policy:1010\", \"permission\": [ "
      "{ \"target\": \"http://example.com/asset:9898.movie\", \"assignee\": "
      "\"John\", \"action\": \"play\" } ] }";
  char text_2[] =
      "{ \"@context\": \"http://www.w3.org/ns/odrl.jsonld\", \"@type\": "
      "\"Set\", \"uid\": \"http://example.com/policy:1010\", \"permission\": [ "
      "{ \"target\": \"http://example.com/asset:9898.movie\", \"action\": "
      "\"display\", \"constraint\": [ { \"leftOperand\": \"spatial\", "
      "\"operator\": \"eq\", \"rightOperand\": "
      "\"https://www.wikidata.org/wiki/Q183\", \"comment\": \"i.e Germany\" } "
      "] } ] }";
  char text_3[] =
      "{ \"@context\": \"http://www.w3.org/ns/odrl.jsonld\", \"@type\": "
      "\"Set\", \"uid\": \"http://example.com/policy:1010\", \"permission\": [ "
      "{ \"target\": \"http://example.com/asset:9898.movie\", \"action\": "
      "\"display\", \"constraint\": [ { \"leftOperand\": \"dateTime\", "
      "\"operator\": \"gt\", \"rightOperand\":  { \"@value\": \"2019-01-01\", "
      "\"@type\": \"xsd:date\" } } ] } ] }";

  char      *delimiter       = " ,!.{}:[]\"/"; //
  np_tree_t *text_as_array_1 = np_tree_create();

  uint16_t count = 0;
  char    *part  = NULL;

  part = strtok(text_1, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_1, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_2 = np_tree_create();

  part = strtok(text_2, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_2, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  part                       = NULL;
  count                      = 0;
  np_tree_t *text_as_array_3 = np_tree_create();

  part = strtok(text_3, delimiter);
  while (part != NULL) {
    np_tree_insert_int(text_as_array_3, count, np_treeval_new_s(part));
    count++;
    part = strtok(NULL, delimiter);
  }

  // np_minhash_push_tree(&minhash_1_1, text_as_array_1, _no_shingles, true );
  np_minhash_push_tree(&minhash_1_2, text_as_array_1, _no_shingles, false);
  // np_minhash_push_tree(&minhash_2_1, text_as_array_2, _no_shingles, true );
  np_minhash_push_tree(&minhash_2_2, text_as_array_2, _no_shingles, false);
  // np_minhash_push_tree(&minhash_3_1, text_as_array_3, _no_shingles, true );
  np_minhash_push_tree(&minhash_3_2, text_as_array_3, _no_shingles, false);

  float result = 0.0;
  np_minhash_similarity(&minhash_1_2, &minhash_1_2, &result);
  cr_expect(1.0 == result, "expect the document similarity to be less than ");
  // fprintf(stdout, "similarity of documents 1.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_2_2, &minhash_1_2, &result);
  cr_expect(0.4 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.5 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 2.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_1_2, &result);
  cr_expect(0.45 < result,
            "expect the document similarity to be greater than 0.6");
  cr_expect(0.55 > result,
            "expect the document similarity to be less than 0.7");
  // fprintf(stdout, "similarity of documents 3.2 to 1.2 is %f\n", result);

  np_minhash_similarity(&minhash_3_2, &minhash_2_2, &result);
  cr_expect(0.6 < result,
            "expect the document similarity to be greater than 0.4");
  cr_expect(0.7 > result, "expect the document similarity to be less than 0.5");
  // fprintf(stdout, "similarity of documents 3.2 to 2.2 is %f\n", result);

  uint32_t signature[minhash_size];
  /*
      fprintf(stdout, "\n SIGNATURE 1.2: %p\n", &minhash_1_2);
      np_minhash_signature(&minhash_1_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 2.2: %p\n", &minhash_2_2);
      np_minhash_signature(&minhash_2_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");

      fprintf(stdout, "\n SIGNATURE 3.2: %p\n", &minhash_3_2);
      np_minhash_signature(&minhash_3_2, &signature);
      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");
  */
  np_minhash_t minhash_test;
  np_minhash_init(&minhash_test, minhash_size, MIXHASH_MULTI, seed_dhkey);

  np_minhash_push(&minhash_test, "odrljsonld", 10);
  np_minhash_push(&minhash_test, "1010permission", 14);
  np_minhash_push(&minhash_test, "asset9898", 9);
  np_minhash_push(&minhash_test, "9898movie", 9);
  np_minhash_push(&minhash_test, "permissiontarget", 16);
  np_minhash_push(&minhash_test, "actiondisplay", 13);
  np_minhash_push(&minhash_test, "displayconstraint", 17);
  np_minhash_push(&minhash_test, "leftOperanddateTime", 19);
  np_minhash_push(&minhash_test, "@value2019-01-01", 16);

  np_minhash_similarity(&minhash_1_2, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 1.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_2_2, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 2.2 to test minhash is %f\n",
  // result);

  np_minhash_similarity(&minhash_3_2, &minhash_test, &result);
  cr_expect(0.1 < result,
            "expect the document similarity to be greater than 0.1");
  cr_expect(0.2 > result, "expect the document similarity to be less than 0.2");
  // fprintf(stdout, "similarity of documents 3.2 to test minhash is %f\n",
  // result);

  /*
      fprintf(stdout, "\n SIGNATURE TEST: %p\n", &minhash_test);
      np_minhash_signature(&minhash_test, &signature);

      for (uint32_t k = 0; k < minhash_size; k++)
      {
          if ((k % 8) == 0) fprintf(stdout, "\n");
          fprintf(stdout, "%16u ", signature[k]);
      }
      fprintf(stdout, "\n");
  */
}

/*
@contexthttp
httpwww
wwww3
w3org
orgns
nsodrl
odrljsonld
jsonld@type
@typeSet
Setuid
uidhttp
httpexample
examplecom
compolicy
policy1010
1010permission
permissiontarget
targethttp
httpexample
examplecom
comasset
asset9898
9898movie
movieaction
actiondisplay
displayconstraint
constraintleftOperand
leftOperanddateTime
dateTimeoperator
operatorgt
gtrightOperand
rightOperand@value
@value2019-01-01
2019-01-01@type
@typexsd
xsddate
*/
