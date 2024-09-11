//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <assert.h>
#include <criterion/criterion.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../test_macros.c"
#include "pthread.h"

#include "neuropil_log.h"

#include "core/np_comp_node.h"
#include "util/np_list.h"
#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_crypto.h"
#include "np_dhkey.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_threads.h"
#include "np_token_factory.h"
#include "np_types.h"
#include "np_util.h"

TestSuite(np_message_t);

Test(np_message_t,
     serialize_np_message_t_with_dhkey,
     .description =
         "test the serialization of a message object with dhkey in body") {
  CTX() {

    np_subject subject_id = {0};
    np_generate_subject(&subject_id, "serialize_np_message_t", 22);
    struct np_mx_properties props = np_get_mx_properties(context, subject_id);

    // Build source message and necessary data
    np_dhkey_t write_dhkey_from;
    write_dhkey_from.t[0] = 1;
    write_dhkey_from.t[1] = 2;
    write_dhkey_from.t[2] = 3;
    write_dhkey_from.t[3] = 4;
    write_dhkey_from.t[4] = 5;
    write_dhkey_from.t[5] = 6;
    write_dhkey_from.t[6] = 7;
    write_dhkey_from.t[7] = 8;

    np_dhkey_t write_dhkey_to;
    write_dhkey_to.t[0] = 5;
    write_dhkey_to.t[1] = 6;
    write_dhkey_to.t[2] = 7;
    write_dhkey_to.t[3] = 8;
    write_dhkey_to.t[4] = 9;
    write_dhkey_to.t[5] = 10;
    write_dhkey_to.t[6] = 11;
    write_dhkey_to.t[7] = 12;

    np_tree_t *write_tree = np_tree_create();
    np_tree_insert_str(write_tree,
                       "TESTKEY_FROM",
                       np_treeval_new_dhkey(write_dhkey_from));
    np_tree_insert_str(write_tree,
                       "TESTKEY_TO",
                       np_treeval_new_dhkey(write_dhkey_to));

    np_dhkey_t test_subject_dhkey = {};
    memcpy(&test_subject_dhkey, &subject_id, NP_FINGERPRINT_BYTES);

    struct np_e2e_message_s *write_msg = NULL;
    np_new_obj(np_message_t, write_msg);
    _np_message_create(write_msg,
                       write_dhkey_to,
                       write_dhkey_from,
                       test_subject_dhkey,
                       write_tree);

    // Do the serialsation
    bool write_ret = _np_message_serialize_chunked(context, write_msg);
    cr_assert(true == write_ret, "Expected positive result in serialisation");

    // np_build_network_paket(write_msg->msg_chunks[0]);

    cr_expect(1 == *write_msg->parts, "expect a single chunk message");

    // Do the deserialisation
    struct np_e2e_message_s *read_msg = NULL;
    np_new_obj(np_message_t, read_msg);

    uint16_t count_of_chunks = 0;
    _np_message_add_chunk(read_msg, write_msg->msg_chunks[0], &count_of_chunks);

    cr_expect(1 == count_of_chunks, "expect a single chunk message");

    bool read_ret = _np_message_deserialize_chunks(read_msg);
    cr_assert(true == read_ret,
              "Expected positive result in de-serialisation of chunks");

    read_ret = _np_message_readbody(read_msg);
    cr_assert(
        true == read_ret,
        "Expected positive result in de-serialisation of data structures");

    // Compare deserialized content with expected
    np_tree_elem_t *testkey_read_from =
        np_tree_find_str(read_msg->msg_body, "TESTKEY_FROM");
    cr_assert(NULL != testkey_read_from,
              "Expected to find TESTKEY_FROM key value");

    cr_assert(testkey_read_from->val.type == np_treeval_type_dhkey,
              "Expected read testkey_read_from to be of type "
              "np_treeval_type_dhkey. But is: %" PRIu8,
              testkey_read_from->val.type);
    cr_expect(
        testkey_read_from->val.size == sizeof(np_dhkey_t),
        "Expected testkey_read_from to be of dhkey size. But is: %" PRIu32,
        testkey_read_from->val.size);

    cr_expect(testkey_read_from->val.value.dhkey.t[0] == 1,
              "Expected read testkey_read_from value 0 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[0]);
    cr_expect(testkey_read_from->val.value.dhkey.t[1] == 2,
              "Expected read testkey_read_from value 1 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[1]);
    cr_expect(testkey_read_from->val.value.dhkey.t[2] == 3,
              "Expected read testkey_read_from value 2 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[2]);
    cr_expect(testkey_read_from->val.value.dhkey.t[3] == 4,
              "Expected read testkey_read_from value 3 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[3]);

    np_tree_elem_t *testkey_read_to =
        np_tree_find_str(read_msg->msg_body, "TESTKEY_TO");
    cr_assert(NULL != testkey_read_to, "Expected to find TESTKEY_TO key value");

    cr_assert(testkey_read_to->val.type == np_treeval_type_dhkey,
              "Expected read testkey_read_to to be of type "
              "np_treeval_type_dhkey. But is: %" PRIu8,
              testkey_read_to->val.type);
    cr_expect(testkey_read_to->val.size == sizeof(np_dhkey_t),
              "Expected testkey_read_to to be of dhkey size. But is: %" PRIu32,
              testkey_read_to->val.size);

    cr_expect(testkey_read_to->val.value.dhkey.t[0] == 5,
              "Expected read testkey_read_to value 0 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[0]);
    cr_expect(testkey_read_to->val.value.dhkey.t[1] == 6,
              "Expected read testkey_read_to value 1 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[1]);
    cr_expect(testkey_read_to->val.value.dhkey.t[2] == 7,
              "Expected read testkey_read_to value 2 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[2]);
    cr_expect(testkey_read_to->val.value.dhkey.t[3] == 8,
              "Expected read testkey_read_to value 3 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[3]);
  }
}

Test(np_message_t,
     serialize_np_message_t_with_dhkey_unchunked_instructions,
     .description =
         "test the serialization of a message object with dhkey in body") {
  CTX() {

    np_subject subject_id = {0};
    np_generate_subject(&subject_id, "serialize_np_message_t", 22);
    struct np_mx_properties props = np_get_mx_properties(context, subject_id);

    // Build source message and necessary data
    np_dhkey_t write_dhkey_from;
    write_dhkey_from.t[0] = 1;
    write_dhkey_from.t[1] = 2;
    write_dhkey_from.t[2] = 3;
    write_dhkey_from.t[3] = 4;
    write_dhkey_from.t[4] = 0;
    write_dhkey_from.t[5] = 0;
    write_dhkey_from.t[6] = 0;
    write_dhkey_from.t[7] = 0;

    np_dhkey_t write_dhkey_to;
    write_dhkey_to.t[0] = 5;
    write_dhkey_to.t[1] = 6;
    write_dhkey_to.t[2] = 7;
    write_dhkey_to.t[3] = 8;
    write_dhkey_to.t[4] = 0;
    write_dhkey_to.t[5] = 0;
    write_dhkey_to.t[6] = 0;
    write_dhkey_to.t[7] = 0;

    struct np_e2e_message_s *write_msg = NULL;
    np_new_obj(np_message_t, write_msg);

    np_tree_t *write_tree = np_tree_create();
    np_tree_insert_str(write_tree,
                       "TESTKEY_FROM",
                       np_treeval_new_dhkey(write_dhkey_from));
    np_tree_insert_str(write_tree,
                       "TESTKEY_TO",
                       np_treeval_new_dhkey(write_dhkey_to));

    np_dhkey_t test_subject_dhkey = {};
    memcpy(&test_subject_dhkey, &subject_id, NP_FINGERPRINT_BYTES);

    _np_message_create(write_msg,
                       write_dhkey_to,
                       write_dhkey_from,
                       test_subject_dhkey,
                       write_tree);

    // Do the serialization
    bool write_ret = _np_message_serialize_chunked(context, write_msg);
    cr_assert(true == write_ret,
              "Expected positive result in chunk serialisation");
    cr_expect(*write_msg->parts == 1, "Expected 1 chunk for message");
    cr_expect(write_msg->state == msgstate_chunked,
              "Expected chunked message state");

    // Do the deserialization
    struct np_e2e_message_s *read_msg = NULL;
    np_new_obj(np_message_t, read_msg);
    uint16_t number_of_chunks = 0;

    enum np_return test_add_chunk = np_ok;
    for (uint16_t i = 0; i < *write_msg->parts; i++) {
      test_add_chunk = _np_message_add_chunk(read_msg,
                                             write_msg->msg_chunks[i],
                                             &number_of_chunks);
      cr_expect(number_of_chunks == i + 1,
                "expect the number of chunks to increase");
      cr_expect(test_add_chunk == np_ok, "expect the chunk to be added");
      test_add_chunk = _np_message_add_chunk(read_msg,
                                             write_msg->msg_chunks[i],
                                             &number_of_chunks);
      cr_expect(number_of_chunks == i + 1,
                "expect the number of chunks to not increase");
      cr_expect(test_add_chunk == np_operation_failed,
                "expect the chunk not to be added");
    }
    bool read_ret = _np_message_deserialize_chunks(read_msg);
    cr_expect(true == read_ret, "Expected positive result in de-serialization");

    read_ret = _np_message_readbody(read_msg);
    cr_expect(true == read_ret,
              "Expected positive result for reading in the body");

    // Compare deserialized content with expected
    np_tree_elem_t *testkey_read_from =
        np_tree_find_str(read_msg->msg_body, "TESTKEY_FROM");
    cr_assert(NULL != testkey_read_from,
              "Expected to find TESTKEY_FROM key value");

    cr_assert(testkey_read_from->val.type == np_treeval_type_dhkey,
              "Expected read testkey_read_from to be of type "
              "np_treeval_type_dhkey. But is: %" PRIu8,
              testkey_read_from->val.type);
    cr_expect(
        testkey_read_from->val.size == sizeof(np_dhkey_t),
        "Expected testkey_read_from to be of dhkey size. But is: %" PRIu32,
        testkey_read_from->val.size);

    cr_expect(testkey_read_from->val.value.dhkey.t[0] == 1,
              "Expected read testkey_read_from value 0 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[0]);
    cr_expect(testkey_read_from->val.value.dhkey.t[1] == 2,
              "Expected read testkey_read_from value 1 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[1]);
    cr_expect(testkey_read_from->val.value.dhkey.t[2] == 3,
              "Expected read testkey_read_from value 2 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[2]);
    cr_expect(testkey_read_from->val.value.dhkey.t[3] == 4,
              "Expected read testkey_read_from value 3 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_from->val.value.dhkey.t[3]);

    np_tree_elem_t *testkey_read_to =
        np_tree_find_str(read_msg->msg_body, "TESTKEY_TO");
    cr_assert(NULL != testkey_read_to, "Expected to find TESTKEY_TO key value");

    cr_assert(testkey_read_to->val.type == np_treeval_type_dhkey,
              "Expected read testkey_read_to to be of type "
              "np_treeval_type_dhkey. But is: %" PRIu8,
              testkey_read_to->val.type);
    cr_expect(testkey_read_to->val.size == sizeof(np_dhkey_t),
              "Expected testkey_read_to to be of dhkey size. But is: %" PRIu32,
              testkey_read_to->val.size);

    cr_expect(testkey_read_to->val.value.dhkey.t[0] == 5,
              "Expected read testkey_read_to value 0 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[0]);
    cr_expect(testkey_read_to->val.value.dhkey.t[1] == 6,
              "Expected read testkey_read_to value 1 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[1]);
    cr_expect(testkey_read_to->val.value.dhkey.t[2] == 7,
              "Expected read testkey_read_to value 2 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[2]);
    cr_expect(testkey_read_to->val.value.dhkey.t[3] == 8,
              "Expected read testkey_read_to value 3 to be the same as "
              "predefined, But is: %" PRIu32,
              testkey_read_to->val.value.dhkey.t[3]);
  }
}

// TODO: add the appropiate cr_expect() statements to really test the message
// chunking
Test(np_message_t,
     _message_chunk_and_serialize,
     .description = "test the chunking of messages") {
  CTX() {
    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    char *msg_subject = "this.is.a.test";

    np_dhkey_t my_dhkey           = np_dhkey_create_from_hostport("me", "two");
    np_dhkey_t test_subject_dhkey = {0};
    np_generate_subject(&test_subject_dhkey,
                        msg_subject,
                        strnlen(msg_subject, 256));

    _np_message_create(msg_out, my_dhkey, my_dhkey, test_subject_dhkey, NULL);

    cr_expect(*msg_out->parts == 1,
              "expect the number of chunks to be one for empty message body");

    np_tree_t *body_tree = np_tree_create();

    char body_payload[51];
    memset(body_payload, 'b', 50);
    body_payload[50] = '\0';

    for (int16_t i = 0; i < 60; i++) {
      np_tree_insert_int(body_tree, i, np_treeval_new_s(body_payload));
    }

    _np_message_setbody(msg_out, body_tree);

    cr_expect(
        *msg_out->parts == 4,
        "expect the number of chunks to be 4 after setting 3k message body");
    cr_expect(msg_out->state == msgstate_binary,
              "expect the message to be in binary format");

    _np_message_serialize_chunked(context, msg_out);

    char *packet[*msg_out->parts];
    for (uint16_t i = 0; i < *msg_out->parts; i++) {
      _np_node_build_network_packet(msg_out->msg_chunks[i]);
      packet[i] = msg_out->msg_chunks[i]->msg_chunk;
    }

    struct np_e2e_message_s *msg_in = NULL;
    np_new_obj(np_message_t, msg_in);

    for (uint16_t i = 0; i < *msg_out->parts; i++) {
      // Do the deserialisation
      struct np_n2n_messagepart_s *msgpart_in = NULL;
      np_new_obj(np_message_t, msgpart_in);

      bool read_ret =
          _np_message_deserialize_header_and_instructions(packet[i],
                                                          msgpart_in);
      cr_assert(true == read_ret,
                "Expected positive result in deserialisation");

      uint16_t       number_of_chunks = 0;
      enum np_return add_chunk_result =
          _np_message_add_chunk(msg_in, msgpart_in, &number_of_chunks);
      cr_expect(add_chunk_result == np_ok,
                "expect that the new chunk (%d) could be added",
                i + 1);
      cr_expect(number_of_chunks == i + 1,
                "expect the number of chunks to be %d",
                i + 1);
    }

    _np_message_deserialize_chunks(msg_out);

    _np_message_readbody(msg_out);

    for (int16_t i = 0; i < 60; i++) {
      np_tree_elem_t *body_node_2 = np_tree_find_int(msg_out->msg_body, i);
      cr_expect(NULL != body_node_2, "Expected to find data in body %d", i);
    }
  }
}

Test(np_message_t,
     encrypt_decrypt_message,
     .description = "test the encryption/decryption for a message") {
  CTX() {
    struct np_e2e_message_s *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    np_dhkey_t _test_dhkey = {.t[0] = 1,
                              .t[1] = 1,
                              .t[2] = 2,
                              .t[3] = 3,
                              .t[4] = 4,
                              .t[5] = 5,
                              .t[6] = 6,
                              .t[7] = 7};
    np_tree_t *test_tree   = np_tree_create();
    np_tree_insert_str(test_tree, "test", np_treeval_new_d(4.0));
    _np_message_create(msg_out,
                       _test_dhkey,
                       _test_dhkey,
                       _test_dhkey,
                       test_tree);

    np_aaatoken_t *peer = _np_key_get_token(context->my_identity);
    strncpy(peer->issuer, _np_key_as_str(context->my_identity), 64);

    // np_sll_t(np_aaatoken_ptr, token_list);
    // sll_init(np_aaatoken_ptr, token_list);
    // sll_append(np_aaatoken_ptr,
    //            token_list,
    //            _np_key_get_token(context->my_identity));

    unsigned char session_key[NP_FINGERPRINT_BYTES];
    randombytes_buf(session_key, NP_FINGERPRINT_BYTES);
    np_crypto_session_t session = {.session_key_to_read_is_set  = true,
                                   .session_key_to_write_is_set = true,
                                   .session_type = crypto_session_private};
    memcpy(session.session_key_to_read, session_key, NP_FINGERPRINT_BYTES);
    memcpy(session.session_key_to_write, session_key, NP_FINGERPRINT_BYTES);

    _np_message_encrypt_payload(msg_out, &session);

    // Do the serialsation
    bool write_ret = _np_message_serialize_chunked(context, msg_out);

    cr_expect(true == write_ret,
              "Expected positive result in chunk serialisation");
    cr_expect(*msg_out->parts == 1, "Expected 1 chunk for message");

    _np_node_build_network_packet(msg_out->msg_chunks[0]);
    char *packet = msg_out->msg_chunks[0]->msg_chunk;

    // Do the deserialisation
    struct np_n2n_messagepart_s *msgpart_in = NULL;
    np_new_obj(np_message_t, msgpart_in);

    bool read_ret =
        _np_message_deserialize_header_and_instructions(packet, msgpart_in);
    cr_assert(true == read_ret, "Expected positive result in deserialisation");

    struct np_e2e_message_s *msg_in = NULL;
    np_new_obj(np_message_t, msg_in);
    uint16_t number_of_chunks = 0;
    _np_message_add_chunk(msg_in, msgpart_in, &number_of_chunks);

    cr_expect(number_of_chunks == 1, "expect the number of chunks to be 1");

    bool ret = _np_message_deserialize_chunks(msg_in);
    cr_assert(true == ret, "Expected positive result in de-serialisation");
    cr_expect(msg_in->state == msgstate_binary,
              "expect the message to be in binary format");

    _np_message_decrypt_payload(msg_in, &session);

    _np_message_readbody(msg_in);
    cr_expect(msg_in->state == msgstate_raw,
              "expect the message to be in raw format");

    np_tree_elem_t *elem = np_tree_find_str(msg_in->msg_body, "test");
    cr_assert(elem != NULL, "expected tree element to be present");
  }
}
