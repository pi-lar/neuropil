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
#include "msgpack/cmp.h"
#include "pthread.h"

#include "neuropil_log.h"

#include "../src/np_jobqueue.c"
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

    struct np_mx_properties props =
        np_get_mx_properties(context, "serialize_np_message_t");

    log_trace_msg(LOG_TRACE, "start test.serialize_np_message_t_with_dhkey");
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

    np_key_t *write_from = NULL;
    np_new_obj(np_key_t, write_from);
    write_from->dhkey  = write_dhkey_from;
    np_key_t *write_to = NULL;
    np_new_obj(np_key_t, write_to);
    write_to->dhkey = write_dhkey_to;

    np_tree_t *write_tree = np_tree_create();
    np_tree_insert_str(write_tree,
                       "TESTKEY_FROM",
                       np_treeval_new_dhkey(write_dhkey_from));
    np_tree_insert_str(write_tree,
                       "TESTKEY_TO",
                       np_treeval_new_dhkey(write_dhkey_to));

    np_dhkey_t test_subject_dhkey = {0};
    np_generate_subject(&test_subject_dhkey, "serialize_np_message_t", 22);

    np_message_t *write_msg = NULL;
    np_new_obj(np_message_t, write_msg);
    _np_message_create(write_msg,
                       write_to->dhkey,
                       write_from->dhkey,
                       test_subject_dhkey,
                       write_tree);
    np_tree_insert_str(write_msg->instructions,
                       _NP_MSG_INST_PARTS,
                       np_treeval_new_iarray(0, 0));

    // Do the serialsation
    _np_message_calculate_chunking(write_msg);
    bool write_ret = _np_message_serialize_chunked(context, write_msg);
    cr_assert(true == write_ret, "Expected positive result in serialisation");

    cr_expect(pll_size(write_msg->msg_chunks) == 1,
              "Expected 1 chunk for message");

    // Do the deserialisation
    np_message_t *read_msg = NULL;
    np_new_obj(np_message_t, read_msg);
    read_msg->msg_chunks = write_msg->msg_chunks;

    bool read_ret = _np_message_deserialize_chunked(read_msg);
    cr_assert(true == read_ret, "Expected positive result in de-serialisation");

    // Compare deserialized content with expected
    np_tree_elem_t *testkey_read_from =
        np_tree_find_str(read_msg->body, "TESTKEY_FROM");
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
        np_tree_find_str(read_msg->body, "TESTKEY_TO");
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

    log_trace_msg(LOG_TRACE, "end test.serialize_np_message_t_with_dhkey");
  }
}

Test(np_message_t,
     serialize_np_message_t_with_dhkey_unchunked_instructions,
     .description =
         "test the serialization of a message object with dhkey in body") {
  CTX() {
    log_trace_msg(
        LOG_TRACE,
        "start test.serialize_np_message_t_with_dhkey_unchunked_instructions");

    struct np_mx_properties props =
        np_get_mx_properties(context, "serialize_np_message_t");

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

    np_key_t *write_from = NULL;
    np_new_obj(np_key_t, write_from);
    write_from->dhkey  = write_dhkey_from;
    np_key_t *write_to = NULL;
    np_new_obj(np_key_t, write_to);
    write_to->dhkey = write_dhkey_to;

    np_message_t *write_msg = NULL;
    np_new_obj(np_message_t, write_msg);

    np_tree_t *write_tree = np_tree_create();
    np_tree_insert_str(write_tree,
                       "TESTKEY_FROM",
                       np_treeval_new_dhkey(write_dhkey_from));
    np_tree_insert_str(write_tree,
                       "TESTKEY_TO",
                       np_treeval_new_dhkey(write_dhkey_to));

    np_tree_insert_str(write_msg->instructions,
                       "TESTKEY_FROM",
                       np_treeval_new_dhkey(write_dhkey_from));
    np_tree_insert_str(write_msg->instructions,
                       "TESTKEY_TO",
                       np_treeval_new_dhkey(write_dhkey_to));

    np_dhkey_t test_subject_dhkey = {0};
    np_generate_subject(&test_subject_dhkey, "serialize_np_message_t", 22);

    _np_message_create(write_msg,
                       write_to->dhkey,
                       write_from->dhkey,
                       test_subject_dhkey,
                       write_tree);
    np_tree_insert_str(write_msg->instructions,
                       _NP_MSG_INST_PARTS,
                       np_treeval_new_iarray(0, 0));

    // Do the serialsation
    _np_message_calculate_chunking(write_msg);
    bool write_ret = _np_message_serialize_chunked(context, write_msg);
    cr_assert(true == write_ret,
              "Expected positive result in chunk serialisation");

    write_ret =
        _np_message_serialize_header_and_instructions(context, write_msg);
    cr_assert(true == write_ret, "Expected positive result in serialisation");

    cr_expect(pll_size(write_msg->msg_chunks) == 1,
              "Expected 1 chunk for message");

    // Do the deserialisation
    np_message_t *read_msg = NULL;
    np_new_obj(np_message_t, read_msg);

    bool read_ret = _np_message_deserialize_header_and_instructions(
        read_msg,
        pll_first(write_msg->msg_chunks)->val->msg_part);
    cr_assert(true == read_ret, "Expected positive result in deserialisation");

    // Compare deserialized content with expected
    np_tree_elem_t *testkey_read_from =
        np_tree_find_str(read_msg->instructions, "TESTKEY_FROM");
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
        np_tree_find_str(read_msg->instructions, "TESTKEY_TO");
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

    log_trace_msg(
        LOG_TRACE,
        "end test.serialize_np_message_t_with_dhkey_unchunked_instructions");
  }
}

// TODO: add the appropiate cr_expect() statements to really test the message
// chunking
Test(np_message_t,
     _message_chunk_and_serialize,
     .description = "test the chunking of messages") {
  CTX() {
    log_trace_msg(LOG_TRACE, "start test._message_chunk_and_serialize");
    np_message_t *msg_out = NULL;
    np_new_obj(np_message_t, msg_out);
    char *msg_subject = "this.is.a.test";

    np_dhkey_t my_dhkey = np_dhkey_create_from_hostport("me", "two");

    np_key_t *my_key = NULL;
    np_new_obj(np_key_t, my_key);
    my_key->dhkey = my_dhkey;

    uint16_t   parts              = 0;
    np_dhkey_t test_subject_dhkey = {0};
    np_generate_subject(&test_subject_dhkey,
                        msg_subject,
                        strnlen(msg_subject, 256));
    np_tree_insert_str(msg_out->header,
                       _NP_MSG_HEADER_SUBJECT,
                       np_treeval_new_dhkey(test_subject_dhkey));
    np_tree_insert_str(msg_out->header,
                       _NP_MSG_HEADER_TO,
                       np_treeval_new_dhkey(my_key->dhkey));
    np_tree_insert_str(msg_out->header,
                       _NP_MSG_HEADER_FROM,
                       np_treeval_new_dhkey(my_key->dhkey));

    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_ACK,
                       np_treeval_new_ush(0));
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_ACK_TO,
                       np_treeval_new_s((char *)_np_key_as_str(my_key)));
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_SEQ,
                       np_treeval_new_ul(0));

    char *new_uuid = np_uuid_create(msg_subject, 1, NULL);
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_UUID,
                       np_treeval_new_s(new_uuid));
    free(new_uuid);

    double now = np_time_now();
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_TSTAMP,
                       np_treeval_new_d(now));
    now += 20;
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_TTL,
                       np_treeval_new_d(now));

    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_SEND_COUNTER,
                       np_treeval_new_ush(0));

    // TODO: message part split-up informations
    np_tree_insert_str(msg_out->instructions,
                       _NP_MSG_INST_PARTS,
                       np_treeval_new_iarray(parts, parts));

    char body_payload[51]; //  = (char*) malloc(50 * sizeof(char));
    memset(body_payload, 'b', 50);
    body_payload[50] = '\0';

    for (int16_t i = 0; i < 60; i++) {
      np_tree_insert_int(msg_out->body, i, np_treeval_new_s(body_payload));
    }

    np_tree_elem_t *body_node = np_tree_find_int(msg_out->body, 20);

    _np_message_calculate_chunking(msg_out);
    _np_message_serialize_chunked(context, msg_out);
    _np_message_deserialize_chunked(msg_out);

    np_tree_elem_t *body_node_2 = np_tree_find_int(msg_out->body, 20);

    cr_assert(NULL != body_node_2, "Expected to find data in body");

    log_msg(LOG_DEBUG, " body %s", np_treeval_to_str(body_node_2->val, NULL));

    log_trace_msg(LOG_TRACE, "end test._message_chunk_and_serialize");
  }
}

static int8_t _np_token_cmp_uuid(np_aaatoken_ptr first,
                                 np_aaatoken_ptr second) {
  return memcmp(first->uuid, second->uuid, NP_UUID_BYTES);
}

Test(np_message_t,
     encrypt_decrypt_message,
     .description = "test the encryption/decryption for a message") {
  CTX() {
    np_message_t *msg_out = NULL;
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
    _np_message_calculate_chunking(msg_out);

    bool write_ret = _np_message_serialize_chunked(context, msg_out);
    cr_assert(true == write_ret,
              "Expected positive result in chunk serialisation");

    //    write_ret = _np_message_serialize_header_and_instructions(context,
    //    msg_out); ASSERT(true == write_ret, "Expected positive result in
    //    serialisation");
    cr_assert(pll_size(msg_out->msg_chunks) == 1,
              "Expected 1 chunk for message");

    char *packet;
    np_new_obj(BLOB_1024, packet, ref_obj_creation);
    memcpy(packet,
           pll_first(msg_out->msg_chunks)->val->msg_part,
           MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);

    // Do the deserialisation
    np_message_t *msg_in = NULL;
    np_new_obj(np_message_t, msg_in);

    bool read_ret =
        _np_message_deserialize_header_and_instructions(msg_in, packet);
    cr_assert(true == read_ret, "Expected positive result in deserialisation");

    bool ret = _np_message_deserialize_chunked(msg_in);
    cr_assert(true == ret, "Expected positive result in de-serialisation");

    _np_message_decrypt_payload(msg_in, &session);

    np_tree_elem_t *elem = np_tree_find_str(msg_in->body, "test");
    cr_assert(elem != NULL, "expected tree element to be present");
    // sll_free(np_aaatoken_ptr, token_list);
  }
}
