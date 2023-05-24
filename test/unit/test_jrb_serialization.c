//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../test_macros.c"
#include "event/ev.h"
#include "sodium.h"

#include "neuropil_log.h"

#include "../src/np_util.c"
#include "util/np_serialization.h"
#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_dhkey.h"
#include "np_jobqueue.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"

uint32_t total_write_count = 0;
uint32_t total_read_count  = 0;

void reset_buffer_counter() {
  total_write_count = 0;
  total_read_count  = 0;
}

#ifdef NP_USE_CMP
#include "./test_jrb_serialization_cmp.c"
#endif

#ifdef NP_USE_QCBOR
#include "./test_jrb_serialization_qcbor.c"
#endif

TestSuite(test_serialization);

Test(test_serialization,
     serialize_np_dhkey_t_in_np_tree_t,
     .description = "test the serialization of a dhkey in a tree") {
  CTX() {

    size_t buffer_size = 1024;
    char   buffer[buffer_size];
    void  *buffer_ptr = buffer;

    cr_log_info("buffer_ptr\t\t %p\n", buffer_ptr);
    memset(buffer_ptr, 0, buffer_size);
    reset_buffer_counter();

    np_dhkey_t tst;
    tst.t[0] = 1;
    tst.t[1] = 2;
    tst.t[2] = 3;
    tst.t[3] = 4;
    tst.t[4] = 5;
    tst.t[5] = 6;
    tst.t[6] = 7;
    tst.t[7] = 8;
    np_dhkey_t tst2;
    tst2.t[0] = 5;
    tst2.t[1] = 6;
    tst2.t[2] = 7;
    tst2.t[3] = 8;
    tst2.t[4] = 9;
    tst2.t[5] = 10;
    tst2.t[6] = 11;
    tst2.t[7] = 12;

    np_tree_t *write_tree = np_tree_create();
    np_tree_insert_str(write_tree, "TESTKEY", np_treeval_new_dhkey(tst));

    cr_expect(total_write_count == 0,
              "Expected empty buffer. But size is %" PRIu32,
              total_write_count);

    size_t expected_write_size = np_tree_get_byte_size(write_tree);
    //     np_serializer_add_map_bytesize(write_tree, &expected_write_size);

    np_serialize_buffer_t serializer_1 = {
        ._tree          = write_tree,
        ._target_buffer = buffer_ptr,
        ._buffer_size   = buffer_size,
        ._error         = 0,
        ._bytes_written = 0,
    };
    np_serializer_write_map(context, &serializer_1, write_tree);

    cr_assert(serializer_1._error == 0,
              "expect no error on write. But is: %" PRIu8,
              serializer_1._error);

    cr_expect(serializer_1._bytes_written == expected_write_size,
              "Expected write size is %" PRIu32 " but is %" PRIu32,
              expected_write_size,
              serializer_1._bytes_written);

    // Beginn reading section
    uint32_t expected_read_count = expected_write_size;
    reset_buffer_counter();

    np_tree_t              *read_tree    = np_tree_create();
    np_deserialize_buffer_t deserializer = {
        ._target_tree = read_tree,
        ._buffer      = buffer,
        ._buffer_size = expected_read_count,
        ._error       = 0,
        ._bytes_read  = 0,
    };
    np_serializer_read_map(context, &deserializer, read_tree);

    cr_assert(deserializer._error == 0,
              "Expected no error on val read. But is: %" PRIu8,
              deserializer._error);
    cr_expect(deserializer._bytes_read == expected_read_count,
              "Expected read size is %" PRIu32 " but is %" PRIu32,
              expected_read_count,
              deserializer._bytes_read);

    np_tree_elem_t *testkey_read = np_tree_find_str(read_tree, "TESTKEY");

    cr_assert(NULL != testkey_read, "Expected to find TESTKEY key value");

    cr_expect(testkey_read->val.type == np_treeval_type_dhkey,
              "Expected read val to be of type np_treeval_type_dhkey. But is: "
              "%" PRIu8,
              testkey_read->val.type);
    cr_expect(testkey_read->val.size == sizeof(np_dhkey_t),
              "Expected val to be of dhkey size. But is: %" PRIu32,
              testkey_read->val.size);

    cr_expect(testkey_read->val.value.dhkey.t[0] == 1,
              "Expected read val value 0 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[0]);
    cr_expect(testkey_read->val.value.dhkey.t[1] == 2,
              "Expected read val value 1 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[1]);
    cr_expect(testkey_read->val.value.dhkey.t[2] == 3,
              "Expected read val value 2 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[2]);
    cr_expect(testkey_read->val.value.dhkey.t[3] == 4,
              "Expected read val value 3 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[3]);
    cr_expect(testkey_read->val.value.dhkey.t[4] == 5,
              "Expected read val value 4 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[4]);
    cr_expect(testkey_read->val.value.dhkey.t[5] == 6,
              "Expected read val value 5 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[5]);
    cr_expect(testkey_read->val.value.dhkey.t[6] == 7,
              "Expected read val value 6 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[6]);
    cr_expect(testkey_read->val.value.dhkey.t[7] == 8,
              "Expected read val value 7 to be the same as predefined, But is: "
              "%" PRIu32,
              testkey_read->val.value.dhkey.t[7]);
  }
}

// 		special strings are not supported at the moment
/*
Test(test_serialization, _np_tree_special_str, .description = "test the
implementation of special strings in the tree implementation")
{
        CTX() {
                uint8_t idx = 254;
                char* tmp;
                uint32_t tmp2;

                cr_expect(_np_tree_is_special_str("np.test1", &idx) == false,
"expecting np.test1 to be no special string"); cr_expect(idx == 254, "expecting
index to be the same");

                cr_assert(_np_tree_is_special_str("np.test2", &idx) == true,
"expecting np.test2 to be a special string"); cr_expect(idx == 0, "expecting
np.test2 to be at position 0 and not %"PRIu8, idx); cr_expect(strcmp("np.test2",
(tmp = _np_tree_get_special_str(idx))) == 0, "expecting retunred special string
to be np.test2 and not %s", tmp);

                cr_expect(_np_tree_is_special_str("np.test3", &idx) == true,
"expecting np.test3 to be a special string"); cr_expect(idx == 2, "expecting
np.test3 to be at position 2"); cr_expect(strcmp("np.test3", (tmp =
_np_tree_get_special_str(idx))) == 0, "expecting retunred special string to be
np.test3 and not %s", tmp);


                np_tree_t* tst = np_tree_create();
                np_tree_elem_t*  ele;

                np_tree_insert_str(tst, "np.test3",
np_treeval_new_s("np.test2")); ele = np_tree_find_str(tst, "np.test3");
                cr_assert(ele != NULL, "Expect to find a element");
                cr_expect(ele->key.type == np_treeval_type_special_char_ptr,
"Expect key of element to be from type np_treeval_type_special_char_ptr");
                cr_expect(ele->key.value.ush == 2, "Expect type index to be 2");

                cr_expect(ele->val.type == np_treeval_type_special_char_ptr,
"Expect value of element to be from type np_treeval_type_special_char_ptr");
                cr_expect(ele->val.value.ush == 0, "Expect type index to be 0
but is %"PRIu8, ele->val.value.ush);

                cr_expect(4 < (tmp2 =
np_tree_element_get_byte_size(tst->rbh_root)), "expect byte size to be 4 but is
%"PRIu32, tmp2);

                np_tree_insert_str(tst, "np.test2", np_treeval_new_s("1234"));
                ele = np_tree_find_str(tst, "np.test2");
                cr_assert(ele != NULL, "Expect to find a element");
                cr_expect(ele->key.type == np_treeval_type_special_char_ptr,
"Expect key of element to be from type np_treeval_type_special_char_ptr");
                cr_expect(ele->key.value.ush == 0, "Expect type index to be 0");
                cr_expect(ele->val.type == np_treeval_type_char_ptr, "Expect
value of element to be from type np_treeval_type_char_ptr");
                cr_expect(strcmp("1234", np_treeval_to_str(ele->val, NULL)) ==
0, "expecting special string to be 1234");

                cr_expect(0 < np_tree_element_get_byte_size(tst->rbh_root),
"expect byte size to be not 0");

                np_tree_free(tst);
        }
}
*/

Test(test_serialization,
     np_tree_serialize,
     .description = "test the serialization of a  jtree") {
  CTX() {
    np_tree_t      *test_jrb_1 = np_tree_create();
    uint32_t        tmp32;
    uint16_t        tmp16;
    uint8_t         tmp8;
    np_tree_elem_t *tmpEle;

    cr_expect(NULL != test_jrb_1, "expect test_jrb_1 pointer to exists");
    cr_expect(NULL == test_jrb_1->rbh_root, "expect rbh_root to be NULL");
    cr_expect(0 == test_jrb_1->size, "expect size of tree to be 0");
    cr_expect(0 == test_jrb_1->byte_size, "expect minimum byte size to be 5");

    size_t buffer_size = 65536;
    char   empty_buffer[buffer_size];
    void  *empty_buf_ptr = empty_buffer;
    memset(empty_buf_ptr, 0, buffer_size);

    np_serialize_buffer_t serializer_1 = {
        ._tree          = test_jrb_1,
        ._target_buffer = empty_buffer,
        ._buffer_size   = buffer_size,
        ._error         = 0,
        ._bytes_written = 0,
    };
    np_serializer_write_map(context, &serializer_1, test_jrb_1);

    // np_jrb_t* node = NULL;
    // cmp_write_array(&cmp_empty, 1);
    // if (!cmp_write_map(&cmp_empty, test_jrb->size*2 )) log_msg(LOG_WARNING,
    // cmp_strerror(&cmp_empty)); node = test_jrb; log_msg(LOG_DEBUG, "for %p;
    // %p!=%p; %p=%p", test_jrb->flink, node, test_jrb, node, node->flink);
    //    jrb_traverse(node, test_jrb) {
    //        log_msg(LOG_INFO, "serializing now: %s",
    //        np_treeval_to_str(node->key)); _np_tree_serialize(context, node,
    //        &cmp_empty);
    //    }
    // free (empty_buffer);
    // np_free_tree(test_jrb_1);
    np_tree_insert_str(test_jrb_1, "halli", np_treeval_new_s("galli"));
    cr_expect(1 == test_jrb_1->size, "expect size of tree to be 1");
    // cr_expect(22 == np_tree_element_get_byte_size(test_jrb_1->rbh_root),
    // "expect byte size to be 22"); cr_expect(27 == test_jrb_1->byte_size,
    // "expect byte size to be 27");

    np_tree_insert_str(test_jrb_1, "hallo", np_treeval_new_s("gulli"));
    cr_expect(2 == test_jrb_1->size, "expect size of tree to be 2");
    // cr_expect(22 == np_tree_element_get_byte_size(test_jrb_1->rbh_root),
    // "expect byte size to be 22"); cr_expect(49 == test_jrb_1->byte_size,
    // "expect byte size to be 49");

    np_tree_t *test_jrb_2 = np_tree_create();
    cr_expect(0 == test_jrb_2->size, "expect size of tree to be 0");

    char *from = "from";
    char *to   = "to";
    char *id   = "id";
    char *exp  = "exp";
    char *mail = "mail";

    char *me     = "me";
    char *you    = "you";
    char *mail_t = "signed.by.me@test.de";

    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    np_tree_insert_str(test_jrb_2, from, np_treeval_new_s(me));
    cr_expect(1 == test_jrb_2->size, "expect size of tree to be 1");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    np_tree_insert_str(test_jrb_2, to, np_treeval_new_s(you));
    cr_expect(2 == test_jrb_2->size, "expect size of tree to be 2");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    np_tree_insert_str(test_jrb_2, id, np_treeval_new_i(18000));
    cr_expect(3 == test_jrb_2->size, "expect size of tree to be 3");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    np_tree_insert_str(test_jrb_2, exp, np_treeval_new_d(5.0));
    cr_expect(4 == test_jrb_2->size, "expect size of tree to be 4");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    np_tree_insert_str(test_jrb_2, mail, np_treeval_new_s(mail_t));
    cr_expect(5 == test_jrb_2->size, "expect size of tree to be 5");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
#ifdef x64
    np_tree_insert_str(test_jrb_2,
                       "ull",
                       np_treeval_new_ull(4905283925042198132));
    cr_expect(6 == test_jrb_2->size, "expect size of tree to be 6");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
#else
    np_tree_insert_str(test_jrb_2, mail_t, np_treeval_new_s(mail_t));
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);
    cr_expect(6 == test_jrb_2->size, "expect size of tree to be 6");
#endif
    np_tree_insert_str(test_jrb_2, "tree_1", np_treeval_new_tree(test_jrb_1));
    cr_expect(7 == test_jrb_2->size, "expect size of tree to be 7");
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);

    np_tree_insert_str(test_jrb_2, "np.test2", np_treeval_new_s("test"));
    cr_expect(8 == (tmp16 = test_jrb_2->size),
              "expect size of tree to be 8 but is %" PRIu16,
              tmp16);
    log_msg(LOG_INFO,
            "test jrb has size: %d %lu",
            test_jrb_2->size,
            test_jrb_2->byte_size);

    // log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb->size,
    // test_jrb->byte_size);
    log_msg(LOG_INFO, "----------------------");
    log_msg(LOG_INFO, "serializing message:  ");

    void *buffer = malloc(buffer_size);
    memset(buffer, 0, buffer_size);

    np_serialize_buffer_t serializer_2 = {
        ._tree          = test_jrb_2,
        ._target_buffer = buffer,
        ._buffer_size   = buffer_size,
        ._error         = 0,
        ._bytes_written = 0,
    };
    np_serializer_write_map(context, &serializer_2, test_jrb_2);
    cr_expect((tmp8 = serializer_2._error) == 0,
              "Expect no error in serialisation (error: %" PRIu8 ")",
              tmp8);

    np_tree_t              *out_jrb      = np_tree_create();
    np_deserialize_buffer_t deserializer = {
        ._target_tree = out_jrb,
        ._buffer      = buffer,
        ._buffer_size = buffer_size,
        ._error       = 0,
        ._bytes_read  = 0,
    };
    np_serializer_read_map(context, &deserializer, out_jrb);

    cr_expect((tmp8 = deserializer._error) == 0,
              "Expect no error in deserialisation (error: %" PRIu8 ")",
              tmp8);

    //    tmpEle = np_tree_find_str(out_jrb, "np.test2");
    //
    //    cr_expect(tmpEle != NULL, "Expect to find element np.test2");
    //    cr_expect(tmpEle->key.type == np_treeval_type_special_char_ptr,
    //    "Expect element key to be of type np_treeval_type_special_char_ptr");
    //    cr_expect(tmpEle->key.value.ush == 0, "Expect element key to be the
    //    same"); cr_expect(tmpEle->val.type == np_treeval_type_char_ptr,
    //    "Expect element value to be of type np_treeval_type_char_ptr");
    //    cr_expect(strcmp(np_treeval_to_str(tmpEle->val, NULL), "test") == 0,
    //    "Expect element value to be the same");

    cr_expect(out_jrb->size == 8,
              "deserialized tree is: %p (size %d)",
              out_jrb,
              out_jrb->size);
    log_msg(LOG_INFO,
            "deserialized tree is: %p (size %d)",
            out_jrb,
            out_jrb->size);

    cr_expect(18000 == np_tree_find_str(out_jrb, "id")->val.value.i,
              "id: %d",
              np_tree_find_str(out_jrb, "id")->val.value.i);
    log_msg(LOG_INFO, "id: %d", np_tree_find_str(out_jrb, "id")->val.value.i);

    log_msg(LOG_INFO,
            "from: %s",
            np_tree_find_str(out_jrb, "from")->val.value.s);
    log_msg(LOG_INFO,
            "mail: %s",
            np_tree_find_str(out_jrb, "mail")->val.value.s);
    log_msg(LOG_INFO, "to: %s", np_tree_find_str(out_jrb, "to")->val.value.s);
    log_msg(LOG_INFO, "exp: %f", np_tree_find_str(out_jrb, "exp")->val.value.d);

#ifdef x64
    log_msg(LOG_INFO,
            "ul: %lu",
            np_tree_find_str(out_jrb, "ull")->val.value.ull);
#endif

    np_tree_t *test_ex = np_tree_find_str(out_jrb, "tree_1")->val.value.tree;
    log_msg(LOG_INFO, "tree_1: %p", test_ex);
    cr_expect(0 == strncmp(np_tree_find_str(test_ex, "halli")->val.value.s,
                           "galli",
                           5),
              "expect the key/value halli/galli to be in the map");
    log_msg(LOG_INFO,
            "tree_1/halli: %s",
            np_tree_find_str(test_ex, "halli")->val.value.s);
    cr_expect(0 == strncmp(np_tree_find_str(test_ex, "hallo")->val.value.s,
                           "gulli",
                           5),
              "expect the key/value halli/gulli to be in the map");
    log_msg(LOG_INFO,
            "tree_1/hallo: %s",
            np_tree_find_str(test_ex, "hallo")->val.value.s);

    log_msg(LOG_INFO, "----------------------");
    log_msg(LOG_INFO,
            "out jrb has size: %d %d",
            out_jrb->size,
            out_jrb->byte_size);
    log_msg(LOG_INFO, "removing entries from jrb message:");

    np_tree_del_str(out_jrb, "from");
    np_tree_elem_t *test = np_tree_find_str(out_jrb, "from");
    if (test == NULL) log_msg(LOG_INFO, "deleted node not found");
    log_msg(LOG_INFO,
            "out jrb has size: %d %d",
            out_jrb->size,
            out_jrb->byte_size);
  }
}

Test(test_serialization,
     np_token_serialization,
     .description = "test the serialization of a np_token") {}

Test(test_serialization,
     np_ed25519_serialization,
     .description =
         "test the serialization of a ed25519 public/private key pair") {
  CTX() {
    char            null_block[NP_SECRET_KEY_BYTES] = {0};
    struct np_token identity_token                  = {0};
    np_id           fingerprint                     = {0};

    double expiry_ts = np_time_now() + 3600;
    identity_token   = np_new_identity(context, expiry_ts, NULL);

    cr_expect(0 != memcmp(&identity_token.secret_key,
                          &null_block,
                          NP_SECRET_KEY_BYTES),
              "expect the secret key to contain a value");
    cr_expect(
        np_ok ==
            np_token_fingerprint(context, identity_token, false, &fingerprint),
        "expect the creation of the fingerprint to be successful");

    size_t max_buffer_size = 10240;
    char   buffer[max_buffer_size];
    cr_expect(true == np_serializer_write_ed25519(&identity_token.secret_key,
                                                  &identity_token.public_key,
                                                  true,
                                                  &fingerprint,
                                                  &buffer,
                                                  &max_buffer_size),
              "expect the serialization to be successful");

    struct np_token copy_of_id = {0};
    np_id           copy_of_fp = {0};
    cr_expect(true == np_serializer_read_ed25519(&buffer,
                                                 &max_buffer_size,
                                                 &copy_of_fp,
                                                 &copy_of_id.secret_key,
                                                 &copy_of_id.public_key),
              "expect the serialization to be successful");

    cr_expect(0 == memcmp(&fingerprint, &copy_of_fp, NP_FINGERPRINT_BYTES),
              "expect the secret keys to match");
    cr_expect(0 == memcmp(copy_of_id.secret_key,
                          identity_token.secret_key,
                          NP_SECRET_KEY_BYTES),
              "expect the secret keys to match");
    cr_expect(0 == memcmp(&copy_of_id.public_key,
                          &identity_token.public_key,
                          NP_PUBLIC_KEY_BYTES),
              "expect the secret keys to match");
  }
}

Test(neuropil_h,
     np_encrypted_container_serialization,
     .description = "test the serialization of a np_token") {
  CTX() {
    size_t buffer_size = 240;
    char   buffer[buffer_size];

    char nonce[crypto_box_NONCEBYTES] = {0};
    randombytes_buf(nonce, crypto_box_NONCEBYTES);

    char message[] = "exampleencryptedttextwithhiddenmessage.gofindit,youfool!";
    size_t message_len = sizeof(message);

    cr_expect(true == np_serializer_write_encrypted(buffer,
                                                    &buffer_size,
                                                    nonce,
                                                    message,
                                                    message_len),
              "expect the encrypted writing to be succesfull");

    char new_nonce[crypto_box_NONCEBYTES] = {0};
    char new_message[message_len];
    memset(new_message, 0, message_len);

    cr_expect(true == np_serializer_read_encrypted(buffer,
                                                   &buffer_size,
                                                   new_nonce,
                                                   new_message,
                                                   &message_len),
              "expect the encrypted writing to be succesfull");
    cr_expect(0 == memcmp(nonce, new_nonce, crypto_box_NONCEBYTES),
              "expect the nonce to be the same");
    cr_expect(0 == memcmp(message, new_message, message_len),
              "expect the messages to be the same");
  }
}
