//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <stdlib.h>

#include "pthread.h"
#include <criterion/criterion.h>

#include "msgpack/cmp.h"

#include "np_types.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_memory.h"

#include "np_message.h"
#include "np_util.h"
#include "np_threads.h"

#include "../src/np_jobqueue.c"

#include "../test_macros.c"

 
TestSuite(np_message_t );


Test(np_message_t, serialize_np_message_t_with_dhkey, .description = "test the serialization of a message object with dhkey in body")
{
    CTX() {
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

        np_key_t* write_from = NULL;
        np_new_obj(np_key_t, write_from);
        write_from->dhkey = write_dhkey_from;
        np_key_t* write_to = NULL;
        np_new_obj(np_key_t, write_to);
        write_to->dhkey = write_dhkey_to;

        np_tree_t* write_tree = np_tree_create();
        np_tree_insert_str(write_tree, "TESTKEY_FROM", np_treeval_new_dhkey(write_dhkey_from));
        np_tree_insert_str(write_tree, "TESTKEY_TO", np_treeval_new_dhkey(write_dhkey_to));

        np_message_t* write_msg = NULL;
        np_new_obj(np_message_t, write_msg);
        _np_message_create(write_msg, write_to->dhkey, write_from->dhkey, "serialize_np_message_t", write_tree);
        np_tree_insert_str(write_msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(0, 0));

        // Do the serialsation
        _np_message_calculate_chunking(write_msg);
        bool write_ret = _np_message_serialize_chunked(write_msg);
        cr_assert(true == write_ret, "Expected positive result in serialisation");

        cr_expect(pll_size(write_msg->msg_chunks) == 1, "Expected 1 chunk for message");

        // Do the deserialisation
        np_message_t* read_msg = NULL;
        np_new_obj(np_message_t, read_msg);
        read_msg->msg_chunks = write_msg->msg_chunks;

        bool read_ret = _np_message_deserialize_chunked(read_msg);
        cr_assert(true == read_ret, "Expected positive result in de-serialisation");

        // Compare deserialized content with expected
        np_tree_elem_t* testkey_read_from = np_tree_find_str(read_msg->body, "TESTKEY_FROM");
        cr_assert(NULL != testkey_read_from, "Expected to find TESTKEY_FROM key value");

        cr_assert(testkey_read_from->val.type == np_treeval_type_dhkey, "Expected read testkey_read_from to be of type np_treeval_type_dhkey. But is: %"PRIu8, testkey_read_from->val.type);
        cr_expect(testkey_read_from->val.size == sizeof(np_dhkey_t), "Expected testkey_read_from to be of dhkey size. But is: %"PRIu32, testkey_read_from->val.size);

        cr_expect(testkey_read_from->val.value.dhkey.t[0] == 1, "Expected read testkey_read_from value 0 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[0]);
        cr_expect(testkey_read_from->val.value.dhkey.t[1] == 2, "Expected read testkey_read_from value 1 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[1]);
        cr_expect(testkey_read_from->val.value.dhkey.t[2] == 3, "Expected read testkey_read_from value 2 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[2]);
        cr_expect(testkey_read_from->val.value.dhkey.t[3] == 4, "Expected read testkey_read_from value 3 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[3]);

        np_tree_elem_t* testkey_read_to = np_tree_find_str(read_msg->body, "TESTKEY_TO");
        cr_assert(NULL != testkey_read_to, "Expected to find TESTKEY_TO key value");

        cr_assert(testkey_read_to->val.type == np_treeval_type_dhkey, "Expected read testkey_read_to to be of type np_treeval_type_dhkey. But is: %"PRIu8, testkey_read_to->val.type);
        cr_expect(testkey_read_to->val.size == sizeof(np_dhkey_t), "Expected testkey_read_to to be of dhkey size. But is: %"PRIu32, testkey_read_to->val.size);

        cr_expect(testkey_read_to->val.value.dhkey.t[0] == 5, "Expected read testkey_read_to value 0 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[0]);
        cr_expect(testkey_read_to->val.value.dhkey.t[1] == 6, "Expected read testkey_read_to value 1 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[1]);
        cr_expect(testkey_read_to->val.value.dhkey.t[2] == 7, "Expected read testkey_read_to value 2 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[2]);
        cr_expect(testkey_read_to->val.value.dhkey.t[3] == 8, "Expected read testkey_read_to value 3 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[3]);

        log_trace_msg(LOG_TRACE, "end test.serialize_np_message_t_with_dhkey");
    }
}

Test(np_message_t, serialize_np_message_t_with_dhkey_unchunked_instructions, .description = "test the serialization of a message object with dhkey in body")
{
    CTX() {
        log_trace_msg(LOG_TRACE, "start test.serialize_np_message_t_with_dhkey_unchunked_instructions");

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

        np_key_t* write_from = NULL;
        np_new_obj(np_key_t, write_from);
        write_from->dhkey = write_dhkey_from;
        np_key_t* write_to = NULL;
        np_new_obj(np_key_t, write_to);
        write_to->dhkey = write_dhkey_to;

        np_message_t* write_msg = NULL;
        np_new_obj(np_message_t, write_msg);

        np_tree_t* write_tree = np_tree_create();
        np_tree_insert_str(write_tree, "TESTKEY_FROM", np_treeval_new_dhkey(write_dhkey_from));
        np_tree_insert_str(write_tree, "TESTKEY_TO", np_treeval_new_dhkey(write_dhkey_to));

        np_tree_insert_str(write_msg->instructions, "TESTKEY_FROM", np_treeval_new_dhkey(write_dhkey_from));
        np_tree_insert_str(write_msg->instructions, "TESTKEY_TO", np_treeval_new_dhkey(write_dhkey_to));

        _np_message_create(write_msg, write_to->dhkey, write_from->dhkey, "serialize_np_message_t", write_tree);
        np_tree_insert_str(write_msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(0, 0));

        np_jobargs_t write_args = _np_job_create_args(context, write_msg, NULL, NULL, "tst");
        

        // Do the serialsation
        _np_message_calculate_chunking(write_msg);
        bool write_ret = _np_message_serialize_chunked(write_args.msg);
        cr_assert(true == write_ret, "Expected positive result in chunk serialisation");

        write_ret = _np_message_serialize_header_and_instructions(context, write_args);
        cr_assert(true == write_ret, "Expected positive result in serialisation");

        cr_expect(pll_size(write_msg->msg_chunks) == 1, "Expected 1 chunk for message");

        // Do the deserialisation
        np_message_t* read_msg = NULL;
        np_new_obj(np_message_t, read_msg);

        bool read_ret = _np_message_deserialize_header_and_instructions(read_msg, pll_first(write_msg->msg_chunks)->val->msg_part);
        cr_assert(true == read_ret, "Expected positive result in deserialisation");

        // Compare deserialized content with expected
        np_tree_elem_t* testkey_read_from = np_tree_find_str(read_msg->instructions, "TESTKEY_FROM");
        cr_assert(NULL != testkey_read_from, "Expected to find TESTKEY_FROM key value");

        cr_assert(testkey_read_from->val.type == np_treeval_type_dhkey, "Expected read testkey_read_from to be of type np_treeval_type_dhkey. But is: %"PRIu8, testkey_read_from->val.type);
        cr_expect(testkey_read_from->val.size == sizeof(np_dhkey_t), "Expected testkey_read_from to be of dhkey size. But is: %"PRIu32, testkey_read_from->val.size);

        cr_expect(testkey_read_from->val.value.dhkey.t[0] == 1, "Expected read testkey_read_from value 0 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[0]);
        cr_expect(testkey_read_from->val.value.dhkey.t[1] == 2, "Expected read testkey_read_from value 1 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[1]);
        cr_expect(testkey_read_from->val.value.dhkey.t[2] == 3, "Expected read testkey_read_from value 2 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[2]);
        cr_expect(testkey_read_from->val.value.dhkey.t[3] == 4, "Expected read testkey_read_from value 3 to be the same as predefined, But is: %"PRIu32, testkey_read_from->val.value.dhkey.t[3]);

        np_tree_elem_t* testkey_read_to = np_tree_find_str(read_msg->instructions, "TESTKEY_TO");
        cr_assert(NULL != testkey_read_to, "Expected to find TESTKEY_TO key value");

        cr_assert(testkey_read_to->val.type == np_treeval_type_dhkey, "Expected read testkey_read_to to be of type np_treeval_type_dhkey. But is: %"PRIu8, testkey_read_to->val.type);
        cr_expect(testkey_read_to->val.size == sizeof(np_dhkey_t), "Expected testkey_read_to to be of dhkey size. But is: %"PRIu32, testkey_read_to->val.size);

        cr_expect(testkey_read_to->val.value.dhkey.t[0] == 5, "Expected read testkey_read_to value 0 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[0]);
        cr_expect(testkey_read_to->val.value.dhkey.t[1] == 6, "Expected read testkey_read_to value 1 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[1]);
        cr_expect(testkey_read_to->val.value.dhkey.t[2] == 7, "Expected read testkey_read_to value 2 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[2]);
        cr_expect(testkey_read_to->val.value.dhkey.t[3] == 8, "Expected read testkey_read_to value 3 to be the same as predefined, But is: %"PRIu32, testkey_read_to->val.value.dhkey.t[3]);

        log_trace_msg(LOG_TRACE, "end test.serialize_np_message_t_with_dhkey_unchunked_instructions");
    }
}


// TODO: add the appropiate cr_expect() statements to really test the message chunking
Test(np_message_t, _message_chunk_and_serialize, .description = "test the chunking of messages")
{
    CTX() {
        log_trace_msg(LOG_TRACE, "start test._message_chunk_and_serialize");
        np_message_t* msg_out = NULL;
        np_new_obj(np_message_t, msg_out);
        char* msg_subject = "this.is.a.test";

        np_dhkey_t my_dhkey = np_dhkey_create_from_hostport( "me", "two");

        np_key_t* my_key = NULL;
        np_new_obj(np_key_t, my_key);
        my_key->dhkey = my_dhkey;

        uint16_t parts = 0;
        np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_SUBJECT, np_treeval_new_s((char*)msg_subject));
        np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_TO, np_treeval_new_dhkey(my_key->dhkey));
        np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_FROM, np_treeval_new_dhkey(my_key->dhkey));

        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(0));
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s((char*)_np_key_as_str(my_key)));
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));

        char* new_uuid = np_uuid_create(msg_subject, 1, NULL);
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(new_uuid));
        free(new_uuid);

        double now = np_time_now();
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
        now += 20;
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(now));

        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));

        // TODO: message part split-up informations
        np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(parts, parts));

        char body_payload[51]; //  = (char*) malloc(50 * sizeof(char));
        memset(body_payload, 'b', 50);
        body_payload[50] = '\0';

        for (int16_t i = 0; i < 60; i++)
        {
            np_tree_insert_int(msg_out->body, i, np_treeval_new_s(body_payload));
        }

        np_tree_elem_t* body_node = np_tree_find_int(msg_out->body, 20);

        _np_message_calculate_chunking(msg_out);

        _np_message_serialize_chunked(msg_out);

        _np_message_deserialize_chunked(msg_out);

        np_tree_elem_t* body_node_2 = np_tree_find_int(msg_out->body, 20);

        cr_assert(NULL != body_node_2, "Expected to find data in body");

        log_msg(LOG_DEBUG, " body %s",
            np_treeval_to_str(body_node_2->val, NULL));

        log_trace_msg(LOG_TRACE, "end test._message_chunk_and_serialize");
    }
}