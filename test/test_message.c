//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <uuid/uuid.h>
#include <assert.h>
#include <stdlib.h>

#include "pthread.h"
#include <criterion/criterion.h>

#include "msgpack/cmp.h"

#include "np_types.h"

#include "np_log.h"
#include "np_tree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"

#include "../src/np_jobqueue.c"

void setup_message(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_MESSAGE;
	np_log_init("test_message.log", log_level);

	np_mem_init();
}

void teardown_message(void)
{
	np_log_destroy();
}

TestSuite(np_message_t, .init=setup_message, .fini=teardown_message);


Test(np_message_t, serialize_np_message_t_with_dhkey, .description="test the serialization of a message object with dhkey in body")
{
    // Build source message and necessary data
    np_dhkey_t write_dhkey_from;
    write_dhkey_from.t[0] = 1;
    write_dhkey_from.t[1] = 2;
    write_dhkey_from.t[2] = 3;
    write_dhkey_from.t[3] = 4;
	np_dhkey_t write_dhkey_to;
	write_dhkey_to.t[0] = 5;
	write_dhkey_to.t[1] = 6;
	write_dhkey_to.t[2] = 7;
	write_dhkey_to.t[3] = 8;

	np_key_t* write_from = NULL;
	np_new_obj(np_key_t, write_from);
	write_from->dhkey = write_dhkey_from;
	np_key_t* write_to = NULL;
	np_new_obj(np_key_t, write_to);
	write_to->dhkey = write_dhkey_to;

    np_tree_t* write_tree = make_nptree();
    tree_insert_str(write_tree,"TESTKEY_FROM", new_val_key(write_dhkey_from));
    tree_insert_str(write_tree,"TESTKEY_TO", new_val_key(write_dhkey_to));

    np_message_t* write_msg = NULL;
    np_new_obj(np_message_t, write_msg);
    np_message_create(write_msg, write_to, write_from, "serialize_np_message_t", write_tree);
	tree_insert_str(write_msg->instructions, NP_MSG_INST_PARTS, new_val_iarray(0, 0));

    np_jobargs_t* write_args = _np_job_create_args(write_msg, NULL, NULL);
    cr_assert(NULL != write_args,"Expected to receive jobargs");

    // Do the serialsation
	np_message_calculate_chunking(write_msg);
    np_bool write_ret = np_message_serialize_chunked(write_args);
    cr_assert(TRUE == write_ret, "Expected positive result in serialisation");

    cr_expect(pll_size(write_msg->msg_chunks) == 1, "Expected 1 chunk for message");

	// Do the deserialisation
    np_message_t* read_msg = NULL;
    np_new_obj(np_message_t,read_msg);
    read_msg->msg_chunks = write_msg->msg_chunks;

    np_bool read_ret = np_message_deserialize_chunked(read_msg);
    cr_assert(TRUE == read_ret, "Expected positive result in deserialisation");

	// Compare deserialized content with expected
    np_tree_elem_t* testkey_read_from =  tree_find_str(read_msg->body,"TESTKEY_FROM");
    cr_assert(NULL != testkey_read_from, "Expected to find TESTKEY_FROM key value");

    cr_assert(testkey_read_from->val.type == key_type, "Expected read testkey_read_from to be of type key_type. But is: %"PRIu8, testkey_read_from->val.type);
	cr_expect(testkey_read_from->val.size == sizeof(np_dhkey_t), "Expected testkey_read_from to be of dhkey size. But is: %"PRIu32, testkey_read_from->val.size);

	cr_expect(testkey_read_from->val.value.key.t[0] == 1, "Expected read testkey_read_from value 0 to be the same as predefined, But is: %"PRIu64, testkey_read_from->val.value.key.t[0]);
	cr_expect(testkey_read_from->val.value.key.t[1] == 2, "Expected read testkey_read_from value 1 to be the same as predefined, But is: %"PRIu64, testkey_read_from->val.value.key.t[1]);
	cr_expect(testkey_read_from->val.value.key.t[2] == 3, "Expected read testkey_read_from value 2 to be the same as predefined, But is: %"PRIu64, testkey_read_from->val.value.key.t[2]);
	cr_expect(testkey_read_from->val.value.key.t[3] == 4, "Expected read testkey_read_from value 3 to be the same as predefined, But is: %"PRIu64, testkey_read_from->val.value.key.t[3]);

	np_tree_elem_t* testkey_read_to =  tree_find_str(read_msg->body,"TESTKEY_TO");
    cr_assert(NULL != testkey_read_to, "Expected to find TESTKEY_TO key value");

    cr_assert(testkey_read_to->val.type == key_type, "Expected read testkey_read_to to be of type key_type. But is: %"PRIu8, testkey_read_to->val.type);
	cr_expect(testkey_read_to->val.size == sizeof(np_dhkey_t), "Expected testkey_read_to to be of dhkey size. But is: %"PRIu32, testkey_read_to->val.size);

	cr_expect(testkey_read_to->val.value.key.t[0] == 5, "Expected read testkey_read_to value 0 to be the same as predefined, But is: %"PRIu64, testkey_read_to->val.value.key.t[0]);
	cr_expect(testkey_read_to->val.value.key.t[1] == 6, "Expected read testkey_read_to value 1 to be the same as predefined, But is: %"PRIu64, testkey_read_to->val.value.key.t[1]);
	cr_expect(testkey_read_to->val.value.key.t[2] == 7, "Expected read testkey_read_to value 2 to be the same as predefined, But is: %"PRIu64, testkey_read_to->val.value.key.t[2]);
	cr_expect(testkey_read_to->val.value.key.t[3] == 8, "Expected read testkey_read_to value 3 to be the same as predefined, But is: %"PRIu64, testkey_read_to->val.value.key.t[3]);
}


// TODO: add the appropiate cr_expect() statements to really test the message chunking
Test(np_message_t, _message_chunk_and_serialize, .description="test the chunking of messages")
{
	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	char* msg_subject = "this.is.a.test";

	np_dhkey_t my_dhkey = dhkey_create_from_hostport("me", "two");

	np_key_t* my_key = NULL;
	np_new_obj(np_key_t, my_key);
	my_key->dhkey = my_dhkey;

	uint16_t parts = 0;
	tree_insert_str(msg_out->header, NP_MSG_HEADER_SUBJECT,  new_val_s((char*) msg_subject));
	tree_insert_str(msg_out->header, NP_MSG_HEADER_TO,  new_val_s((char*) _key_as_str(my_key)) );
	tree_insert_str(msg_out->header, NP_MSG_HEADER_FROM, new_val_s((char*) _key_as_str(my_key)) );
	tree_insert_str(msg_out->header, NP_MSG_HEADER_REPLY_TO, new_val_s((char*) _key_as_str(my_key)) );

	tree_insert_str(msg_out->instructions, NP_MSG_INST_ACK, new_val_ush(0));
	tree_insert_str(msg_out->instructions, NP_MSG_INST_ACK_TO, new_val_s((char*) _key_as_str(my_key)) );
	tree_insert_str(msg_out->instructions, NP_MSG_INST_SEQ, new_val_ul(0));

	char* new_uuid = np_create_uuid(msg_subject, 1);
	tree_insert_str(msg_out->instructions, NP_MSG_INST_UUID, new_val_s(new_uuid));
	free(new_uuid);

	double now = ev_time();
	tree_insert_str(msg_out->instructions, NP_MSG_INST_TSTAMP, new_val_d(now));
	now += 20;
	tree_insert_str(msg_out->instructions, NP_MSG_INST_TTL, new_val_d(now));

	tree_insert_str(msg_out->instructions, NP_MSG_INST_SEND_COUNTER, new_val_ush(0));

	// TODO: message part split-up informations
	tree_insert_str(msg_out->instructions, NP_MSG_INST_PARTS, new_val_iarray(parts, parts));

	char prop_payload[30]; //  = (char*) malloc(25 * sizeof(char));
	memset (prop_payload, 'a', 29);
	prop_payload[29] = '\0';

	for (int16_t i = 0; i < 9; i++)
	{
		tree_insert_int(msg_out->properties, i, new_val_s(prop_payload));
	}

	char body_payload[51]; //  = (char*) malloc(50 * sizeof(char));
	memset (body_payload, 'b', 50);
	body_payload[50] = '\0';

	for (int16_t i = 0; i < 60; i++)
	{
		tree_insert_int(msg_out->body, i, new_val_s(body_payload));
	}

	np_tree_elem_t* properties_node = tree_find_int(msg_out->properties, 1);
	np_tree_elem_t* body_node = tree_find_int(msg_out->body, 20);

	np_message_calculate_chunking(msg_out);

	np_jobargs_t args = { .msg=msg_out };
	np_message_serialize_chunked(&args);

	np_message_deserialize_chunked(msg_out);

	np_tree_elem_t* properties_node_2 = tree_find_int(msg_out->properties, 1);
	np_tree_elem_t* body_node_2 = tree_find_int(msg_out->body, 20);

	cr_assert(NULL != properties_node_2 ,"Expected to find data in properties");
	cr_assert(NULL != body_node_2 ,"Expected to find data in body");

	log_msg(LOG_DEBUG, "properties %s, body %s",
			properties_node_2->val.value.s,
			body_node_2->val.value.s);
}
