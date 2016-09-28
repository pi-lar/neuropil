/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 **/
#include <uuid/uuid.h>
#include <assert.h>
#include <stdlib.h>

#include "pthread.h"
#include <criterion/criterion.h>

#include "msgpack/cmp.h"

#include "np_types.h"

#include "np_log.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"

void setup_message(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_MESSAGE;
	np_log_init("test_jrb_impl.log", log_level);

	np_mem_init();
}

void teardown_message(void)
{
	np_log_destroy();
}

TestSuite(np_message_t, .init=setup_message, .fini=teardown_message);

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

	np_tree_elem_t* footer_node = tree_find_str(msg_out->footer, NP_MSG_FOOTER_GARBAGE);

	log_msg(LOG_DEBUG, "properties %s, body %s, garbage size %llu",
			properties_node->val.value.s,
			body_node->val.value.s,
			jrb_get_byte_size(footer_node));

	np_message_deserialize_chunked(msg_out);

	np_tree_elem_t* properties_node_2 = tree_find_int(msg_out->properties, 1);
	np_tree_elem_t* body_node_2 = tree_find_int(msg_out->body, 20);

	log_msg(LOG_DEBUG, "properties %s, body %s",
			properties_node_2->val.value.s,
			body_node_2->val.value.s);
}
