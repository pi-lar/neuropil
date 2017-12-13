//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <uuid/uuid.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include "pthread.h"
#include "event/ev.h"
#include "msgpack/cmp.h"

#include "dtime.h"
#include "np_treeval.h"
#include "np_log.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"


int main(int argc, char **argv) {

	char log_file[256];
	sprintf(log_file, "%s.log", "./test_chunk_message");
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_MESSAGE;
	log_init(log_file, level);

	np_mem_init();

	np_message_t* msg_out = NULL;
	np_new_obj(np_message_t, msg_out);
	char* msg_subject = "this.is.a.test";

	np_dhkey_t my_dhkey = np_dhkey_create_from_hostport("me", "two");

	np_key_t* my_key = NULL;
	np_new_obj(np_key_t, my_key);
	my_key->dhkey = my_dhkey;

	uint16_t parts = 0;
	np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_SUBJECT,  np_treeval_new_s((char*) msg_subject));
	np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_TO,  np_treeval_new_s((char*) _np_key_as_str(my_key)) );
	np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_FROM, np_treeval_new_s((char*) _np_key_as_str(my_key)) );
	np_tree_insert_str(msg_out->header, _NP_MSG_HEADER_REPLY_TO, np_treeval_new_s((char*) _np_key_as_str(my_key)) );

	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(0));
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_ACK_TO, np_treeval_new_s((char*) _np_key_as_str(my_key)) );
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));

	char* new_uuid = np_uuid_create(msg_subject, 1);
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(new_uuid));
	free(new_uuid);

	double now = np_time_now();
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
	now += 20;
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(now));

	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));

	// TODO: message part split-up informations
	np_tree_insert_str(msg_out->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(parts, parts));

	char prop_payload[30]; //  = (char*) malloc(25 * sizeof(char));
	memset (prop_payload, 'a', 29);
	prop_payload[29] = '\0';

	for (int16_t i = 0; i < 9; i++)
	{
		np_tree_insert_int(msg_out->properties, i, np_treeval_new_s(prop_payload));
	}

	char body_payload[51]; //  = (char*) malloc(50 * sizeof(char));
	memset (body_payload, 'b', 50);
	body_payload[50] = '\0';

	for (int16_t i = 0; i < 60; i++)
	{
		np_tree_insert_int(msg_out->body, i, np_treeval_new_s(body_payload));
	}

	np_tree_elem_t* properties_node = np_tree_find_int(msg_out->properties, 1);
	np_tree_elem_t* body_node = np_tree_find_int(msg_out->body, 20);

 
	/** message split up maths
	 ** message size = 1b (common header) + 40b (encryption) +
	 **                msg (header + instructions) + msg (properties + body) + msg (footer)
	 ** if (size > 1024)
	 **     fixed_size = 1b + 40b + msg (header + instructions)
	 **     payload_size = msg (properties) + msg(body) + msg(footer)
	 **     #_of_chunks = int(payload_size / (1024 - fixed_size)) + 1
	 **     chunk_size = payload_size / #_of_chunks
	 **     garbage_size = #_qof_chunks * (fixed_size + chunk_size) % 1024 // spezial behandlung garbage_size < 3
	 **     add garbage
	 ** else
	 ** 	add garbage
	 **/
	_np_message_calculate_chunking(msg_out);
	_np_message_serialize_chunked(msg_out);
	np_tree_elem_t* footer_node = np_tree_find_str(msg_out->footer, NP_MSG_FOOTER_GARBAGE);
	log_msg(LOG_DEBUG, "properties %s, body %s, garbage size %"PRIu32,
			 np_treeval_to_str(properties_node->val),
			 np_treeval_to_str(body_node->val),
			np_tree_get_byte_size(footer_node));


	_np_message_deserialize_chunked(msg_out);

	np_tree_elem_t* properties_node_2 = np_tree_find_int(msg_out->properties, 1);
	np_tree_elem_t* body_node_2 = np_tree_find_int(msg_out->body, 20);
	// np_tree_elem_t* footer_node_2 = np_tree_find_str(msg_out->footer, NP_MSG_FOOTER_GARBAGE);
	log_msg(LOG_DEBUG, "properties %s, body %s",
			 np_treeval_to_str(properties_node_2->val),
			 np_treeval_to_str(body_node_2->val));

	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}
