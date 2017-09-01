//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <uuid/uuid.h>
#include <assert.h>
#include <stdlib.h>
#include "pthread.h"

#include "msgpack/cmp.h"

#include "np_log.h"
#include "np_treeval.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"


int main(int argc, char **argv) {

	char log_file[256];
	sprintf(log_file, "%s.log", "./jrb_test_msg");
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORK | LOG_KEY;
	log_init(log_file, level);

	np_tree_t* test_jrb_1 = np_tree_create();

	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_1->size, test_jrb_1->byte_size);
	cmp_ctx_t cmp_empty;
	char empty_buffer[65536];
	void* empty_buf_ptr = empty_buffer;
	memset(empty_buf_ptr, 0, 65536);

	cmp_init(&cmp_empty, empty_buf_ptr, _np_buffer_reader, _np_buffer_writer);
	_np_tree_serialize(test_jrb_1, &cmp_empty);

	// np_jrb_t* node = NULL;
	// cmp_write_array(&cmp_empty, 1);
	// if (!cmp_write_map(&cmp_empty, test_jrb->size*2 )) log_msg(LOG_WARN, cmp_strerror(&cmp_empty));
	// node = test_jrb;
	// log_msg(LOG_DEBUG, "for %p; %p!=%p; %p=%p", test_jrb->flink, node, test_jrb, node, node->flink);
	//	jrb_traverse(node, test_jrb) {
	//		log_msg(LOG_INFO, "serializing now: %s", node->key.value.s);
	//		_np_tree_serialize(node, &cmp_empty);
	//	}
	// free (empty_buffer);
	// np_free_tree(test_jrb_1);
	jrb_insert_str(test_jrb_1, "halli", new_jval_s("galli"));
	jrb_insert_str(test_jrb_1, "hallo", new_jval_s("gulli"));

	np_tree_t* test_jrb_2 = np_tree_create();
	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	jrb_insert_str(test_jrb_2, from, new_jval_s(me));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	jrb_insert_str(test_jrb_2, to,   new_jval_s(you));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	jrb_insert_str(test_jrb_2, id,   new_jval_i(18000));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	jrb_insert_str(test_jrb_2, exp,  new_jval_d(5.0));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	jrb_insert_str(test_jrb_2, mail, new_jval_s(mail_t));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	jrb_insert_str(test_jrb_2, "ul", new_jval_ull(4905283925042198132));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	jrb_insert_str(test_jrb_2, "tree_1", new_jval_tree(test_jrb_1));
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	// log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "serializing message:  ");

	cmp_ctx_t cmp;
	void* buffer = malloc(65536);
	memset(buffer, 0, 65536);

	cmp_init(&cmp, buffer, _np_buffer_reader, _np_buffer_writer);
	_np_tree_serialize(test_jrb_2, &cmp);

	log_msg(LOG_INFO, "serialized message is: %p %s (size: %d)", buffer, buffer, cmp.buf-buffer);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "deserializing message:");

	np_tree_t* out_jrb = np_tree_create();
	cmp_ctx_t cmp_out;
	// int cmp_err_out;
	cmp_init(&cmp_out, buffer, _np_buffer_reader, _np_buffer_writer);

	// unsigned int map_size = 0;
	// cmp_err_out = cmp_read_map(&cmp_out, &map_size);
	// if (!cmp_err_out) log_msg(LOG_WARN, cmp_strerror(&cmp_out));
	// log_msg(LOG_INFO, "deserialized buffer contains %d elements", map_size);
	_np_tree_deserialize(out_jrb, &cmp_out);

	log_msg(LOG_INFO, "deserialized tree is: %p (size %d)", out_jrb, out_jrb->size);
	log_msg(LOG_INFO, "id: %d", jrb_find_str(out_jrb, "id")->val.value.i);
	log_msg(LOG_INFO, "from: %s", jrb_find_str(out_jrb, "from")->val.value.s);
	log_msg(LOG_INFO, "mail: %s", jrb_find_str(out_jrb, "mail")->val.value.s);
	log_msg(LOG_INFO, "to: %s", jrb_find_str(out_jrb, "to")->val.value.s);
	log_msg(LOG_INFO, "exp: %f", jrb_find_str(out_jrb, "exp")->val.value.d);
	log_msg(LOG_INFO, "ul: %lu", jrb_find_str(out_jrb, "ul")->val.value.ull);

	np_tree_t* test_ex = jrb_find_str(out_jrb, "tree_1")->val.value.tree;
	log_msg(LOG_INFO, "tree_1: %p", test_ex);
	log_msg(LOG_INFO, "tree_1/halli: %s", jrb_find_str(test_ex, "halli")->val.value.s);
	log_msg(LOG_INFO, "tree_1/hallo: %s", jrb_find_str(test_ex, "hallo")->val.value.s);

	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "out jrb has size: %d %d", out_jrb->size, out_jrb->byte_size);
	log_msg(LOG_INFO, "removing entries from jrb message:");

	del_str_node(out_jrb, "from");
	np_tree_elem_t* test = jrb_find_str(out_jrb, "from");
	if(test == NULL) log_msg(LOG_INFO, "deleted node not found");
	log_msg(LOG_INFO, "out jrb has size: %d %d", out_jrb->size, out_jrb->byte_size);


	log_msg(LOG_INFO, "----------------------");
	np_message_t* msg;
	np_new_obj(np_message_t, msg);
	// TODO:
	// strange behaviour: msg->header->flink points to somewhere else, although it was never modified
	// np_message_create_empty simply call make_jrb() (see test case #1 in this file)
	// !!!
	// log_msg(LOG_DEBUG, "now serializing message #1 (%p: %p->%p)", msg, msg->header, msg->header->flink);

	char send_buffer[120000];
	void* send_buf_ptr = send_buffer;
	uint64_t send_buf_len;

	// log_msg(LOG_DEBUG, "now serializing message #1 (%p->%p)", msg->header, msg->header->flink);
	np_jobargs_t job_args = { .msg=msg };
	np_message_serialize(NULL, &job_args);

	jrb_insert_str(msg->instructions, "_np.ack", new_jval_i(1));
	jrb_insert_str(msg->instructions, "_np.seq", new_jval_ul(2));
	jrb_insert_str(msg->instructions, "_np.part", new_jval_i(3));

	// char send_buffer[120000];
	// void* send_buf_ptr = send_buffer;
	// unsigned long send_buf_len;

	log_msg(LOG_DEBUG, "now serializing message #2");
	np_jobargs_t job_args_2 = { .msg=msg };
	np_message_serialize(NULL, &job_args_2);

}
