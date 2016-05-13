#include <criterion/criterion.h>

#include "event/ev.h"
#include "np_log.h"
#include "jval.h"
#include "np_tree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"
#include "np_jobqueue.h"

#include "msgpack/cmp.h"

void setup_jrb_serialization(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	np_mem_init();
	np_log_init("test_jrb_serialization.log", log_level);
}

void teardown_jrb_serialization(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_jrb_serialize_t, .init=setup_jrb_serialization, .fini=teardown_jrb_serialization);

Test(np_jrb_serialize_t, serialize_jrb_node_t, .description="test the serialization of a  jtree")
{
	np_tree_t* test_jrb_1 = make_jtree();

	cr_expect(NULL != test_jrb_1, "expect test_jrb_1 pointer to exists");
	cr_expect(NULL == test_jrb_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_jrb_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_jrb_1->byte_size, "expect minimum byte size to be 5");

	cmp_ctx_t cmp_empty;
    char empty_buffer[65536];
    void* empty_buf_ptr = empty_buffer;
    memset(empty_buf_ptr, 0, 65536);

    cmp_init(&cmp_empty, empty_buf_ptr, buffer_reader, buffer_writer);
	serialize_jrb_node_t(test_jrb_1, &cmp_empty);

	// np_jrb_t* node = NULL;
	// cmp_write_array(&cmp_empty, 1);
	// if (!cmp_write_map(&cmp_empty, test_jrb->size*2 )) log_msg(LOG_WARN, cmp_strerror(&cmp_empty));
	// node = test_jrb;
	// log_msg(LOG_DEBUG, "for %p; %p!=%p; %p=%p", test_jrb->flink, node, test_jrb, node, node->flink);
	//	jrb_traverse(node, test_jrb) {
	//		log_msg(LOG_INFO, "serializing now: %s", node->key.value.s);
	//		serialize_jrb_node_t(node, &cmp_empty);
	//	}
	// free (empty_buffer);
	// np_free_tree(test_jrb_1);
	tree_insert_str(test_jrb_1, "halli", new_val_s("galli"));
	cr_expect(   1 == test_jrb_1->size, "expect size of tree to be 1");
	cr_expect(  20 == jrb_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 20");
	cr_expect(  25 == test_jrb_1->byte_size, "expect byte size to be 25");

	tree_insert_str(test_jrb_1, "hallo", new_val_s("gulli"));
	cr_expect(  2 == test_jrb_1->size, "expect size of tree to be 2");
	cr_expect( 20 == jrb_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 20");
	cr_expect( 45 == test_jrb_1->byte_size, "expect byte size to be 45");

	np_tree_t* test_jrb_2 = make_jtree();
	cr_expect(   0 == test_jrb_2->size, "expect size of tree to be 0");

	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	tree_insert_str(test_jrb_2, from, new_val_s(me));
	cr_expect(   1 == test_jrb_2->size, "expect size of tree to be 1");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	tree_insert_str(test_jrb_2, to,   new_val_s(you));
	cr_expect(   2 == test_jrb_2->size, "expect size of tree to be 2");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	tree_insert_str(test_jrb_2, id,   new_val_i(18000));
	cr_expect(   3 == test_jrb_2->size, "expect size of tree to be 3");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	tree_insert_str(test_jrb_2, exp,  new_val_d(5.0));
	cr_expect(   4 == test_jrb_2->size, "expect size of tree to be 4");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);
	tree_insert_str(test_jrb_2, mail, new_val_s(mail_t));
	cr_expect(   5 == test_jrb_2->size, "expect size of tree to be 5");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	tree_insert_str(test_jrb_2, "ul", new_val_ull(4905283925042198132));
	cr_expect(   6 == test_jrb_2->size, "expect size of tree to be 6");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	tree_insert_str(test_jrb_2, "tree_1", new_val_tree(test_jrb_1));
	cr_expect(   7 == test_jrb_2->size, "expect size of tree to be 7");
	log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb_2->size, test_jrb_2->byte_size);

	// log_msg(LOG_INFO, "test jrb has size: %d %d", test_jrb->size, test_jrb->byte_size);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "serializing message:  ");

    cmp_ctx_t cmp;
    void* buffer = malloc(65536);
    memset(buffer, 0, 65536);

    cmp_init(&cmp, buffer, buffer_reader, buffer_writer);
	serialize_jrb_node_t(test_jrb_2, &cmp);

	/*
	log_msg(LOG_INFO, "serialized message is: %p %s (size: %d)", buffer, buffer, cmp.buf-buffer);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "deserializing message:");

	np_tree_t* out_jrb = make_jtree();
	cmp_ctx_t cmp_out;
	// int cmp_err_out;
	cmp_init(&cmp_out, buffer, buffer_reader, buffer_writer);

	// unsigned int map_size = 0;
	// cmp_err_out = cmp_read_map(&cmp_out, &map_size);
	// if (!cmp_err_out) log_msg(LOG_WARN, cmp_strerror(&cmp_out));
	// log_msg(LOG_INFO, "deserialized buffer contains %d elements", map_size);
	deserialize_jrb_node_t(out_jrb, &cmp_out);

	log_msg(LOG_INFO, "deserialized tree is: %p (size %d)", out_jrb, out_jrb->size);
	log_msg(LOG_INFO, "id: %d", tree_find_str(out_jrb, "id")->val.value.i);
	log_msg(LOG_INFO, "from: %s", tree_find_str(out_jrb, "from")->val.value.s);
	log_msg(LOG_INFO, "mail: %s", tree_find_str(out_jrb, "mail")->val.value.s);
	log_msg(LOG_INFO, "to: %s", tree_find_str(out_jrb, "to")->val.value.s);
	log_msg(LOG_INFO, "exp: %f", tree_find_str(out_jrb, "exp")->val.value.d);
	log_msg(LOG_INFO, "ul: %lu", tree_find_str(out_jrb, "ul")->val.value.ull);

	np_tree_t* test_ex = tree_find_str(out_jrb, "tree_1")->val.value.tree;
	log_msg(LOG_INFO, "tree_1: %p", test_ex);
	log_msg(LOG_INFO, "tree_1/halli: %s", tree_find_str(test_ex, "halli")->val.value.s);
	log_msg(LOG_INFO, "tree_1/hallo: %s", tree_find_str(test_ex, "hallo")->val.value.s);

	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "out jrb has size: %d %d", out_jrb->size, out_jrb->byte_size);
	log_msg(LOG_INFO, "removing entries from jrb message:");

	tree_del_str(out_jrb, "from");
	np_tree_elem_t* test = tree_find_str(out_jrb, "from");
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
	np_message_serialize(&job_args);

	tree_insert_str(msg->instructions, "_np.ack", new_val_i(1));
	tree_insert_str(msg->instructions, "_np.seq", new_val_ul(2));
	tree_insert_str(msg->instructions, "_np.part", new_val_i(3));

	// char send_buffer[120000];
	// void* send_buf_ptr = send_buffer;
	// unsigned long send_buf_len;

	log_msg(LOG_DEBUG, "now serializing message #2");
	np_jobargs_t job_args_2 = { .msg=msg };
	np_message_serialize(&job_args_2);
*/
}
