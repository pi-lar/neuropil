//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include "event/ev.h"

#include "np_log.h"
#include "np_val.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_util.h"
#include "np_jobqueue.h"

#include "../src/msgpack/cmp.c"
#include "../src/np_util.c"

uint32_t total_write_count = 0;
size_t buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count);
size_t buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count)
{
	total_write_count += count;
	return buffer_writer(ctx, data, count);
}
uint32_t total_read_count = 0;
np_bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit);
np_bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit)
{
	total_read_count += limit;
	return buffer_reader(ctx, data, limit);
}
void reset_buffer_counter();
void reset_buffer_counter(){
	total_write_count = 0;
	total_read_count = 0;
}


void setup_serialization(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	np_mem_init();
	np_log_init("test_jrb_serialization.log", log_level);
}

void teardown_serialization(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(test_serialization, .init=setup_serialization, .fini=teardown_serialization);

Test(test_serialization, serialize_np_dhkey_t, .description="test the serialization of a dhkey")
{
	cmp_ctx_t cmp_read;
	cmp_ctx_t cmp_write;

    char buffer[512];
    void* buffer_ptr = buffer;

    cr_log_info("buffer_ptr\t\t %p\n", buffer_ptr);
    memset(buffer_ptr, 0, 512);
    reset_buffer_counter();
    cmp_init(&cmp_write, buffer_ptr, buffer_reader_counter, buffer_writer_counter);

    np_dhkey_t tst;
    tst.t[0] = 1;
    tst.t[1] = 2;
    tst.t[2] = 3;
    tst.t[3] = 4;

    np_val_t val = new_val_key(tst);
	cr_expect(val.type == key_type, "Expected source val to be of type key_type. But is: %"PRIu8, val.type);
	cr_expect(total_write_count == 0, "Expected empty buffer. But size is %"PRIu32, total_write_count);
    write_type(val, &cmp_write);
	cr_assert(cmp_write.error == ERROR_NONE, "expect no error on write. But is: %"PRIu8, cmp_write.error);

	                             //4 * (marker of uint64 + content of uint64)
	uint32_t expected_obj_size =  (4 * (sizeof(uint8_t)  + sizeof(uint64_t)));
								  // marker EXT32    + size of EXT32    + type of EXT32
	uint32_t expected_write_size =  (sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) + expected_obj_size);

	cr_expect(total_write_count == expected_write_size, "Expected write size is %"PRIu32" but is %"PRIu32, expected_write_size, total_write_count);
	uint32_t expected_read_count = total_write_count;


	// Beginn reading section
    cmp_init(&cmp_read, buffer_ptr, buffer_reader_counter, buffer_writer_counter);
    reset_buffer_counter();

	cmp_object_t obj;
	np_val_t read_tst = { .type = none_type, .size = 0 };
	cmp_read_object(&cmp_read, &obj);

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on object read. But is: %"PRIu8,cmp_read.error);
	cr_assert(obj.type == CMP_TYPE_EXT32, "Expected obj to be of type CMP_TYPE_EXT32. But is: %"PRIu8, obj.type);
	cr_expect(obj.as.ext.type == key_type, "Expected obj to be of type EXT type key_type. But is: %"PRIu8, read_tst.type);
	cr_expect(obj.as.ext.size == expected_obj_size, "Expected obj to be of size %"PRIu32". But is: %"PRIu32, expected_obj_size, obj.as.ext.size);

	read_type(&obj, &cmp_read, &read_tst);

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on val read. But is: %"PRIu8,cmp_read.error);
	cr_expect(total_read_count == expected_read_count, "Expected read size is %"PRIu32" but is %"PRIu32, expected_read_count, total_read_count);

	cr_expect(read_tst.type == key_type, "Expected read val to be of type key_type. But is: %"PRIu8, read_tst.type);
	cr_expect(read_tst.size == sizeof(np_dhkey_t), "Expected val to be of dhkey size. But is: %"PRIu32, read_tst.size);
	cr_expect(read_tst.value.key.t[0] == 1, "Expected read val value 0 to be the same as predefined, But is: %"PRIu64, read_tst.value.key.t[0]);
	cr_expect(read_tst.value.key.t[1] == 2, "Expected read val value 1 to be the same as predefined, But is: %"PRIu64, read_tst.value.key.t[1]);
	cr_expect(read_tst.value.key.t[2] == 3, "Expected read val value 2 to be the same as predefined, But is: %"PRIu64, read_tst.value.key.t[2]);
	cr_expect(read_tst.value.key.t[3] == 4, "Expected read val value 3 to be the same as predefined, But is: %"PRIu64, read_tst.value.key.t[3]);
}

Test(test_serialization, serialize_np_dhkey_t_in_np_tree_t_, .description="test the serialization of a dhkey in a tree")
{
	cmp_ctx_t cmp_read;
	cmp_ctx_t cmp_write;

    char buffer[1024];
    void* buffer_ptr = buffer;

    cr_log_info("buffer_ptr\t\t %p\n", buffer_ptr);
    memset(buffer_ptr, 0, 1024);
    reset_buffer_counter();
    cmp_init(&cmp_write, buffer_ptr, buffer_reader_counter, buffer_writer_counter);

    np_dhkey_t tst;
    tst.t[0] = 1;
    tst.t[1] = 2;
    tst.t[2] = 3;
    tst.t[3] = 4;
    np_dhkey_t tst2;
    tst2.t[0] = 5;
    tst2.t[1] = 6;
    tst2.t[2] = 7;
    tst2.t[3] = 8;

    np_tree_t* write_tree = np_tree_create();
    np_tree_insert_str(write_tree,"TESTKEY", new_val_key(tst));

	cr_expect(total_write_count == 0, "Expected empty buffer. But size is %"PRIu32, total_write_count);

	serialize_jrb_node_t(write_tree,&cmp_write);

	cr_assert(cmp_write.error == ERROR_NONE, "expect no error on write. But is: %"PRIu8, cmp_write.error);

	uint32_t expected_write_size =  59;

	cr_expect(total_write_count == expected_write_size, "Expected write size is %"PRIu32" but is %"PRIu32, expected_write_size, total_write_count);
	uint32_t expected_read_count = total_write_count;


	// Beginn reading section
    cmp_init(&cmp_read, buffer_ptr, buffer_reader_counter, buffer_writer_counter);
    reset_buffer_counter();
    np_tree_t* read_tree = np_tree_create();

    deserialize_jrb_node_t(read_tree, &cmp_read);

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on val read. But is: %"PRIu8,cmp_read.error);
	cr_expect(total_read_count == expected_read_count, "Expected read size is %"PRIu32" but is %"PRIu32, expected_read_count, total_read_count);

	np_tree_elem_t* testkey_read =  np_tree_find_str(read_tree,"TESTKEY");

	cr_assert(NULL != testkey_read, "Expected to find TESTKEY key value");

	cr_expect(testkey_read->val.type == key_type, "Expected read val to be of type key_type. But is: %"PRIu8, testkey_read->val.type);
	cr_expect(testkey_read->val.size == sizeof(np_dhkey_t), "Expected val to be of dhkey size. But is: %"PRIu32, testkey_read->val.size);

	cr_expect(testkey_read->val.value.key.t[0] == 1, "Expected read val value 0 to be the same as predefined, But is: %"PRIu64, testkey_read->val.value.key.t[0]);
	cr_expect(testkey_read->val.value.key.t[1] == 2, "Expected read val value 1 to be the same as predefined, But is: %"PRIu64, testkey_read->val.value.key.t[1]);
	cr_expect(testkey_read->val.value.key.t[2] == 3, "Expected read val value 2 to be the same as predefined, But is: %"PRIu64, testkey_read->val.value.key.t[2]);
	cr_expect(testkey_read->val.value.key.t[3] == 4, "Expected read val value 3 to be the same as predefined, But is: %"PRIu64, testkey_read->val.value.key.t[3]);
}



Test(test_serialization, serialize_jrb_node_t, .description="test the serialization of a  jtree")
{
	np_tree_t* test_jrb_1 = np_tree_create();

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
	np_tree_insert_str(test_jrb_1, "halli", new_val_s("galli"));
	cr_expect(   1 == test_jrb_1->size, "expect size of tree to be 1");
	cr_expect(  20 == np_tree_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 20");
	cr_expect(  25 == test_jrb_1->byte_size, "expect byte size to be 25");

	np_tree_insert_str(test_jrb_1, "hallo", new_val_s("gulli"));
	cr_expect(  2 == test_jrb_1->size, "expect size of tree to be 2");
	cr_expect( 20 == np_tree_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 20");
	cr_expect( 45 == test_jrb_1->byte_size, "expect byte size to be 45");

	np_tree_t* test_jrb_2 = np_tree_create();
	cr_expect(   0 == test_jrb_2->size, "expect size of tree to be 0");

	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, from, new_val_s(me));
	cr_expect(   1 == test_jrb_2->size, "expect size of tree to be 1");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, to,   new_val_s(you));
	cr_expect(   2 == test_jrb_2->size, "expect size of tree to be 2");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, id,   new_val_i(18000));
	cr_expect(   3 == test_jrb_2->size, "expect size of tree to be 3");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, exp,  new_val_d(5.0));
	cr_expect(   4 == test_jrb_2->size, "expect size of tree to be 4");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, mail, new_val_s(mail_t));
	cr_expect(   5 == test_jrb_2->size, "expect size of tree to be 5");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);

	np_tree_insert_str(test_jrb_2, "ul", new_val_ull(4905283925042198132));
	cr_expect(   6 == test_jrb_2->size, "expect size of tree to be 6");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);

	np_tree_insert_str(test_jrb_2, "tree_1", new_val_tree(test_jrb_1));
	cr_expect(   7 == test_jrb_2->size, "expect size of tree to be 7");
	log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb_2->size, test_jrb_2->byte_size);

	// log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb->size, test_jrb->byte_size);
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

	np_tree_t* out_jrb = np_tree_create();
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
