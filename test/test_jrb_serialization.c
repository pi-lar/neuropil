//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include "event/ev.h"

#include "np_log.h"
#include "np_treeval.h"
#include "np_tree.h"
#include "np_dhkey.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_message.h"
#include "np_util.h"
#include "np_jobqueue.h"
#include "np_serialization.h"

#include "../src/msgpack/cmp.c"
#include "../src/np_util.c"

uint32_t total_write_count = 0;
size_t buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count);
size_t buffer_writer_counter(struct cmp_ctx_s *ctx, const void *data, size_t count)
{
	total_write_count += count;
	return _np_buffer_writer(ctx, data, count);
}
uint32_t total_read_count = 0;
np_bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit);
np_bool buffer_reader_counter(struct cmp_ctx_s *ctx, void *data, size_t limit)
{
	total_read_count += limit;
	return _np_buffer_reader(ctx, data, limit);
}
void reset_buffer_counter();
void reset_buffer_counter(){
	total_write_count = 0;
	total_read_count = 0;
}


void setup_serialization(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_TREE;
	np_mem_init();
	np_memory_init();
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
    cmp_init(&cmp_write, buffer_ptr, buffer_reader_counter, NULL, buffer_writer_counter);

    np_dhkey_t tst;
    tst.t[0] = 1;
    tst.t[1] = 2;
    tst.t[2] = 3;
	tst.t[3] = 4;
	tst.t[4] = 5;
	tst.t[5] = 6;
	tst.t[6] = 7;
	tst.t[7] = 8;

	cr_expect(total_write_count == 0, "Expected empty buffer. But size is %"PRIu32, total_write_count);

	np_treeval_t val = np_treeval_new_dhkey(tst);
	cr_expect(val.type == np_treeval_type_dhkey, "Expected source val to be of type np_treeval_type_dhkey. But is: %"PRIu8, val.type);

	__np_tree_serialize_write_type(val, &cmp_write);

	cr_assert(cmp_write.error == ERROR_NONE, "expect no error on write. But is: %"PRIu8, cmp_write.error);

	                                // 8 * (marker of uint32 + content of uint32)
	uint32_t expected_obj_size   =  (  8 * (sizeof(uint8_t)  + sizeof(uint32_t)) );

								    // marker EXT32  + size of EXT32    + type of EXT32
	uint32_t expected_write_size =  (sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) + expected_obj_size);


	cr_expect(total_write_count == expected_write_size, "Expected write size is %d but is %d", expected_write_size, total_write_count);
	uint32_t expected_read_count = total_write_count;


	// Beginn reading section
    cmp_init(&cmp_read, buffer_ptr, buffer_reader_counter, NULL, buffer_writer_counter);
    reset_buffer_counter();

	cmp_object_t obj;
	np_treeval_t read_tst = { .type = np_treeval_type_undefined, .size = 0 };
	cmp_read_object(&cmp_read, &obj);

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on object read. But is: %"PRIu8,cmp_read.error);
	cr_assert(obj.type == CMP_TYPE_EXT32, "Expected obj to be of type CMP_TYPE_EXT32. But is: %"PRIu8, obj.type);
	cr_expect(obj.as.ext.type == np_treeval_type_dhkey, "Expected obj to be of type EXT type np_treeval_type_dhkey. But is: %"PRIu8, read_tst.type);
	cr_expect(obj.as.ext.size == expected_obj_size, "Expected obj to be of size %"PRIu32". But is: %"PRIu32, expected_obj_size, obj.as.ext.size);

	__np_tree_deserialize_read_type(np_tree_create(), &obj, &cmp_read, &read_tst,"test read");

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on val read. But is: %"PRIu8,cmp_read.error);
	cr_expect(total_read_count == expected_read_count, "Expected read size is %"PRIu32" but is %"PRIu32, expected_read_count, total_read_count);

	cr_expect(read_tst.type == np_treeval_type_dhkey, "Expected read val to be of type np_treeval_type_dhkey. But is: %"PRIu8, read_tst.type);
	cr_expect(read_tst.size == sizeof(np_dhkey_t), "Expected val to be of dhkey size. But is: %"PRIu32, read_tst.size);
	cr_expect(read_tst.value.dhkey.t[0] == 1, "Expected read val value 0 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[0]);
	cr_expect(read_tst.value.dhkey.t[1] == 2, "Expected read val value 1 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[1]);
	cr_expect(read_tst.value.dhkey.t[2] == 3, "Expected read val value 2 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[2]);
	cr_expect(read_tst.value.dhkey.t[3] == 4, "Expected read val value 3 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[3]);
	cr_expect(read_tst.value.dhkey.t[4] == 5, "Expected read val value 4 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[4]);
	cr_expect(read_tst.value.dhkey.t[5] == 6, "Expected read val value 5 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[5]);
	cr_expect(read_tst.value.dhkey.t[6] == 7, "Expected read val value 6 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[6]);
	cr_expect(read_tst.value.dhkey.t[7] == 8, "Expected read val value 7 to be the same as predefined, But is: %"PRIu32, read_tst.value.dhkey.t[7]);
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
    cmp_init(&cmp_write, buffer_ptr, buffer_reader_counter, NULL, buffer_writer_counter);

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

    np_tree_t* write_tree = np_tree_create();
    np_tree_insert_str(write_tree,"TESTKEY", np_treeval_new_dhkey(tst));

	cr_expect(total_write_count == 0, "Expected empty buffer. But size is %"PRIu32, total_write_count);

	np_tree_serialize(write_tree,&cmp_write);

	cr_assert(cmp_write.error == ERROR_NONE, "expect no error on write. But is: %"PRIu8, cmp_write.error);

	uint32_t expected_write_size =  64;

	cr_expect(total_write_count == expected_write_size, "Expected write size is %"PRIu32" but is %"PRIu32, expected_write_size, total_write_count);
	uint32_t expected_read_count = total_write_count;


	// Beginn reading section
    cmp_init(&cmp_read, buffer_ptr, buffer_reader_counter, NULL, buffer_writer_counter);
    reset_buffer_counter();
    np_tree_t* read_tree = np_tree_create();

    np_tree_deserialize(read_tree, &cmp_read);

	cr_assert(cmp_read.error == ERROR_NONE, "Expected no error on val read. But is: %"PRIu8,cmp_read.error);
	cr_expect(total_read_count == expected_read_count, "Expected read size is %"PRIu32" but is %"PRIu32, expected_read_count, total_read_count);

	np_tree_elem_t* testkey_read =  np_tree_find_str(read_tree,"TESTKEY");

	cr_assert(NULL != testkey_read, "Expected to find TESTKEY key value");

	cr_expect(testkey_read->val.type == np_treeval_type_dhkey, "Expected read val to be of type np_treeval_type_dhkey. But is: %"PRIu8, testkey_read->val.type);
	cr_expect(testkey_read->val.size == sizeof(np_dhkey_t), "Expected val to be of dhkey size. But is: %"PRIu32, testkey_read->val.size);

	cr_expect(testkey_read->val.value.dhkey.t[0] == 1, "Expected read val value 0 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[0]);
	cr_expect(testkey_read->val.value.dhkey.t[1] == 2, "Expected read val value 1 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[1]);
	cr_expect(testkey_read->val.value.dhkey.t[2] == 3, "Expected read val value 2 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[2]);
	cr_expect(testkey_read->val.value.dhkey.t[3] == 4, "Expected read val value 3 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[3]);
	cr_expect(testkey_read->val.value.dhkey.t[4] == 5, "Expected read val value 4 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[4]);
	cr_expect(testkey_read->val.value.dhkey.t[5] == 6, "Expected read val value 5 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[5]);
	cr_expect(testkey_read->val.value.dhkey.t[6] == 7, "Expected read val value 6 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[6]);
	cr_expect(testkey_read->val.value.dhkey.t[7] == 8, "Expected read val value 7 to be the same as predefined, But is: %"PRIu32, testkey_read->val.value.dhkey.t[7]);
}


Test(test_serialization, _np_tree_special_str, .description = "test the implementation of special strings in the tree implementation")
{
	uint8_t idx = 254;	
	char* tmp;
	uint32_t tmp2;

	cr_expect(_np_tree_is_special_str("np.test1", &idx) == FALSE, "expecting np.test1 to be no special string");
	cr_expect(idx == 254, "expecting index to be the same");

	cr_assert(_np_tree_is_special_str("np.test2", &idx) == TRUE, "expecting np.test2 to be a special string");
	cr_expect(idx == 0, "expecting np.test2 to be at position 0 and not %"PRIu8, idx);
	cr_expect(strcmp("np.test2", (tmp = _np_tree_get_special_str(idx))) == 0, "expecting retunred special string to be np.test2 and not %s",tmp);


	cr_expect(_np_tree_is_special_str("np.test3", &idx) == TRUE, "expecting np.test3 to be a special string");
	cr_expect(idx == 2, "expecting np.test3 to be at position 2");
	cr_expect(strcmp("np.test3", (tmp =  _np_tree_get_special_str(idx))) == 0, "expecting retunred special string to be np.test3 and not %s",tmp);


	np_tree_t* tst = np_tree_create();
	np_tree_elem_t*  ele;

	np_tree_insert_str(tst, "np.test3", np_treeval_new_s("np.test2"));
	ele = np_tree_find_str(tst, "np.test3");
	cr_assert(ele != NULL, "Expect to find a element");
	cr_expect(ele->key.type == np_treeval_type_special_char_ptr, "Expect key of element to be from type np_treeval_type_special_char_ptr");
	cr_expect(ele->key.value.ush == 2, "Expect type index to be 2");

	cr_expect(ele->val.type == np_treeval_type_special_char_ptr, "Expect value of element to be from type np_treeval_type_special_char_ptr");
	cr_expect(ele->val.value.ush == 0, "Expect type index to be 0 but is %"PRIu8, ele->val.value.ush);

	cr_expect(4 < (tmp2 = np_tree_get_byte_size(tst->rbh_root)), "expect byte size to be 4 but is %"PRIu32, tmp2);

	np_tree_insert_str(tst, "np.test2", np_treeval_new_s("1234"));
	ele = np_tree_find_str(tst, "np.test2");
	cr_assert(ele != NULL, "Expect to find a element");
	cr_expect(ele->key.type == np_treeval_type_special_char_ptr, "Expect key of element to be from type np_treeval_type_special_char_ptr");
	cr_expect(ele->key.value.ush == 0, "Expect type index to be 0");
	cr_expect(ele->val.type == np_treeval_type_char_ptr, "Expect value of element to be from type np_treeval_type_char_ptr");
	cr_expect(strcmp("1234",  np_treeval_to_str(ele->val, NULL)) == 0, "expecting special string to be 1234");

	cr_expect(0 < np_tree_get_byte_size(tst->rbh_root), "expect byte size to be not 0");

	np_tree_free(tst);
}

Test(test_serialization, np_tree_serialize, .description="test the serialization of a  jtree")
{
	np_tree_t* test_jrb_1 = np_tree_create();
	uint32_t tmp32;
	uint16_t tmp16;
	uint8_t tmp8;
	np_tree_elem_t* tmpEle;

	cr_expect(NULL != test_jrb_1, "expect test_jrb_1 pointer to exists");
	cr_expect(NULL == test_jrb_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_jrb_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_jrb_1->byte_size, "expect minimum byte size to be 5");

	cmp_ctx_t cmp_empty;
    char empty_buffer[65536];
    void* empty_buf_ptr = empty_buffer;
    memset(empty_buf_ptr, 0, 65536);

    cmp_init(&cmp_empty, empty_buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	np_tree_serialize(test_jrb_1, &cmp_empty);

	// np_jrb_t* node = NULL;
	// cmp_write_array(&cmp_empty, 1);
	// if (!cmp_write_map(&cmp_empty, test_jrb->size*2 )) log_msg(LOG_WARN, cmp_strerror(&cmp_empty));
	// node = test_jrb;
	// log_msg(LOG_DEBUG, "for %p; %p!=%p; %p=%p", test_jrb->flink, node, test_jrb, node, node->flink);
	//	jrb_traverse(node, test_jrb) {
	//		log_msg(LOG_INFO, "serializing now: %s",  np_treeval_to_str(node->key));
	//		_np_tree_serialize(node, &cmp_empty);
	//	}
	// free (empty_buffer);
	// np_free_tree(test_jrb_1);
	np_tree_insert_str(test_jrb_1, "halli", np_treeval_new_s("galli"));
	cr_expect(   1 == test_jrb_1->size, "expect size of tree to be 1");
	cr_expect(  22 == np_tree_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 22");
	cr_expect(  27 == test_jrb_1->byte_size, "expect byte size to be 27");

	np_tree_insert_str(test_jrb_1, "hallo", np_treeval_new_s("gulli"));
	cr_expect(  2 == test_jrb_1->size, "expect size of tree to be 2");
	cr_expect( 22 == np_tree_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 22");
	cr_expect( 49 == test_jrb_1->byte_size, "expect byte size to be 49");

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

	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, from, np_treeval_new_s(me));
	cr_expect(   1 == test_jrb_2->size, "expect size of tree to be 1");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, to,   np_treeval_new_s(you));
	cr_expect(   2 == test_jrb_2->size, "expect size of tree to be 2");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, id,   np_treeval_new_i(18000));
	cr_expect(   3 == test_jrb_2->size, "expect size of tree to be 3");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, exp,  np_treeval_new_d(5.0));
	cr_expect(   4 == test_jrb_2->size, "expect size of tree to be 4");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	np_tree_insert_str(test_jrb_2, mail, np_treeval_new_s(mail_t));
	cr_expect(   5 == test_jrb_2->size, "expect size of tree to be 5");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
#ifdef x64
	np_tree_insert_str(test_jrb_2, "ul", np_treeval_new_ull(4905283925042198132));
	cr_expect(   6 == test_jrb_2->size, "expect size of tree to be 6");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
#else
	np_tree_insert_str(test_jrb_2, mail, np_treeval_new_s(mail_t));
	cr_expect(6 == test_jrb_2->size, "expect size of tree to be 6");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
#endif
	np_tree_insert_str(test_jrb_2, "tree_1", np_treeval_new_tree(test_jrb_1));
	cr_expect(7 == test_jrb_2->size, "expect size of tree to be 7");
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);
	
	np_tree_insert_str(test_jrb_2, "np.test2", np_treeval_new_s("test"));
	cr_expect(8 == (tmp16 = test_jrb_2->size), "expect size of tree to be 8 but is %"PRIu16, tmp16);
	log_msg(LOG_INFO, "test jrb has size: %d %lu", test_jrb_2->size, test_jrb_2->byte_size);


	// log_msg(LOG_INFO, "test jrb has size: %d %llu", test_jrb->size, test_jrb->byte_size);
	log_msg(LOG_INFO, "----------------------");
	log_msg(LOG_INFO, "serializing message:  ");

    cmp_ctx_t cmp;
    void* buffer = malloc(65536);
    memset(buffer, 0, 65536);

    cmp_init(&cmp, buffer, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	np_tree_serialize(test_jrb_2, &cmp);

	np_tree_t* out_jrb = np_tree_create();
	cmp_ctx_t cmp_out;
	// int cmp_err_out;
	cmp_init(&cmp_out, buffer, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

	np_tree_deserialize(out_jrb, &cmp_out);

	cr_assert((tmp8 = cmp_out.error )== 0, "Expect no error in deserialisation (error: %"PRIu8")",tmp8);

	tmpEle = np_tree_find_str(out_jrb, "np.test2");
	
	cr_assert(tmpEle != NULL, "Expect to find element np.test2");
	cr_assert(tmpEle->key.type == np_treeval_type_special_char_ptr, "Expect element key to be of type np_treeval_type_special_char_ptr" );
	cr_expect(tmpEle->key.value.ush  == 0, "Expect element key to be the same");
	cr_expect(tmpEle->val.type == np_treeval_type_char_ptr, "Expect element value to be of type np_treeval_type_char_ptr");
	cr_expect(strcmp( np_treeval_to_str(tmpEle->val, NULL), "test") == 0, "Expect element value to be the same");


	/*
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

	tree_insert_str(msg->instructions, "_np.ack", np_treeval_new_i(1));
	tree_insert_str(msg->instructions, "_np.seq", new_val_ul(2));
	tree_insert_str(msg->instructions, "_np.part", np_treeval_new_i(3));

	// char send_buffer[120000];
	// void* send_buf_ptr = send_buffer;
	// unsigned long send_buf_len;

	log_msg(LOG_DEBUG, "now serializing message #2");
	np_jobargs_t job_args_2 = { .msg=msg };
	np_message_serialize(&job_args_2);
*/
}
