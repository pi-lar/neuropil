//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "event/ev.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_treeval.h"

void setup_tree(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	np_log_init("test_tree_impl.log", log_level);
}

void teardown_tree(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_tree_t, .init=setup_tree, .fini=teardown_tree);

Test(np_tree_t, tree_node_insert_str, .description="test the insertion into a tree (string key)")
{
	np_tree_t* test_tree_1 = np_tree_create();

	cr_expect(NULL != test_tree_1, "expect test_tree_1 pointer to exists");
	cr_expect(NULL == test_tree_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_tree_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_tree_1->byte_size, "expect minimum byte size to be 5");

	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));

	cr_expect(   1 == test_tree_1->size, "expect size of tree to be 1");
	cr_expect(  20 == np_tree_get_byte_size(test_tree_1->rbh_root), "expect byte size to be 20");
	cr_expect(  25 == test_tree_1->byte_size, "expect byte size to be 25");
	cr_expect(NULL != test_tree_1->rbh_root, "expect rbh_root to be not NULL");

	np_tree_elem_t* tmp = test_tree_1->rbh_root;
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galli", tmp->val.value.s, 10), "expect the value to be the string 'galli'");

	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galligallo"));
	cr_expect(tmp == test_tree_1->rbh_root, "expect the key to not change (insert will not replace");
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galli", tmp->val.value.s, 10), "expect the value to be the string 'galli'");

	np_tree_replace_str(test_tree_1, "halli", np_treeval_new_s("galligallo"));
	cr_expect(tmp == test_tree_1->rbh_root, "expect the key to not change (replace only replaces value)");
	cr_expect(  1 == test_tree_1->size, "expect size of tree to be 1");
	cr_expect( 25 == np_tree_get_byte_size(test_tree_1->rbh_root), "expect byte size to be 25");
	cr_expect( 30 == test_tree_1->byte_size, "expect byte size to be 30");
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galligallo", tmp->val.value.s, 12), "expect the value to be the string 'galli'");

	np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));
	cr_expect(  2 == test_tree_1->size, "expect size of tree to be 2");
	cr_expect( 25 == np_tree_get_byte_size(test_tree_1->rbh_root), "expect byte size to be 25");
	cr_expect( 50 == test_tree_1->byte_size, "expect byte size to be 50");

	np_tree_clear (test_tree_1);
	cr_expect(NULL == test_tree_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_tree_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_tree_1->byte_size, "expect minimum byte size to be 5");

	np_tree_free(test_tree_1);
}

Test(np_tree_t, tree_node_insert_tree, .description="test the insertion of a tree into tree")
{
	np_tree_t* test_tree_1 = np_tree_create();
	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
	np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));
	cr_expect(   2 == test_tree_1->size, "expect size of tree to be 2");

	np_tree_t* test_tree_2 = np_tree_create();
	cr_expect(   0 == test_tree_2->size, "expect size of tree to be 0");

	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	np_tree_insert_str(test_tree_2, from, np_treeval_new_s(me));
	cr_expect(   1 == test_tree_2->size, "expect size of tree to be 1");

	np_tree_insert_str(test_tree_2, to,   np_treeval_new_s(you));
	cr_expect(   2 == test_tree_2->size, "expect size of tree to be 2");

	np_tree_insert_str(test_tree_2, id,   np_treeval_new_i(18000));
	cr_expect(   3 == test_tree_2->size, "expect size of tree to be 3");

	np_tree_insert_str(test_tree_2, exp,  np_treeval_new_d(5.0));
	cr_expect(   4 == test_tree_2->size, "expect size of tree to be 4");

	np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
	cr_expect(   5 == test_tree_2->size, "expect size of tree to be 5");

	np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
	cr_expect(   6 == test_tree_2->size, "expect size of tree to be 6");

	np_tree_insert_str(test_tree_2, "tree_1", np_treeval_new_tree(test_tree_1));
	cr_expect(   7 == test_tree_2->size, "expect size of tree to be 7");

	/*
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
	*/
}

Test(np_tree_t, tree_node_find_tree, .description="test lookup of data in a tree")
{
	np_tree_t* test_tree_1 = np_tree_create();
	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
	np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));

	np_tree_t* test_tree_2 = np_tree_create();

	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	np_tree_insert_str(test_tree_2, from, np_treeval_new_s(me));
	np_tree_insert_str(test_tree_2, to,   np_treeval_new_s(you));
	np_tree_insert_str(test_tree_2, id,   np_treeval_new_i(18000));
	np_tree_insert_str(test_tree_2, exp,  np_treeval_new_d(5.0));
	np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
	np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
	np_tree_insert_str(test_tree_2, "tree_1", np_treeval_new_tree(test_tree_1));

	cr_expect(NULL == np_tree_find_str(test_tree_1, "dummy"),
				"expect a result of NULL");

	uint8_t found = 0;
	cr_expect(NULL != np_tree_find_gte_str(test_tree_1, "dummy", &found),
				"expect a result of non NULL");
	cr_expect(   0 == found,
				"expect a vaue of 0 for found indicator");
	cr_expect(   2 == test_tree_1->size,
				"expect size of tree to be 2");

	cr_expect(NULL != np_tree_find_str(test_tree_2, from), "expect a result of non NULL");
	cr_expect(0    == strncmp(me, np_tree_find_str(test_tree_2, from)->val.value.s, 3),
				"expect a result of literal 'me'");
	cr_expect(0    == strncmp(from, np_tree_find_str(test_tree_2, from)->key.value.s, 5),
				"expect a result of literal 'from'");

	found = 0;
	cr_expect(NULL != np_tree_find_gte_str(test_tree_2, from, &found),
				"expect a result of non NULL");
	cr_expect(   1 == found,
				"expect a vaue of 1 for found indicator");

	found = 0;
	cr_expect(0 == strncmp(from, np_tree_find_gte_str(test_tree_2, from, &found)->key.value.s, 5),
				"expect a result of literal me");
	cr_expect(   1 == found,
				"expect a vaue of 1 for found indicator");

	found = 0;
	cr_expect(0 == strncmp(me, np_tree_find_gte_str(test_tree_2, from, &found)->val.value.s, 3),
				"expect a result of literal me");
	cr_expect(   1 == found,
				"expect a vaue of 1 for found indicator");
}

Test(np_tree_t, tree_node_del_tree, .description="test deletion of data in a tree")
{
	np_tree_t* test_tree_1 = np_tree_create();
	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
	np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));

	np_tree_t* test_tree_2 = np_tree_create();

	char* from = "from";
	char* to = "to";
	char* id = "id";
	char* exp = "exp";
	char* mail = "mail";

	char* me = "me";
	char* you = "you";
	char* mail_t = "signed.by.me@test.de";

	np_tree_insert_str(test_tree_2, from, np_treeval_new_s(me));
	np_tree_insert_str(test_tree_2, to,   np_treeval_new_s(you));
	np_tree_insert_str(test_tree_2, id,   np_treeval_new_i(18000));
	np_tree_insert_str(test_tree_2, exp,  np_treeval_new_d(5.0));
	np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
	np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
	np_tree_insert_str(test_tree_2, "tree_1", np_treeval_new_tree(test_tree_1));

	cr_expect(2 == test_tree_1->size, "expect the size of teh subtree to be 2");
	cr_expect(NULL != np_tree_find_str(test_tree_1, "halli"), "expect element to be present");

	np_tree_del_str(test_tree_1, "halli");
	cr_expect(1 == test_tree_1->size, "expect the size of the subtree to be 1");
	cr_expect(NULL == np_tree_find_str(test_tree_1, "halli"), "expect element to be absent");

	np_tree_clear(test_tree_1);
	cr_expect(0 == test_tree_1->size, "expect the size of the subtree to be 0");


	cr_expect(7 == test_tree_2->size, "expect the size of teh subtree to be 2");
	cr_expect(NULL != np_tree_find_str(test_tree_2, "tree_1"), "expect element to be present");

	np_tree_del_str(test_tree_2, "tree_1");

	cr_expect(6 == test_tree_2->size, "expect the size of teh subtree to be 6");
	cr_expect(NULL == np_tree_find_str(test_tree_2, "tree_1"), "expect element to be absent");

	np_tree_free(test_tree_2);
}

Test(np_tree_t, tree_node_repl_tree, .description="test replacement of data in a tree")
{
	np_tree_t* test_tree_1 = np_tree_create();
	np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
	np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));

	cr_expect(2 == test_tree_1->size, "expect the size of the subtree to be 2");
	cr_expect(45 == test_tree_1->byte_size, "expect the byte size of the tree to be 45");
	cr_expect(NULL != np_tree_find_str(test_tree_1, "halli"), "expect element to be present");
	cr_expect(0 == strncmp("galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 5),
				"expect element to be the same string");

	np_tree_replace_str(test_tree_1, "halli", np_treeval_new_s("other_galli"));

	cr_expect(2 == test_tree_1->size, "expect the size of the subtree to be 2");
	cr_expect(51 == test_tree_1->byte_size, "expect the byte size of the tree to be 51");
	cr_expect(NULL != np_tree_find_str(test_tree_1, "halli"), "expect element to be present");
	cr_expect(0 != strncmp("galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 5),
				"expect element to be not the same string");
	cr_expect(0 == strncmp("other_galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 11),
				"expect element to be changed");

}
