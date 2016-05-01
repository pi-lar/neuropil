#include <criterion/criterion.h>

#include "event/ev.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_val.h"

void setup_jrb(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	np_log_init("test_jrb_impl.log", log_level);
}

void teardown_jrb(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_jrb_t, .init=setup_jrb, .fini=teardown_jrb);

Test(np_jrb_t, jrb_node_insert_str, .description="test the insertion into a jtree (string key)")
{
	np_tree_t* test_jrb_1 = make_jtree();

	cr_expect(NULL != test_jrb_1, "expect test_jrb_1 pointer to exists");
	cr_expect(NULL == test_jrb_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_jrb_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_jrb_1->byte_size, "expect minimum byte size to be 5");

	tree_insert_str(test_jrb_1, "halli", new_val_s("galli"));

	cr_expect(   1 == test_jrb_1->size, "expect size of tree to be 1");
	cr_expect(  20 == jrb_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 20");
	cr_expect(  25 == test_jrb_1->byte_size, "expect byte size to be 25");
	cr_expect(NULL != test_jrb_1->rbh_root, "expect rbh_root to be not NULL");

	np_tree_elem_t* tmp = test_jrb_1->rbh_root;
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galli", tmp->val.value.s, 10), "expect the value to be the string 'galli'");

	tree_insert_str(test_jrb_1, "halli", new_val_s("galligallo"));
	cr_expect(tmp == test_jrb_1->rbh_root, "expect the key to not change (insert will not replace");
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galli", tmp->val.value.s, 10), "expect the value to be the string 'galli'");

	tree_replace_str(test_jrb_1, "halli", new_val_s("galligallo"));
	cr_expect(tmp == test_jrb_1->rbh_root, "expect the key to not change (replace only replaces value)");
	cr_expect(  1 == test_jrb_1->size, "expect size of tree to be 1");
	cr_expect( 25 == jrb_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 25");
	cr_expect( 30 == test_jrb_1->byte_size, "expect byte size to be 30");
	cr_expect(char_ptr_type == tmp->key.type, "expect the key to be of the type char_ptr");
	cr_expect(0 == strncmp("halli", tmp->key.value.s, 10), "expect the key to be the string 'halli'");
	cr_expect(char_ptr_type == tmp->val.type, "expect the value to be of the type char_ptr");
	cr_expect(0 == strncmp("galligallo", tmp->val.value.s, 12), "expect the value to be the string 'galli'");

	tree_insert_str(test_jrb_1, "hallo", new_val_s("gulli"));
	cr_expect(  2 == test_jrb_1->size, "expect size of tree to be 2");
	cr_expect( 25 == jrb_get_byte_size(test_jrb_1->rbh_root), "expect byte size to be 25");
	cr_expect( 50 == test_jrb_1->byte_size, "expect byte size to be 50");

	np_clear_tree (test_jrb_1);
	cr_expect(NULL == test_jrb_1->rbh_root, "expect rbh_root to be NULL");
	cr_expect(   0 == test_jrb_1->size, "expect size of tree to be 0");
	cr_expect(   5 == test_jrb_1->byte_size, "expect minimum byte size to be 5");

	np_free_tree(test_jrb_1);
}

Test(np_jrb_t, jrb_node_insert_tree, .description="test the insertion of a tree into tree")
{
	np_tree_t* test_jrb_1 = make_jtree();
	tree_insert_str(test_jrb_1, "halli", new_val_s("galli"));
	tree_insert_str(test_jrb_1, "hallo", new_val_s("gulli"));
	cr_expect(   2 == test_jrb_1->size, "expect size of tree to be 2");

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

	tree_insert_str(test_jrb_2, from, new_val_s(me));
	cr_expect(   1 == test_jrb_2->size, "expect size of tree to be 1");

	tree_insert_str(test_jrb_2, to,   new_val_s(you));
	cr_expect(   2 == test_jrb_2->size, "expect size of tree to be 2");

	tree_insert_str(test_jrb_2, id,   new_val_i(18000));
	cr_expect(   3 == test_jrb_2->size, "expect size of tree to be 3");

	tree_insert_str(test_jrb_2, exp,  new_val_d(5.0));
	cr_expect(   4 == test_jrb_2->size, "expect size of tree to be 4");

	tree_insert_str(test_jrb_2, mail, new_val_s(mail_t));
	cr_expect(   5 == test_jrb_2->size, "expect size of tree to be 5");

	tree_insert_str(test_jrb_2, "ul", new_val_ull(4905283925042198132));
	cr_expect(   6 == test_jrb_2->size, "expect size of tree to be 6");

	tree_insert_str(test_jrb_2, "tree_1", new_val_tree(test_jrb_1));
	cr_expect(   7 == test_jrb_2->size, "expect size of tree to be 7");

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
