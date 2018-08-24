//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "event/ev.h"
#include "np_log.h"
#include "np_tree.h"
#include "np_treeval.h"

#include "../test_macros.c"

TestSuite(np_tree_t);


#define cr_expect_np_tree_bytesize(tree, ele, expected_size_parts, expected_size_total)		\
	cr_expect(  expected_size_parts == (tmp_ui32 = np_tree_get_byte_size(ele)), "expect byte size of element to be "#expected_size_parts" but is %"PRIu32, tmp_ui32); \
	cr_expect(  expected_size_total == (tmp_ui32 = test_tree_1->byte_size), "expect byte size to be "#expected_size_total" but is %"PRIu32, tmp_ui32)

Test(np_tree_t, tree_node_insert_str, .description = "test the insertion into a tree (string key)")
{
	CTX() {
		np_tree_t* test_tree_1 = np_tree_create();
		uint32_t tmp_ui32;

		// check empty tree
		cr_expect(NULL != test_tree_1, "expect test_tree_1 pointer to exists");
		cr_expect(NULL == test_tree_1->rbh_root, "expect rbh_root to be NULL");
		cr_expect(0 == test_tree_1->size, "expect size of tree to be 0");
		cr_expect(5 == test_tree_1->byte_size, "expect minimum byte size to be 5");

		// add the first kev value pair
		np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
		cr_expect(1 == test_tree_1->size, "expect size of tree to be 1");
		cr_assert(NULL != test_tree_1->rbh_root, "expect rbh_root to be not NULL");
		cr_expect_np_tree_bytesize(test_tree_1, test_tree_1->rbh_root, 22, 27);
		np_tree_elem_t* tmp = test_tree_1->rbh_root;
		cr_expect(np_treeval_type_char_ptr == tmp->key.type, "expect the key to be of the type char_ptr");
		cr_expect(0 == strncmp("halli", np_treeval_to_str(tmp->key, NULL), 10), "expect the key to be the string 'halli'");
		cr_expect(np_treeval_type_char_ptr == tmp->val.type, "expect the value to be of the type char_ptr");
		cr_expect(0 == strncmp("galli", np_treeval_to_str(tmp->val, NULL), 10), "expect the value to be the string 'galli'");

		// try to add a key value pair without success
		np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galligallo"));
		cr_expect(tmp == test_tree_1->rbh_root, "expect the key to not change (insert will not replace");
		cr_expect(np_treeval_type_char_ptr == tmp->key.type, "expect the key to be of the type char_ptr");
		cr_expect(0 == strncmp("halli", np_treeval_to_str(tmp->key, NULL), 10), "expect the key to be the string 'halli'");
		cr_expect(np_treeval_type_char_ptr == tmp->val.type, "expect the value to be of the type char_ptr");
		cr_expect(0 == strncmp("galli", np_treeval_to_str(tmp->val, NULL), 10), "expect the value to be the string 'galli'");
		cr_expect_np_tree_bytesize(test_tree_1, test_tree_1->rbh_root, 22, 27);

		// replace the key value pair 
		np_tree_replace_str(test_tree_1, "halli", np_treeval_new_s("gallogalli"));
		cr_expect(tmp == test_tree_1->rbh_root, "expect the key to not change (replace only replaces value)");
		cr_expect(1 == test_tree_1->size, "expect size of tree to be 1");
		cr_expect_np_tree_bytesize(test_tree_1, test_tree_1->rbh_root, 27, 32);
		cr_expect(np_treeval_type_char_ptr == tmp->key.type, "expect the key to be of the type char_ptr");
		cr_expect(0 == strncmp("halli", np_treeval_to_str(tmp->key, NULL), 10), "expect the key to be the string 'halli'");
		cr_expect(np_treeval_type_char_ptr == tmp->val.type, "expect the value to be of the type char_ptr");
		cr_expect(0 == strncmp("gallogalli", np_treeval_to_str(tmp->val, NULL), 12), "expect the value to be the string 'galli'");

		// add an additional key value pair
		np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));
		// verify new key value
		cr_expect(2 == test_tree_1->size, "expect size of tree to be 2");
		tmp = np_tree_find_str(test_tree_1, "hallo");
		cr_assert(tmp != NULL, "require key \"hallo\" to be present");
		cr_expect_np_tree_bytesize(test_tree_1, tmp, 22, 54);
		cr_expect(np_treeval_type_char_ptr == tmp->key.type, "expect the key to be of the type char_ptr");
		cr_expect(0 == strncmp("hallo", np_treeval_to_str(tmp->key, NULL), 10), "expect the key to be the string 'hallo'");
		cr_expect(np_treeval_type_char_ptr == tmp->val.type, "expect the value to be of the type char_ptr");
		cr_expect(0 == strncmp("gulli", np_treeval_to_str(tmp->val, NULL), 10), "expect the value to be the string 'gulli'");
		// verify old key value
		tmp = np_tree_find_str(test_tree_1, "halli");
		cr_assert(tmp != NULL, "require key \"halli\" to be present");
		cr_expect(np_treeval_type_char_ptr == tmp->key.type, "expect the key to be of the type char_ptr");
		cr_expect(0 == strncmp("halli", np_treeval_to_str(tmp->key, NULL), 10), "expect the key to be the string 'halli'");
		cr_expect(np_treeval_type_char_ptr == tmp->val.type, "expect the value to be of the type char_ptr");
		cr_expect(0 == strncmp("gallogalli", np_treeval_to_str(tmp->val, NULL), 10), "expect the value to be the string 'gallogalli'");

		// remove all entries
		np_tree_clear(test_tree_1);
		cr_expect(NULL == test_tree_1->rbh_root, "expect rbh_root to be NULL");
		cr_expect(0 == test_tree_1->size, "expect size of tree to be 0");
		cr_expect(5 == test_tree_1->byte_size, "expect minimum byte size to be 5");

		np_tree_free(test_tree_1);
	}
}

Test(np_tree_t, tree_node_insert_tree, .description = "test the insertion of a tree into tree")
{
	CTX() {
		np_tree_t* test_tree_1 = np_tree_create();
		np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
		np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));
		cr_expect(2 == test_tree_1->size, "expect size of tree to be 2");

		np_tree_t* test_tree_2 = np_tree_create();
		cr_expect(0 == test_tree_2->size, "expect size of tree to be 0");

		char* from = "from";
		char* to = "to";
		char* id = "id";
		char* exp = "exp";
		char* mail = "mail";

		char* me = "me";
		char* you = "you";
		char* mail_t = "signed.by.me@test.de";

		np_tree_insert_str(test_tree_2, from, np_treeval_new_s(me));
		cr_expect(1 == test_tree_2->size, "expect size of tree to be 1");

		np_tree_insert_str(test_tree_2, to, np_treeval_new_s(you));
		cr_expect(2 == test_tree_2->size, "expect size of tree to be 2");

		np_tree_insert_str(test_tree_2, id, np_treeval_new_i(18000));
		cr_expect(3 == test_tree_2->size, "expect size of tree to be 3");

		np_tree_insert_str(test_tree_2, exp, np_treeval_new_d(5.0));
		cr_expect(4 == test_tree_2->size, "expect size of tree to be 4");

		np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
		cr_expect(5 == test_tree_2->size, "expect size of tree to be 5");

#ifdef x64
		np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
		cr_expect(6 == test_tree_2->size, "expect size of tree to be 6");
#endif

		np_tree_insert_str(test_tree_2, "tree_1", np_treeval_new_tree(test_tree_1));
		cr_expect(7 == test_tree_2->size, "expect size of tree to be 7");

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
}
Test(np_tree_t, tree_node_find_tree, .description = "test lookup of data in a tree")
{
	CTX() {
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
		np_tree_insert_str(test_tree_2, to, np_treeval_new_s(you));
		np_tree_insert_str(test_tree_2, id, np_treeval_new_i(18000));
		np_tree_insert_str(test_tree_2, exp, np_treeval_new_d(5.0));
		np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
#ifdef x64
		np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
#endif
		np_tree_insert_str(test_tree_2, "tree_1", np_treeval_new_tree(test_tree_1));

		cr_expect(NULL == np_tree_find_str(test_tree_1, "dummy"),
			"expect a result of NULL");

		uint8_t found = 0;
		cr_expect(NULL != np_tree_find_gte_str(test_tree_1, "dummy", &found),
			"expect a result of non NULL");
		cr_expect(0 == found,
			"expect a vaue of 0 for found indicator");
		cr_expect(2 == test_tree_1->size,
			"expect size of tree to be 2");

		cr_expect(NULL != np_tree_find_str(test_tree_2, from), "expect a result of non NULL");
		cr_expect(0 == strncmp(me, np_tree_find_str(test_tree_2, from)->val.value.s, 3),
			"expect a result of literal 'me'");
		cr_expect(0 == strncmp(from, np_tree_find_str(test_tree_2, from)->key.value.s, 5),
			"expect a result of literal 'from'");

		found = 0;
		cr_expect(NULL != np_tree_find_gte_str(test_tree_2, from, &found),
			"expect a result of non NULL");
		cr_expect(1 == found,
			"expect a vaue of 1 for found indicator");

		found = 0;
		cr_expect(0 == strncmp(from, np_tree_find_gte_str(test_tree_2, from, &found)->key.value.s, 5),
			"expect a result of literal me");
		cr_expect(1 == found,
			"expect a vaue of 1 for found indicator");

		found = 0;
		cr_expect(0 == strncmp(me, np_tree_find_gte_str(test_tree_2, from, &found)->val.value.s, 3),
			"expect a result of literal me");
		cr_expect(1 == found,
			"expect a vaue of 1 for found indicator");
	}

}

Test(np_tree_t, tree_node_del_tree, .description = "test deletion of data in a tree")
{
	CTX() {
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
		np_tree_insert_str(test_tree_2, to, np_treeval_new_s(you));
		np_tree_insert_str(test_tree_2, id, np_treeval_new_i(18000));
		np_tree_insert_str(test_tree_2, exp, np_treeval_new_d(5.0));
		np_tree_insert_str(test_tree_2, mail, np_treeval_new_s(mail_t));
#ifdef x64
		np_tree_insert_str(test_tree_2, "ul", np_treeval_new_ull(4905283925042198132));
#endif
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
}

Test(np_tree_t, tree_node_repl_tree, .description = "test replacement of data in a tree")
{
	CTX() {
		np_tree_t* test_tree_1 = np_tree_create();
		np_tree_insert_str(test_tree_1, "halli", np_treeval_new_s("galli"));
		np_tree_insert_str(test_tree_1, "hallo", np_treeval_new_s("gulli"));

		cr_expect(2 == test_tree_1->size, "expect the size of the subtree to be 2");
		cr_expect(49 == test_tree_1->byte_size, "expect the byte size of the tree to be 49");

		cr_expect(NULL != np_tree_find_str(test_tree_1, "halli"), "expect element to be present");
		cr_expect(0 == strncmp("galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 5),
			"expect element to be the same string");

		np_tree_replace_str(test_tree_1, "halli", np_treeval_new_s("other_galli"));

		cr_expect(2 == test_tree_1->size, "expect the size of the subtree to be 2");
		cr_expect(55 == test_tree_1->byte_size, "expect the byte size of the tree to be 55");
		cr_expect(NULL != np_tree_find_str(test_tree_1, "halli"), "expect element to be present");
		cr_expect(0 != strncmp("galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 10),
			"expect element to be not the same string");
		cr_expect(0 == strncmp("other_galli", np_tree_find_str(test_tree_1, "halli")->val.value.s, 20),
			"expect element to be changed");

	}
}