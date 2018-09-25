//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version is based on the chimera project
/* Revision 1.2.  Jim Plank */

/* Original code by Jim Plank (plank@cs.utk.edu) */
/* modified for THINK C 6.0 for Macintosh by Chris Bartley */
/* modified for neuropil 2015 pi-lar GmbH Stephan Schwichtenberg */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <pthread.h>
#include <inttypes.h>

#include "sodium.h"


#include "np_tree.h"
#include "np_treeval.h"

#include "np_serialization.h"
#include "np_util.h"
#include "np_log.h"
#include "np_dhkey.h"


/* A list of replaceable strings.
	do not include more than 255 items here
	or expand the special_char_ptr implementation of the tree
*/
const char* const np_special_strs[] = {
	//"np.test1",	// for test purposes. do not include into list
	"np.test2",	// for test purposes
	"localhost",
	"np.test3",	// for test purposes
	"_np.ack",
	"_np.ack_to",
	"_np.from",
	"_np.garbage",
	"_np.parts",
	"_np.r_to",
	"_np.sendnr",
	"_np.seq",
	"_np.subj",
	"_np.to",
	"_np.tstamp",
	"_np.ttl",
	"_np.uuid",
	"ack_mode",
	"max_threshold",
	"mep_type",
	"msg_threshold",
	"np.n.d",
	"np.n.k",
	"np.n.p",
	"np.n.pr",
	"np.t.a",
	"np.t.c",
	"np.t.e",
	"np.t.ex",
	"np.t.i",
	"np.t.ia",
	"np.t.nb",
	"np.t.p",
	"np.t.r",
	"np.t.s",
	"np.t.si",
	"np.t.u",
	"np.t.partner",
	"np.t.signature_extensions",
	"_np.token.ident",
	"_np.token.node",

	"_NP.DEFAULT",
	"_NP.ACK",
	"_NP.HANDSHAKE",
	"_NP.PING.REQUEST",
	"_NP.LEAVE.REQUEST",
	"_NP.JOIN.",
	"_NP.JOIN.REQUEST",
	"_NP.JOIN.ACK",
	"_NP.JOIN.NACK",
	"_NP.NODES.PIGGY",
	"_NP.NODES.UPDATE",
	"_NP.MESSAGE.DISCOVER.RECEIVER",
	"_NP.MESSAGE.DISCOVER.SENDER",
	"_NP.MESSAGE.RECEIVER.LIST",
	"_NP.MESSAGE.SENDER.LIST",
	"_NP.MESSAGE.AUTHENTICATE",
	"_NP.MESSAGE.AUTHENICATION.REPLY",
	"_NP.MESSAGE.AUTHORIZE",
	"_NP.MESSAGE.AUTHORIZATION.REPLY",
	"_NP.MESSAGE.ACCOUNT",
	"_NP.MESSAGE.ACCOUNT",
	"_NP.MESSAGE.ACCOUNT",

	"_NP.SYSINFO.REQUEST",
	"_NP.SYSINFO.REPLY",
	"node",
	"timestamp",
	"neighbour_nodes",
	"routing_nodes",
	"source_hash",
	"target_hash",

};

RB_GENERATE(np_tree_s, np_tree_elem_s, link, _np_tree_elem_cmp);

//RB_GENERATE_STATIC(np_str_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
//RB_GENERATE_STATIC(np_int_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
//RB_GENERATE_STATIC(np_dbl_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);
//RB_GENERATE_STATIC(np_ulong_jtree, np_tree_elem_s, link, _np_tree_elem_cmp);

/*
	Allocates space for a new tree structure.

	:param:in_place: disables the copy of values behaviour for this tree (and subtrees)
*/
np_tree_t* np_tree_create()
{
	np_tree_t* new_tree = (np_tree_t*)malloc(sizeof(np_tree_t));
	CHECK_MALLOC(new_tree);

	memset(&new_tree->attr, 0, sizeof(np_tree_conf_t));
	
	new_tree->size = 0;
	new_tree->rbh_root = NULL;
	new_tree->byte_size = 5;

	return new_tree;
}

bool _np_tree_is_special_str(const char* in_question, uint8_t* idx_on_found) {
	bool ret = false;		
	return ret; //FIXME: special strings!
	uint8_t item_count = sizeof(np_special_strs) / sizeof(np_special_strs[0]);
	for (uint8_t i = 0; i < item_count; i++) {
		const char* special_str = np_special_strs[i];
	
		if (strncmp(special_str, in_question, strlen(special_str)+1/*+ NULL Terminator*/) == 0) {
			if(idx_on_found != NULL){
				//log_debug_msg(LOG_TREE | LOG_DEBUG, "idx detected for %15s at %3"PRIu8" saving into %p",in_question, i, idx_on_found);
				*idx_on_found = i;
			}
			ret = true;
			break;
		}
	}
	/*
	if (!ret) {
		log_debug_msg(LOG_TREE | LOG_DEBUG, "not in np_special_strs dictionary: \"%s\"", in_question);
	}
	*/

	return ret;
}

const char* _np_tree_get_special_str(uint8_t idx) {
	return np_special_strs[idx];
}

int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2)
{
	log_trace_msg(LOG_TRACE, "start: int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2){");
	assert(NULL != j1);
	assert(NULL != j2);

	np_treeval_t jv1 = j1->key;
	np_treeval_t jv2 = j2->key;

	if (jv1.type == jv2.type)
	{
		if (jv1.type == np_treeval_type_char_ptr) {
			return strncmp(jv1.value.s, jv2.value.s, strlen(jv1.value.s)+1);
		}
		else if (jv1.type == np_treeval_type_special_char_ptr){
			int res = (int)jv1.value.ush - (int)jv2.value.ush;
			if (res < 0) return -1;
			if (res > 0) return  1;
			return 0;
		}
		else if (jv1.type == np_treeval_type_double)
		{
			// log_debug_msg(LOG_DEBUG, "comparing %f - %f = %d",
			// 		jv1.value.d, jv2.value.d, (int16_t) (jv1.value.d-jv2.value.d) );
			double res = jv1.value.d - jv2.value.d;
			if (res < 0) return -1;
			if (res > 0) return  1;
			return 0;
		}
		else if (jv1.type == np_treeval_type_unsigned_long) {
			return (int16_t)(jv1.value.ul - jv2.value.ul);
		}
		else if (jv1.type == np_treeval_type_int) {
			return (int16_t)(jv1.value.i - jv2.value.i);
		}
		else if (jv1.type == np_treeval_type_dhkey) {
			return (int16_t)_np_dhkey_cmp(&jv1.value.dhkey, &jv2.value.dhkey);
		}
	}
	return (((int)jv1.type - (int) jv2.type) > 0);
};

np_tree_elem_t* np_tree_find_gte_str(np_tree_t* n, const char *key, uint8_t *fnd)
{
	assert(n != NULL);
	assert(key != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = np_treeval_type_char_ptr,.value.s = (char*)key };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		0 == strncmp(result->key.value.s, key, strlen(key)))
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}
	return (result);
}

np_tree_elem_t* np_tree_find_special_str(np_tree_t* n, const uint8_t key)
{
	assert(NULL != n);

	np_treeval_t search_key = { .type = np_treeval_type_special_char_ptr, .value.ush = key };
	np_tree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_tree_s, n, &search_elem);
}

np_tree_elem_t* np_tree_find_str(np_tree_t* n, const char *key)
{
	assert(NULL != n);
	assert(NULL != key);

	np_tree_elem_t* ret = NULL;
	uint8_t idx = 0;
	if (_np_tree_is_special_str(key, &idx)) {
		ret = np_tree_find_special_str(n, idx);
	} 
	if(ret == NULL) 
	{
		np_treeval_t search_key = { .type = np_treeval_type_char_ptr, .value.s = (char*)key };
		np_tree_elem_t search_elem = { .key = search_key };
		ret = RB_FIND(np_tree_s, n, &search_elem);
	}
	return ret;
}

np_tree_elem_t* np_tree_find_gte_int(np_tree_t* n, int16_t ikey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = np_treeval_type_int,.value.i = ikey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.i == ikey)
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}

np_tree_elem_t* np_tree_find_int(np_tree_t* n, int16_t key)
{
	np_treeval_t search_key = { .type = np_treeval_type_int,.value.i = key };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* np_tree_find_dhkey(np_tree_t* n, np_dhkey_t key)
{
	np_treeval_t search_key = { .type = np_treeval_type_dhkey,.value.dhkey = key };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* np_tree_find_gte_ulong(np_tree_t* n, uint32_t ulkey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = np_treeval_type_unsigned_long,.value.ul = ulkey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.ul == ulkey)
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}

np_tree_elem_t* np_tree_find_ulong(np_tree_t* n, uint32_t ulkey)
{
	np_treeval_t search_key = { .type = np_treeval_type_unsigned_long,.value.ul = ulkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* np_tree_find_gte_dbl(np_tree_t* n, double dkey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = np_treeval_type_double,.value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.d == dkey)
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}

np_tree_elem_t* np_tree_find_dbl(np_tree_t* n, double dkey)
{
	np_treeval_t search_key = { .type = np_treeval_type_double,.value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

void _np_tree_cleanup_treeval(np_tree_t* tree, np_treeval_t toclean) {
	if(tree->attr.in_place == false){
		if (toclean.type == np_treeval_type_char_ptr) free(toclean.value.s);
		if (toclean.type == np_treeval_type_bin) free(toclean.value.bin);
	}
	if (toclean.type == np_treeval_type_jrb_tree) { np_tree_free(toclean.value.tree); }

}

void np_tree_del_element(np_tree_t* tree, np_tree_elem_t* to_delete)
{
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);

		tree->byte_size -= np_tree_get_byte_size(to_delete);
		tree->size--;

		_np_tree_cleanup_treeval(tree, to_delete->key);
		_np_tree_cleanup_treeval(tree, to_delete->val);

		free(to_delete);
	}

}

void __np_tree_immutable_check(np_tree_t* tree) {
	assert(tree->attr.immutable == false && "Tree is not in a state of modification");
}

void np_tree_del_special_str(np_tree_t* tree, const uint8_t idx)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_special_str(tree, idx));
}

void np_tree_del_str(np_tree_t* tree, const char *key)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_str(tree, key));
}

void np_tree_del_int(np_tree_t* tree, const int16_t key)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_int(tree, key));
}

void np_tree_del_dhkey(np_tree_t* tree, const np_dhkey_t key)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_dhkey(tree, key));
}

void np_tree_del_double(np_tree_t* tree, const double dkey)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_dbl(tree,dkey));
}

void np_tree_del_ulong(np_tree_t* tree, const uint32_t key)
{
	__np_tree_immutable_check(tree);
	np_tree_del_element(tree, np_tree_find_ulong(tree,key));
}

void np_tree_clear(np_tree_t* n)
{	
	np_tree_elem_t* iter = RB_MIN(np_tree_s, n);

	while(NULL != iter)
	{		
		np_tree_del_element(n, iter);
		iter = RB_MIN(np_tree_s, n);
	}
}

void np_tree_free(np_tree_t* n)
{
	if (NULL != n) {
		if (n->size > 0) {
			np_tree_clear(n);
		}
		free(n);
		n = NULL;
	}
}

void _np_tree_replace_all_with_str(np_tree_t* n, const char* key, np_treeval_t val)
{
	log_trace_msg(LOG_TRACE, "start: void _np_tree_replace_all_with_str(np_tree_t* n, const char* key, np_treeval_t val){");
	np_tree_clear(n);
	np_tree_insert_str( n, key, val);
}

uint32_t np_tree_get_byte_size(np_tree_elem_t* node)
{
	log_trace_msg(LOG_TRACE, "start: uint32_t np_tree_get_byte_size(np_tree_elem_t* node){");
	assert(node != NULL);

	uint32_t byte_size = np_treeval_get_byte_size(node->key) + np_treeval_get_byte_size(node->val);

	return byte_size;
}

void np_tree_insert_element(np_tree_t* tree, np_tree_elem_t* ele) {
	__np_tree_immutable_check(tree);
	RB_INSERT(np_tree_s, tree, ele);
	tree->size++;
	tree->byte_size += np_tree_get_byte_size(ele);
}

void np_tree_insert_special_str(np_tree_t* tree, const uint8_t idx, np_treeval_t val)
{
	np_tree_elem_t* found = np_tree_find_special_str(tree, idx);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.ush = idx;
		found->key.type = np_treeval_type_special_char_ptr;
		found->key.size = sizeof(uint8_t);

		np_tree_set_treeval(tree, found, val);
		np_tree_insert_element(tree, found);
	}
}

void np_tree_insert_str(np_tree_t* tree, const char *key, np_treeval_t val)
{
	assert(tree != NULL);
	assert(key != NULL);

	uint8_t idx = 0;
	if (tree->attr.disable_special_str == false && _np_tree_is_special_str(key, &idx)) {
		np_tree_insert_special_str(tree, idx, val);
	} else {
		np_tree_elem_t* found = np_tree_find_str(tree, key);

		if (found == NULL)
		{
			// insert new value
			found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
			CHECK_MALLOC(found);

			if (tree->attr.in_place == true) {
				found->key.value.s = (char*) key;
			}
			else {
				found->key.value.s = strndup(key, 255);
			}

			found->key.type = np_treeval_type_char_ptr;
			found->key.size = strnlen(found->key.value.s,255);

			np_tree_set_treeval(tree, found, val);
			np_tree_insert_element(tree, found);
		}
	}
}

void np_tree_insert_int(np_tree_t* tree, int16_t ikey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_int(tree, ikey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.i = ikey;
		found->key.type = np_treeval_type_int;
		found->key.size = sizeof(int16_t);
		np_tree_set_treeval(tree, found, val);
		np_tree_insert_element(tree, found);
	}
}


void np_tree_insert_dhkey(np_tree_t* tree, np_dhkey_t key, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_dhkey(tree, key);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.dhkey = key;
		found->key.type = np_treeval_type_dhkey;
		found->key.size = sizeof(np_dhkey_t);
		np_tree_set_treeval(tree, found, val);
		np_tree_insert_element(tree, found);
	}
}

void np_tree_insert_ulong(np_tree_t* tree, uint32_t ulkey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_ulong(tree, ulkey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.ul = ulkey;
		found->key.type = np_treeval_type_unsigned_long;
		found->key.size = sizeof(uint32_t);

		np_tree_set_treeval(tree, found, val);
		np_tree_insert_element(tree, found);
	}
}

void np_tree_insert_dbl(np_tree_t* tree, double dkey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_dbl(tree, dkey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.d = dkey;
		found->key.type = np_treeval_type_double;
		found->key.size = sizeof(double);

		np_tree_set_treeval(tree, found, val);
		np_tree_insert_element(tree, found);
	}
	else
	{
		// log_msg(LOG_WARN, "not inserting double key (%f) into jtree", dkey );
	}
}

void np_tree_set_treeval(np_tree_t* tree, np_tree_elem_t* element, np_treeval_t val) {

	if (tree->attr.in_place == false){
		element->val = np_treeval_copy_of_val(val);
	}
	else{
		//memmove(&element->val, &val, sizeof(np_treeval_t));
		//memset(&element->val, &val, sizeof(np_treeval_t));
		memcpy(&element->val, &val, sizeof(np_treeval_t));
	}

}

void np_tree_replace_treeval(np_tree_t* tree, np_tree_elem_t* element, np_treeval_t val) {

	__np_tree_immutable_check(tree);
	// free up memory before replacing
	tree->byte_size -= np_tree_get_byte_size(element);

	_np_tree_cleanup_treeval(tree, element->val);
	np_tree_set_treeval(tree, element, val);
	tree->byte_size += np_tree_get_byte_size(element);
}

void np_tree_replace_special_str(np_tree_t* tree, const uint8_t key, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_special_str(tree, key);

	if (found == NULL)
	{
		// insert new value
		np_tree_insert_special_str(tree, key, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_replace_str(np_tree_t* tree, const char *key, np_treeval_t val)
{
	assert(tree != NULL);
	assert(key != NULL);

	np_tree_elem_t* found = np_tree_find_str(tree, key);

	if (found == NULL)
	{
		// insert new value
		np_tree_insert_str( tree, key, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_replace_int(np_tree_t* tree, int16_t ikey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_int(tree, ikey);

	if (found == NULL)
	{
		// insert new value
		np_tree_insert_int(tree, ikey, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_replace_dhkey(np_tree_t* tree, np_dhkey_t key, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_dhkey(tree, key);

	if (found == NULL)
	{
		// insert new value
		np_tree_insert_dhkey(tree, key, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_replace_ulong(np_tree_t* tree, uint32_t ulkey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_ulong(tree, ulkey);

	if (found == NULL)
	{
		np_tree_insert_ulong(tree, ulkey, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_replace_dbl(np_tree_t* tree, double dkey, np_treeval_t val)
{
	assert(tree != NULL);

	np_tree_elem_t* found = np_tree_find_dbl(tree, dkey);

	if (found == NULL)
	{
		// insert new value
		np_tree_insert_dbl( tree, dkey, val);
	}
	else
	{
		np_tree_replace_treeval(tree, found, val);
	}
}

void np_tree_copy(np_tree_t* source, np_tree_t* target) {
	np_tree_elem_t* tmp = NULL;

	assert(source != NULL);
	assert(target != NULL);

	RB_FOREACH(tmp, np_tree_s, source)
	{
		if (tmp->key.type == np_treeval_type_char_ptr)					np_tree_insert_str( target, tmp->key.value.s, tmp->val);
		else if (tmp->key.type == np_treeval_type_special_char_ptr)	np_tree_insert_special_str(target, tmp->key.value.ush, tmp->val);
		else if (tmp->key.type == np_treeval_type_int)					np_tree_insert_int(target, tmp->key.value.i, tmp->val);
		else if (tmp->key.type == np_treeval_type_double)				np_tree_insert_dbl( target, tmp->key.value.d, tmp->val);
		else if (tmp->key.type == np_treeval_type_unsigned_long)		np_tree_insert_ulong(target, tmp->key.value.ul, tmp->val);
		else if (tmp->key.type == np_treeval_type_dhkey)		np_tree_insert_dhkey(target, tmp->key.value.dhkey, tmp->val);
	}
}

void np_tree_copy_inplace(np_tree_t* source, np_tree_t* target) {
	np_tree_elem_t* tmp = NULL;

	assert(source != NULL);
	assert(target != NULL);

	RB_FOREACH(tmp, np_tree_s, source)
	{
		if (tmp->key.type == np_treeval_type_char_ptr)					np_tree_replace_str(target, tmp->key.value.s, tmp->val);
		else if (tmp->key.type == np_treeval_type_special_char_ptr)	np_tree_replace_special_str(target, tmp->key.value.ush, tmp->val);
		else if (tmp->key.type == np_treeval_type_int)					np_tree_replace_int(target, tmp->key.value.i, tmp->val);
		else if (tmp->key.type == np_treeval_type_double)				np_tree_replace_dbl( target, tmp->key.value.d, tmp->val);
		else if (tmp->key.type == np_treeval_type_unsigned_long)		np_tree_replace_ulong(target, tmp->key.value.ul, tmp->val);
		else if (tmp->key.type == np_treeval_type_dhkey)		np_tree_replace_dhkey(target, tmp->key.value.dhkey, tmp->val);
	}
}

np_tree_t* np_tree_clone(np_tree_t* source) {
	log_trace_msg(LOG_TRACE, "start: np_tree_t* np_tree_clone(np_tree_t* source) {");

	np_tree_t* ret = np_tree_create();
	memcpy(&ret->attr, &source->attr, sizeof(np_tree_conf_t));
	ret->attr.in_place = false;
	bool old = ret->attr.immutable;
	ret->attr.immutable = false;
	np_tree_copy(source, ret);
	ret->attr.immutable = old;
	return ret;
}

void np_tree_serialize(np_state_t* context, np_tree_t* jtree, cmp_ctx_t* cmp)
{
	log_trace_msg(LOG_TRACE, "start: void np_tree_serialize(context, np_tree_t* jtree, cmp_ctx_t* cmp){");
	uint16_t i = 0;
	// first assume a size based on jrb size

	if (!cmp_write_map32(cmp, jtree->size * 2)) return;

	// write jrb tree
	if (0 < jtree->size)
	{
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, jtree)
		{

			if (np_treeval_type_int == tmp->key.type ||
				np_treeval_type_dhkey == tmp->key.type ||
				np_treeval_type_unsigned_long == tmp->key.type ||
				np_treeval_type_double == tmp->key.type ||
				np_treeval_type_char_ptr == tmp->key.type ||
				np_treeval_type_special_char_ptr== tmp->key.type)
			{
				// log_debug_msg(LOG_DEBUG, "for (%p; %p!=%p; %p=%p) ", tmp->flink, tmp, msg->header, node, node->flink);
				__np_tree_serialize_write_type(context,tmp->key, cmp); i++;
				__np_tree_serialize_write_type(context, tmp->val, cmp); i++;
			}
			else
			{
				log_msg(LOG_ERROR, "unknown key type for serialization");
			}
		}
	}

	if (i != jtree->size * 2)
		log_msg(LOG_ERROR, "serialized jrb size map size is %d, but should be %hd", jtree->size * 2, i);
}

bool np_tree_deserialize( np_state_t* context, np_tree_t* jtree, cmp_ctx_t* cmp)
{
	log_trace_msg(LOG_TRACE, "start: void np_tree_deserialize( context, np_tree_t* jtree, cmp_ctx_t* cmp){");

	ASSERT(jtree != NULL,"Tree do deserialize cannot be NULL")
	bool ret = true;

	cmp_object_t obj_key = { 0 };
	cmp_object_t obj_val = { 0 };	

	uint32_t size = 0;

	cmp_read_map(cmp, &size);

	if (size == 0){
		return true;
	}
	else if ((size % 2) != 0) {
		return false;
	}


	for (uint32_t i = 0; i < (size / 2); i++)
	{
		// read key
		np_treeval_t tmp_key = { 0 };
		tmp_key.type = np_treeval_type_undefined;
		tmp_key.size = 0;
		cmp_read_object(cmp, &obj_key);
		__np_tree_deserialize_read_type(context, jtree, &obj_key, cmp, &tmp_key,"<<key read>>");

		if (cmp->error != 0 || np_treeval_type_undefined == tmp_key.type) {
			ret = false;
			break;
		}


		// read value
		np_treeval_t tmp_val = { 0 };
		tmp_val.type = np_treeval_type_undefined;
		tmp_val.size = 0;
		cmp_read_object(cmp, &obj_val);

#ifdef DEBUG
		bool free_tmp_key_str = false;
		char * tmp_key_str = np_treeval_to_str(tmp_key, &free_tmp_key_str);
		__np_tree_deserialize_read_type(context, jtree, &obj_val, cmp, &tmp_val, tmp_key_str);
		if (free_tmp_key_str) {
			free(tmp_key_str);
		}
#else
		__np_tree_deserialize_read_type(context, jtree, &obj_val, cmp, &tmp_val, "<<unknown>>");
#endif

		if (cmp->error != 0 || np_treeval_type_undefined == tmp_val.type) {
			ret = false;
			break;
		}

		// add key value pair to tree
		switch (tmp_key.type)
		{
		case np_treeval_type_int:
			np_tree_insert_int(jtree, tmp_key.value.i, tmp_val);
			break;
		case np_treeval_type_dhkey:
			np_tree_insert_dhkey(jtree, tmp_key.value.dhkey, tmp_val);
			break;
		case np_treeval_type_unsigned_long:
			np_tree_insert_ulong(jtree, tmp_key.value.ul, tmp_val);
			break;
		case np_treeval_type_double:
			np_tree_insert_dbl( jtree, tmp_key.value.d, tmp_val);
			break;
		case np_treeval_type_char_ptr:
			np_tree_insert_str( jtree, tmp_key.value.s, tmp_val);
			break;
		case np_treeval_type_special_char_ptr:
			np_tree_insert_special_str(jtree, tmp_key.value.ush, tmp_val);
			break;
		default:
			tmp_val.type = np_treeval_type_undefined;
			break;
		}

		_np_tree_cleanup_treeval(jtree, tmp_key);
		if(jtree->attr.in_place == false || tmp_val.type != np_treeval_type_jrb_tree){
			_np_tree_cleanup_treeval(jtree, tmp_val);
		}

	}

	if(cmp->error != 0) {
		 log_msg(LOG_INFO, "Deserialization error: %s", cmp_strerror(cmp));
	}

	if (ret == false) {
		log_debug_msg(LOG_SERIALIZATION | LOG_TREE | LOG_WARN, "Deserialization error: unspecified error");
	}
	else {
		if (jtree->attr.in_place == true) {
			jtree->attr.immutable = true;
		}
	}
	return ret;
}

uint8_t __np_tree_serialize_read_type_dhkey(cmp_ctx_t* cmp_key, np_treeval_t* target) {
	log_trace_msg(LOG_TRACE, "start: uint8_t __np_tree_serialize_read_type_dhkey(void* buffer_ptr, np_treeval_t* target) {");

	//cmp_ctx_t cmp_key;
	//cmp_init(&cmp_key, buffer_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

	np_dhkey_t empty_key = { 0 };
	np_dhkey_t new_key;

	target->value.dhkey = empty_key;
	target->type = np_treeval_type_dhkey;
	target->size = sizeof(np_dhkey_t);

	bool read_ok = true;
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[0]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[1]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[2]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[3]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[4]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[5]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[6]));
	read_ok &= cmp_read_u32(cmp_key, &(new_key.t[7]));

	if(read_ok){
		target->value.dhkey = new_key;
	}
	else {
		if (cmp_key->error == 0/*ERROR_NONE*/) {
			cmp_key->error = 14;// LENGTH_READING_ERROR;
		}
	}


	return cmp_key->error;
}

void __np_tree_serialize_write_type_dhkey(np_dhkey_t source, cmp_ctx_t* target) {
	log_trace_msg(LOG_TRACE, "start: void __np_tree_serialize_write_type_dhkey(np_dhkey_t source, cmp_ctx_t* target) {");
	// source->size is not relevant here as the transport size includes marker sizes etc..
	//                        8 * (size of uint32 marker + size of key element)
	uint32_t transport_size = 8 * (sizeof(uint8_t) + sizeof(uint32_t));

	cmp_ctx_t key_ctx;
	char buffer[transport_size];
	void* buf_ptr = buffer;
	cmp_init(&key_ctx, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

	bool write_ok = true;
	write_ok &= cmp_write_u32(&key_ctx, source.t[0]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[1]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[2]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[3]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[4]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[5]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[6]);
	write_ok &= cmp_write_u32(&key_ctx, source.t[7]);

	if (key_ctx.error == 0) {
		cmp_write_ext32(target, np_treeval_type_dhkey, transport_size, buf_ptr);
	}
	else {
		target->error = key_ctx.error;
	}
}

uint8_t __np_tree_serialize_read_type_special_str(cmp_ctx_t* cmp, np_treeval_t* target) {
	log_trace_msg(LOG_TRACE, "start: uint8_t __np_tree_serialize_read_type_special_str(void* buffer_ptr, np_treeval_t* target) {");	

	uint8_t idx = 0;
	cmp_read_u8(cmp, &idx);
	target->value.ush = idx;
	target->type = np_treeval_type_special_char_ptr;
	target->size = sizeof(uint8_t);

	return cmp->error;
}

void __np_tree_serialize_write_type_special_str(uint8_t idx, cmp_ctx_t* target) {

	//                        size of uint8 marker + size uint8 for index
	uint32_t transport_size = (sizeof(uint8_t) + sizeof(uint8_t));

	cmp_ctx_t cmp;
	char buffer[transport_size];
	void* buf_ptr = buffer;

	cmp_init(&cmp, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	cmp_write_u8(&cmp, idx);

	if(cmp.error == 0) {
		cmp_write_ext32(target, np_treeval_type_special_char_ptr, transport_size, buf_ptr);
	}
	else {
		target->error = cmp.error;
	}

}

void __np_tree_serialize_write_type(np_state_t* context, np_treeval_t val, cmp_ctx_t* cmp)
{
	log_trace_msg(LOG_TRACE, "start: void __np_tree_serialize_write_type(np_treeval_t val, cmp_ctx_t* cmp){");
	// void* count_buf_start = cmp->buf;
	// log_debug_msg(LOG_DEBUG, "writing jrb (%p) value: %s", jrb, jrb->key.value.s);
	switch (val.type)
	{
		// signed numbers
	case np_treeval_type_short:
		cmp_write_s8(cmp, val.value.sh);
		break;
	case np_treeval_type_int:
		cmp_write_s16(cmp, val.value.i);
		break;
	case np_treeval_type_long:
		cmp_write_s32(cmp, val.value.l);
		break;
#ifdef x64
	case np_treeval_type_long_long:
		cmp_write_s64(cmp, val.value.ll);
		break;
#endif
		// characters
	case np_treeval_type_char_ptr:
		//log_debug_msg(LOG_DEBUG, "string size %u/%lu -> %s", val.size, strlen(val.value.s), val.value.s);
		cmp_write_str32(cmp, val.value.s, val.size + sizeof(char)/*include terminator*/);
		break;

	case np_treeval_type_char:
		cmp_write_fixstr(cmp, (const char*)&val.value.c, sizeof(char));
		break;
		//	case np_treeval_type_unsigned_char:
		//	 	cmp_write_str(cmp, (const char*) &val.value.uc, sizeof(unsigned char));
		//	 	break;

		// float and double precision
	case np_treeval_type_float:
		cmp_write_float(cmp, val.value.f);
		break;
	case np_treeval_type_double:
		cmp_write_double(cmp, val.value.d);
		break;

		// unsigned numbers
	case np_treeval_type_unsigned_short:
		cmp_write_u8(cmp, val.value.ush);
		break;
	case np_treeval_type_unsigned_int:
		cmp_write_u16(cmp, val.value.ui);
		break;
	case np_treeval_type_unsigned_long:
		cmp_write_u32(cmp, val.value.ul);
		break;
#ifdef x64
	case np_treeval_type_unsigned_long_long:
		cmp_write_u64(cmp, val.value.ull);
		break;
#endif
	case np_treeval_type_uint_array_2:
		cmp_write_fixarray(cmp, 2);
		cmp->write(cmp, &val.value.a2_ui[0], sizeof(uint16_t));
		cmp->write(cmp, &val.value.a2_ui[1], sizeof(uint16_t));
		break;

	case np_treeval_type_float_array_2:
	case np_treeval_type_char_array_8:
	case np_treeval_type_unsigned_char_array_8:
		log_msg(LOG_WARN, "please implement serialization for type %"PRIu8, val.type);
		break;

	case np_treeval_type_void:
		log_msg(LOG_WARN, "please implement serialization for type %"PRIu8, val.type);
		break;
	case np_treeval_type_bin:
		cmp_write_bin32(cmp, val.value.bin, val.size);
		break;
	case np_treeval_type_dhkey:
		__np_tree_serialize_write_type_dhkey(val.value.dhkey, cmp);
		break;
	case np_treeval_type_special_char_ptr:
		__np_tree_serialize_write_type_special_str(val.value.ush, cmp);
		break;
	case np_treeval_type_hash:
		// log_debug_msg(LOG_DEBUG, "adding hash value %s to serialization", val.value.s);
		cmp_write_ext32(cmp, np_treeval_type_hash, val.size, val.value.bin);
		break;

	case np_treeval_type_jrb_tree:
	{
		cmp_ctx_t tree_cmp = { 0 };
		uint32_t buf_size = val.value.tree->byte_size;
		char buffer[buf_size];
		log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "write: buffer size for subtree %u (%hd %u) %u", val.size, val.value.tree->size, val.value.tree->byte_size, buf_size);
		void* buf_ptr = buffer;
		cmp_init(&tree_cmp, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
		np_tree_serialize(context, val.value.tree, &tree_cmp);
		// write the serialized tree to the upper level buffer
		if (!cmp_write_ext32(cmp, np_treeval_type_jrb_tree, buf_size, buf_ptr))
		{
			log_msg(LOG_WARN, "couldn't write tree data -- ignoring for now");
		}
	}
	break;
	default:
		log_msg(LOG_WARN, "please implement serialization for type %hhd", val.type);
		break;
	}
}

void __np_tree_deserialize_read_type(np_state_t* context, np_tree_t* tree, cmp_object_t* obj, cmp_ctx_t* cmp, np_treeval_t* value, NP_UNUSED char* key_to_read_for)
{
	log_trace_msg(LOG_TRACE, "start: void __np_tree_deserialize_read_type(cmp_object_t* obj, cmp_ctx_t* cmp, np_treeval_t* value){");
	switch (obj->type)
	{
		case CMP_TYPE_FIXMAP:
		case CMP_TYPE_MAP16:
		case CMP_TYPE_MAP32:
			log_msg(LOG_WARN,
				"error de-serializing message to normal form, found map type");
			break;

		case CMP_TYPE_FIXARRAY:
			if (2 == obj->as.array_size)
			{
				cmp->read(cmp, &value->value.a2_ui[0], sizeof(uint16_t));
				cmp->read(cmp, &value->value.a2_ui[1], sizeof(uint16_t));
				value->type = np_treeval_type_uint_array_2;
			}
			break;
		case CMP_TYPE_ARRAY16:
		case CMP_TYPE_ARRAY32:
			log_msg(LOG_WARN,
				"error de-serializing message to normal form, found array type");
			break;

		case CMP_TYPE_FIXSTR:
			if(obj->as.str_size == sizeof(char)){
				value->type = np_treeval_type_char;
				cmp->read(cmp, &value->value.c, sizeof(char));
				value->size = obj->as.str_size;
				break;
			}
		case CMP_TYPE_STR8:
		case CMP_TYPE_STR16:
		case CMP_TYPE_STR32:
		{
			value->type = np_treeval_type_char_ptr;
			value->size = obj->as.str_size - 1 /*terminator*/;

			if ( tree->attr.in_place == true) {
				value->value.s = _np_buffer_get_buffer(cmp);
				cmp->skip(cmp, obj->as.str_size);
			}else{
				value->value.s = (char*) malloc(obj->as.str_size * sizeof(char));
				CHECK_MALLOC(value->value.s);
				cmp->read(cmp, value->value.s, obj->as.str_size);
			}

			// to prevent undefined lengths. but should already have a terminator
			char* term = value->value.s + obj->as.str_size - 1;
			term  = "\0";

			break;
		}
		case CMP_TYPE_BIN8:
		case CMP_TYPE_BIN16:
		case CMP_TYPE_BIN32:
		{
			value->type = np_treeval_type_bin;
			value->size = obj->as.bin_size;

			if (tree->attr.in_place == true) {
				value->value.bin = _np_buffer_get_buffer(cmp);
				cmp->skip(cmp, obj->as.bin_size);
			} else {
				value->value.bin = malloc(value->size);
				CHECK_MALLOC(value->value.bin);

				memset(value->value.bin, 0, value->size);
				cmp->read(cmp, value->value.bin, obj->as.bin_size);
			}


			break;
		}
		case CMP_TYPE_NIL:
			log_msg(LOG_WARN, "unknown de-serialization for given type (cmp NIL) ");
			break;

		case CMP_TYPE_BOOLEAN:
			log_msg(LOG_WARN,
				"unknown de-serialization for given type (cmp boolean) ");
			break;

		case CMP_TYPE_EXT8:
		case CMP_TYPE_EXT16:
		case CMP_TYPE_EXT32:
		case CMP_TYPE_FIXEXT1:
		case CMP_TYPE_FIXEXT2:
		case CMP_TYPE_FIXEXT4:
		case CMP_TYPE_FIXEXT8:
		case CMP_TYPE_FIXEXT16:
		{
			void* buffer = _np_buffer_get_buffer(cmp);
			void* target_buffer = buffer + obj->as.ext.size;

			if (obj->as.ext.type == np_treeval_type_jrb_tree)
			{
				// tree type
				value->type = np_treeval_type_jrb_tree;

				np_tree_t* subtree = np_tree_create();
				subtree->attr.in_place = tree->attr.in_place;
				if(np_tree_deserialize( context, subtree, cmp) == false) {
					//TODO: further error handling
					break;
				}

				// if (subtree->rbh_root == NULL) {
				//	 ASSERT(0 == subtree->size, "Size of tree does not match 0 size is: %"PRIu16, subtree->size);
				//	 ASSERT(5/*the empty byte size (set in tree_create())*/ == obj->as.ext.size, "Bytesize of tree does not match , size is: %"PRIu32, obj->as.ext.size);
				// }else{
				//	 ASSERT(
				//		np_tree_get_byte_size(subtree->rbh_root) == obj->as.ext.size,
				//		"Bytesize of tree does not match. actual: %"PRIu32" expected: %"PRIu32,
				//		np_tree_get_byte_size(subtree->rbh_root), obj->as.ext.size
				//	);
				//}
				// TODO: check if the complete buffer was read (byte count match)
				value->value.tree = subtree;
				value->size = subtree->byte_size;
				log_debug_msg(LOG_DEBUG, "read:  buffer size for subtree %u (%hd %u)", value->size, value->value.tree->size, subtree->byte_size);
			}
			else if (obj->as.ext.type == np_treeval_type_dhkey)
			{
				cmp->error = __np_tree_serialize_read_type_dhkey(cmp, value);
			}
			else if (obj->as.ext.type == np_treeval_type_special_char_ptr)
			{
				cmp->error = __np_tree_serialize_read_type_special_str(cmp, value);
			}

			else if (obj->as.ext.type == np_treeval_type_hash)
			{
				value->type = np_treeval_type_hash;
				value->size = obj->as.ext.size;

				if (tree->attr.in_place == true) {

					value->value.bin = buffer;
					cmp->skip(cmp, obj->as.bin_size);
				}
				else {

					value->value.bin = (char*)malloc(obj->as.ext.size);
					CHECK_MALLOC(value->value.bin);

					memset(value->value.bin, 0, value->size);
					memcpy(value->value.bin, buffer, obj->as.ext.size);
				}
			}
			else
			{
				log_debug_msg(LOG_TREE | LOG_SERIALIZATION | LOG_DEBUG,
					"Cannot deserialize ext type %"PRIi8" (size: %"PRIu32")",
					obj->as.ext.type, obj->as.ext.size);

				log_msg(LOG_TREE | LOG_SERIALIZATION | LOG_WARN,
					"Unknown de-serialization for given extension type %"PRIi8, obj->as.ext.type);
				_np_buffer_set_buffer(cmp, target_buffer);
			}

			ASSERT(_np_buffer_get_buffer(cmp) == target_buffer,
				"buffer is not at expected position at \"%s\" (ext key type: %"PRIi32"). actual: %p expected: %p diff byte count: %"PRIi32" size: %"PRIu32" cmp error: %"PRIu8,
				key_to_read_for, obj->as.ext.type, _np_buffer_get_buffer(cmp), target_buffer, _np_buffer_get_buffer(cmp) - target_buffer, (uint32_t) obj->as.ext.size, cmp->error
			);
			// skip forward in case of error ?
			// cmp->skip(cmp,  (_np_buffer_get_buffer(cmp) - target_buffer) );
		}
		break;
		case CMP_TYPE_FLOAT:
			value->value.f = 0.0;
			value->value.f = obj->as.flt;
			value->type = np_treeval_type_float;
			break;

		case CMP_TYPE_DOUBLE:
			value->value.d = 0.0;
			value->value.d = obj->as.dbl;
			value->type = np_treeval_type_double;
			break;

		case CMP_TYPE_POSITIVE_FIXNUM:
		case CMP_TYPE_UINT8:
			value->value.ush = obj->as.u8;
			value->type = np_treeval_type_unsigned_short;
			break;
		case CMP_TYPE_UINT16:
			value->value.ui = 0;
			value->value.ui = obj->as.u16;
			value->type = np_treeval_type_unsigned_int;
			break;
		case CMP_TYPE_UINT32:
			value->value.ul = 0;
			value->value.ul = obj->as.u32;
			value->type = np_treeval_type_unsigned_long;
			break;
	#ifdef x64
		case CMP_TYPE_UINT64:
			value->value.ull = 0;
			value->value.ull = obj->as.u64;
			value->type = np_treeval_type_unsigned_long_long;
			break;
	#endif
		case CMP_TYPE_NEGATIVE_FIXNUM:
		case CMP_TYPE_SINT8:
			value->value.sh = obj->as.s8;
			value->type = np_treeval_type_short;
			break;

		case CMP_TYPE_SINT16:
			value->value.i = 0;
			value->value.i = obj->as.s16;
			value->type = np_treeval_type_int;
			break;

		case CMP_TYPE_SINT32:
			value->value.l = obj->as.s32;
			value->type = np_treeval_type_long;
			break;
	#ifdef x64
		case CMP_TYPE_SINT64:
			value->value.ll = 0;
			value->value.ll = obj->as.s64;
			value->type = np_treeval_type_long_long;
			break;
	#endif
		default:
			value->type = np_treeval_type_undefined;
			log_msg(LOG_WARN, "unknown deserialization for given type");
			break;
	}
}

unsigned char* np_tree_get_hash(np_tree_t* self) {
	unsigned char* hash = calloc(1, crypto_generichash_BYTES);
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

	if (self != NULL && self->size > 0) {
		np_tree_elem_t* iter_tree = NULL;
		char* tmp;
		unsigned char* tmp2;
		bool free_tmp;
		unsigned char* ptr;
		RB_FOREACH(iter_tree, np_tree_s, self)
		{
			tmp = np_treeval_to_str(iter_tree->key, &free_tmp);
			crypto_generichash_update(&gh_state, (unsigned char*)tmp, strlen(tmp));
			if (free_tmp) free(tmp);

			if (iter_tree->val.type == np_treeval_type_jrb_tree) {
				tmp2 = np_tree_get_hash(iter_tree->val.value.tree);
				crypto_generichash_update(&gh_state, tmp2, crypto_generichash_BYTES);
				free(tmp2);
			}
			else {
				if (/*Pointer types*/
					iter_tree->val.type == np_treeval_type_void ||
					iter_tree->val.type == np_treeval_type_bin ||
					iter_tree->val.type == np_treeval_type_char_ptr ||
					iter_tree->val.type == np_treeval_type_char_array_8 ||
					iter_tree->val.type == np_treeval_type_float_array_2 ||
					iter_tree->val.type == np_treeval_type_uint_array_2 ||
					iter_tree->val.type == np_treeval_type_npobj ||
					iter_tree->val.type == np_treeval_type_unsigned_char_array_8
					) {
					ptr = iter_tree->val.value.bin;
				}
				else {
					ptr = &iter_tree->val.value.uc;
				}
				crypto_generichash_update(&gh_state, ptr, iter_tree->val.size);
			}
		}
	}

	crypto_generichash_final(&gh_state, hash, crypto_generichash_BYTES);
	return hash;
}
