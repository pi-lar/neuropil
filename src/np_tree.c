//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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

#include "np_tree.h"
#include "np_treeval.h"

#include "np_serialization.h"
#include "np_util.h"
#include "np_log.h"


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

np_tree_t* np_tree_create(np_bool in_place)
{
	np_tree_t* new_tree = (np_tree_t*)malloc(sizeof(np_tree_t));
	CHECK_MALLOC(new_tree);

	new_tree->rbh_root = NULL;
	new_tree->size = 0;
	new_tree->byte_size = 5;
	new_tree->in_place = in_place;

	return new_tree;
}

np_bool _np_tree_is_special_str(char* in_question, uint8_t* idx_on_found) {
	np_bool ret = FALSE;
	return ret;
	uint8_t item_count = sizeof(np_special_strs) / sizeof(char*);

	for (uint8_t i = 0; i < item_count; i++) {
		char* special_str = np_special_strs[i];
		if (strncmp(special_str, in_question, strlen(special_str)) == 0 && strlen(in_question) == strlen(special_str)) {
			if(idx_on_found != NULL){
				log_debug_msg(LOG_DEBUG, "idx detected for %15s at %3"PRIu8" saving into %p",in_question, i, idx_on_found);
				*idx_on_found = i;
			}
			ret = TRUE;
			break;
		}
	}

	if (!ret) {
		log_debug_msg(LOG_DEBUG, "not in np_special_strs dictionary: \"%s\"", in_question);
	}

	return ret;
}

char* _np_tree_get_special_str(uint8_t idx) {
	return np_special_strs[idx];
}

int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2)
{
	log_msg(LOG_TRACE, "start: int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2){");
	assert(NULL != j1);
	assert(NULL != j2);

	np_treeval_t jv1 = j1->key;
	np_treeval_t jv2 = j2->key;

	if (jv1.type == jv2.type)
	{
		if (jv1.type == char_ptr_type) {
			return strncmp(jv1.value.s, jv2.value.s, 64);
		}
		else if (jv1.type == special_char_ptr_type){
			int res = (int)jv1.value.ush - (int)jv2.value.ush;
			if (res < 0) return -1;
			if (res > 0) return  1;
			return 0;
		}
		else if (jv1.type == double_type)
		{
			// log_debug_msg(LOG_DEBUG, "comparing %f - %f = %d",
			// 		jv1.value.d, jv2.value.d, (int16_t) (jv1.value.d-jv2.value.d) );
			double res = jv1.value.d - jv2.value.d;
			if (res < 0) return -1;
			if (res > 0) return  1;
			return 0;
		}
		else if (jv1.type == unsigned_long_type) {
			return (int16_t)(jv1.value.ul - jv2.value.ul);
		}
		else if (jv1.type == int_type) {
			return (int16_t)(jv1.value.i - jv2.value.i);
		}
	}
	return (((int)jv1.type - (int) jv2.type) > 0);
};

np_tree_elem_t* np_tree_find_gte_str(np_tree_t* n, const char *key, uint8_t *fnd)
{
	assert(n != NULL);
	assert(key != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = char_ptr_type,.value.s = (char*)key };
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

	np_treeval_t search_key = { .type = special_char_ptr_type, .value.ush = key };
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
	} else {
		np_treeval_t search_key = { .type = char_ptr_type, .value.s = (char*)key };
		np_tree_elem_t search_elem = { .key = search_key };
		ret = RB_FIND(np_tree_s, n, &search_elem);
	}
	return ret;
}

np_tree_elem_t* np_tree_find_gte_int(np_tree_t* n, int16_t ikey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = int_type,.value.i = ikey };
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
	np_treeval_t search_key = { .type = int_type,.value.i = key };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* np_tree_find_gte_ulong(np_tree_t* n, uint32_t ulkey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = unsigned_long_type,.value.ul = ulkey };
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
	np_treeval_t search_key = { .type = unsigned_long_type,.value.ul = ulkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* np_tree_find_gte_dbl(np_tree_t* n, double dkey, uint8_t *fnd)
{
	assert(n != NULL);

	np_tree_elem_t* result = NULL;

	np_treeval_t search_key = { .type = double_type,.value.d = dkey };
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
	np_treeval_t search_key = { .type = double_type,.value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

void np_tree_cleanup_treeval(np_tree_t* tree, np_treeval_t toclean) {	
	if(tree->in_place == FALSE){
		if (toclean.type == char_ptr_type) free(toclean.value.s);
		if (toclean.type == bin_type) free(toclean.value.bin);
	}
	if (toclean.type == jrb_tree_type) { np_tree_free(toclean.value.tree); }
}
void np_tree_del_element(np_tree_t* tree, np_tree_elem_t* to_delete)
{	
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);

		tree->byte_size -= np_tree_get_byte_size(to_delete);
		tree->size--;

		np_tree_cleanup_treeval(tree, to_delete->key);
		np_tree_cleanup_treeval(tree, to_delete->val);

		free(to_delete);
	}

}
void np_tree_del_special_str(np_tree_t* tree, const uint8_t idx)
{
	np_tree_del_element(tree, np_tree_find_special_str(tree, idx));
}

void np_tree_del_str(np_tree_t* tree, const char *key)
{
	np_tree_del_element(tree, np_tree_find_str(tree, key));
}

void np_tree_del_int(np_tree_t* tree, const int16_t key)
{
	np_tree_del_element(tree, np_tree_find_int(tree, key));
}

void np_tree_del_double(np_tree_t* tree, const double dkey)
{
	np_tree_del_element(tree, np_tree_find_dbl(tree,dkey));
}

void np_tree_del_ulong(np_tree_t* tree, const uint32_t key)
{
	np_tree_del_element(tree, np_tree_find_ulong(tree,key));
}

void np_tree_clear(np_tree_t* n)
{
	np_tree_elem_t* iter = RB_MIN(np_tree_s, n);
	np_tree_elem_t* tmp = NULL;

	if (NULL != iter)
	{
		do
		{
			tmp = iter;
			iter = RB_NEXT(np_tree_s, n, iter);

			np_tree_del_element(n, tmp);

		} while (NULL != iter);
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
	log_msg(LOG_TRACE, "start: void _np_tree_replace_all_with_str(np_tree_t* n, const char* key, np_treeval_t val){");
	np_tree_clear(n);
	np_tree_insert_str(n, key, val);
}


uint32_t np_tree_get_byte_size(np_tree_elem_t* node)
{
	log_msg(LOG_TRACE, "start: uint32_t np_tree_get_byte_size(np_tree_elem_t* node){");
	assert(node != NULL);

	uint32_t byte_size = np_treeval_get_byte_size(node->key) + np_treeval_get_byte_size(node->val);

	return byte_size;
}

void np_tree_insert_element(np_tree_t* tree, np_tree_elem_t* ele) {
	RB_INSERT(np_tree_s, tree, ele);
	tree->size++;
	tree->byte_size += np_tree_get_byte_size(ele);
}

void np_tree_insert_special_str(np_tree_t* tree, const uint8_t const idx, np_treeval_t val)
{
	np_tree_elem_t* found = np_tree_find_special_str(tree, idx);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);
		
		found->key.value.ush = idx;
		found->key.type = special_char_ptr_type;
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
	if (_np_tree_is_special_str(key, &idx)) {
		np_tree_insert_special_str(tree, idx, val);
	} else {		
		np_tree_elem_t* found = np_tree_find_str(tree, key);

		if (found == NULL)
		{
			// insert new value
			found = (np_tree_elem_t*)malloc(sizeof(np_tree_elem_t));
			CHECK_MALLOC(found);

			if (tree->in_place == TRUE) {
				found->key.value.s = key; 
			}
			else {
				found->key.value.s = strndup(key, 255);
			}

			found->key.type = char_ptr_type;
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

		// if (NULL == found) return;

		found->key.value.i = ikey;
		found->key.type = int_type;
		found->key.size = sizeof(int16_t);
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
		found->key.type = unsigned_long_type;
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
		found->key.type = double_type;
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

	if (tree->in_place == FALSE){
		element->val = np_treeval_copy_of_val(val);
	}
	else{
		//memmove(&element->val, &val, sizeof(np_treeval_t));
		memset(&element->val, &val, sizeof(np_treeval_t));
	}

}
void np_tree_replace_treeval(np_tree_t* tree, np_tree_elem_t* element, np_treeval_t val) {
	// free up memory before replacing
	tree->byte_size -= np_tree_get_byte_size(element);

	np_tree_cleanup_treeval(tree, element->val);
	np_tree_set_treeval(tree, element, val);
	tree->byte_size += np_tree_get_byte_size(element);

}
void np_tree_replace_special_str(np_tree_t* tree, const uint8_t key, np_treeval_t val)
{
	assert(tree != NULL);
	assert(key != NULL);

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
		np_tree_insert_str(tree, key, val);
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
		np_tree_insert_dbl(tree, dkey, val);
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
		if (tmp->key.type == char_ptr_type)					np_tree_insert_str(target, tmp->key.value.s, tmp->val);
		else if (tmp->key.type == special_char_ptr_type)	np_tree_insert_special_str(target, tmp->key.value.ush, tmp->val);
		else if (tmp->key.type == int_type)					np_tree_insert_int(target, tmp->key.value.i, tmp->val);
		else if (tmp->key.type == double_type)				np_tree_insert_dbl(target, tmp->key.value.d, tmp->val);
		else if (tmp->key.type == unsigned_long_type)		np_tree_insert_ulong(target, tmp->key.value.ul, tmp->val);
	}
}

void np_tree_copy_inplace(np_tree_t* source, np_tree_t* target) {
	np_tree_elem_t* tmp = NULL;

	assert(source != NULL);
	assert(target != NULL);

	RB_FOREACH(tmp, np_tree_s, source)
	{
		if (tmp->key.type == char_ptr_type)					np_tree_replace_str(target, tmp->key.value.s, tmp->val);
		else if (tmp->key.type == special_char_ptr_type)	np_tree_replace_special_str(target, tmp->key.value.ush, tmp->val);
		else if (tmp->key.type == int_type)					np_tree_replace_int(target, tmp->key.value.i, tmp->val);
		else if (tmp->key.type == double_type)				np_tree_replace_dbl(target, tmp->key.value.d, tmp->val);
		else if (tmp->key.type == unsigned_long_type)		np_tree_replace_ulong(target, tmp->key.value.ul, tmp->val);
	}
}
np_tree_t* np_tree_clone(np_tree_t* source) {
	log_msg(LOG_TRACE, "start: np_tree_t* np_tree_clone(np_tree_t* source) {");

	np_tree_t* ret = np_tree_create(FALSE);
	np_tree_copy(source, ret);
	return ret;
}


void np_tree_serialize(np_tree_t* jtree, cmp_ctx_t* cmp)
{
	log_msg(LOG_TRACE, "start: void np_tree_serialize(np_tree_t* jtree, cmp_ctx_t* cmp){");
	uint16_t i = 0;
	// first assume a size based on jrb size
		
	if (!cmp_write_map32(cmp, jtree->size * 2)) return;

	// write jrb tree
	if (0 < jtree->size)
	{
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, jtree)
		{

			if (int_type == tmp->key.type ||
				unsigned_long_type == tmp->key.type ||
				double_type == tmp->key.type ||
				char_ptr_type == tmp->key.type ||
				special_char_ptr_type== tmp->key.type)
			{
				// log_debug_msg(LOG_DEBUG, "for (%p; %p!=%p; %p=%p) ", tmp->flink, tmp, msg->header, node, node->flink);
				__np_tree_serialize_write_type(tmp->key, cmp); i++;
				__np_tree_serialize_write_type(tmp->val, cmp); i++;
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


np_bool np_tree_deserialize(np_tree_t* jtree, cmp_ctx_t* cmp)
{
	log_msg(LOG_TRACE, "start: void np_tree_deserialize(np_tree_t* jtree, cmp_ctx_t* cmp){");

	ASSERT(jtree != NULL,"Tree do deserialize cannot be NULL")
	np_bool ret = TRUE;
	
	cmp_object_t obj_key = { 0 };
	cmp_object_t obj_val = { 0 };

	uint32_t size = 0;

	cmp_read_map(cmp, &size);

	if (size == 0){
		return TRUE;
	}
	else if ((size % 2) != 0) {
		return FALSE;
	}


	for (uint32_t i = 0; i < (size / 2); i++)
	{
		// read key
		np_treeval_t tmp_key = { 0 };
		tmp_key.type = none_type;
		tmp_key.size = 0;
		cmp_read_object(cmp, &obj_key);
		__np_tree_deserialize_read_type(jtree, &obj_key, cmp, &tmp_key);

		if (cmp->error != 0 || none_type == tmp_key.type) {
			ret = FALSE;
			break;
		}


		// read value
		np_treeval_t tmp_val = { 0 };
		tmp_val.type = none_type;
		tmp_val.size = 0;
		cmp_read_object(cmp, &obj_val);
		__np_tree_deserialize_read_type(jtree, &obj_val, cmp, &tmp_val);

		if (cmp->error != 0 || none_type == tmp_val.type) {
			ret = FALSE;
			break;
		}

		// add key value pair to tree
		switch (tmp_key.type)
		{
			case int_type:
				np_tree_insert_int(jtree, tmp_key.value.i, tmp_val);
				break;
			case unsigned_long_type:
				np_tree_insert_ulong(jtree, tmp_key.value.ul, tmp_val);
				break;
			case double_type:
				np_tree_insert_dbl(jtree, tmp_key.value.d, tmp_val);
				break;
			case char_ptr_type:		
				np_tree_insert_str(jtree, tmp_key.value.s, tmp_val);				
				break;
			case special_char_ptr_type:
				np_tree_insert_special_str(jtree, tmp_key.value.ush, tmp_val);
				break;
			default:
				tmp_val.type = none_type;
				break;
		}
		
		np_tree_cleanup_treeval(jtree, tmp_key);
		np_tree_cleanup_treeval(jtree, tmp_val);
		
	}
	
	if(cmp->error != 0) {
		 log_msg(LOG_INFO, "Deserialization error: %s", cmp_strerror(cmp));
	}

	if (ret == FALSE) {
		log_debug_msg(LOG_WARN | DEBUG, "Deserialization error: unspecified error");
	}
	return ret;
}

uint8_t __np_tree_serialize_read_type_dhkey(void* buffer_ptr, np_treeval_t* target) {
	log_msg(LOG_TRACE, "start: uint8_t __np_tree_serialize_read_type_dhkey(void* buffer_ptr, np_treeval_t* target) {");
	cmp_ctx_t cmp_key;
	cmp_init(&cmp_key, buffer_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	np_dhkey_t empty_key = { 0 };
	np_dhkey_t new_key;

	target->value.dhkey = empty_key;
	target->type = dhkey_type;
	target->size = sizeof(np_dhkey_t);

	if (cmp_read_u32(&cmp_key, &(new_key.t[0])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[1])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[2])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[3])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[4])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[5])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[6])) &&
		cmp_read_u32(&cmp_key, &(new_key.t[7])))
			target->value.dhkey = new_key;
	

	return cmp_key.error;
}

void __np_tree_serialize_write_type_dhkey(np_dhkey_t source, cmp_ctx_t* target) {
	log_msg(LOG_TRACE, "start: void __np_tree_serialize_write_type_dhkey(np_dhkey_t source, cmp_ctx_t* target) {");
	// source->size is not relevant here as the transport size includes marker sizes etc..
	//                        8 * (size of uint32 marker + size of key element)
	uint32_t transport_size = 8 * (sizeof(uint8_t) + sizeof(uint32_t));

	cmp_ctx_t key_ctx;
	char buffer[transport_size];
	void* buf_ptr = buffer;
	cmp_init(&key_ctx, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

	if (
		cmp_write_u32(&key_ctx, source.t[0]) &&
		cmp_write_u32(&key_ctx, source.t[1]) &&
		cmp_write_u32(&key_ctx, source.t[2]) &&
		cmp_write_u32(&key_ctx, source.t[3]) &&
		cmp_write_u32(&key_ctx, source.t[4]) &&
		cmp_write_u32(&key_ctx, source.t[5]) &&
		cmp_write_u32(&key_ctx, source.t[6]) &&
		cmp_write_u32(&key_ctx, source.t[7]))
		{
		// everything is awsome
		}

	if (key_ctx.error == 0) {
		cmp_write_ext32(target, dhkey_type, transport_size, buf_ptr);
	}
	else {
		target->error = key_ctx.error;
	}


}


uint8_t __np_tree_serialize_read_type_special_str(void* buffer_ptr, np_treeval_t* target) {
	log_msg(LOG_TRACE, "start: uint8_t __np_tree_serialize_read_type_special_str(void* buffer_ptr, np_treeval_t* target) {");
	cmp_ctx_t cmp;
	cmp_init(&cmp, buffer_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	uint8_t idx = 0;
	cmp_read_u8(&cmp, &idx);	
	target->value.ush = idx;
	target->type = special_char_ptr_type;
	target->size = sizeof(uint8_t);

	return cmp.error;
}

void __np_tree_serialize_write_type_special_str(uint8_t idx, cmp_ctx_t* target) {
	//                        size of uint8 marker + size uint8 for index
	uint32_t transport_size = (sizeof(uint8_t) + sizeof(uint8_t)); 
	
	cmp_ctx_t cmp;
	char buffer[255];
	
	void* buf_ptr = buffer;
	cmp_init(&cmp, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);

	cmp_write_u8(&cmp, idx);

	if(cmp.error == 0){
		cmp_write_ext32(target, special_char_ptr_type, transport_size, buf_ptr);
	}
	else {
		target->error = cmp.error;
	}

}

void __np_tree_serialize_write_type(np_treeval_t val, cmp_ctx_t* cmp)
{
	log_msg(LOG_TRACE, "start: void __np_tree_serialize_write_type(np_treeval_t val, cmp_ctx_t* cmp){");
	// void* count_buf_start = cmp->buf;
	// log_debug_msg(LOG_DEBUG, "writing jrb (%p) value: %s", jrb, jrb->key.value.s);
	switch (val.type)
	{
		// signed numbers
	case short_type:
		cmp_write_s8(cmp, val.value.sh);
		break;
	case int_type:
		cmp_write_s16(cmp, val.value.i);
		break;
	case long_type:
		cmp_write_s32(cmp, val.value.l);
		break;
#ifdef x64
	case long_long_type:
		cmp_write_s64(cmp, val.value.ll);
		break;
#endif
		// characters
	case char_ptr_type:
		//log_debug_msg(LOG_DEBUG, "string size %u/%lu -> %s", val.size, strlen(val.value.s), val.value.s);
		cmp_write_str32(cmp, val.value.s, val.size + sizeof(char)/*include terminator*/);
		break;

	case char_type:
		cmp_write_fixstr(cmp, (const char*)&val.value.c, sizeof(char));
		break;
		//	case unsigned_char_type:
		//	 	cmp_write_str(cmp, (const char*) &val.value.uc, sizeof(unsigned char));
		//	 	break;

		// float and double precision
	case float_type:
		cmp_write_float(cmp, val.value.f);
		break;
	case double_type:
		cmp_write_double(cmp, val.value.d);
		break;

		// unsigned numbers
	case unsigned_short_type:
		cmp_write_u8(cmp, val.value.ush);
		break;
	case unsigned_int_type:
		cmp_write_u16(cmp, val.value.ui);
		break;
	case unsigned_long_type:
		cmp_write_u32(cmp, val.value.ul);
		break;
#ifdef x64
	case unsigned_long_long_type:
		cmp_write_u64(cmp, val.value.ull);
		break;
#endif
	case uint_array_2_type:
		cmp_write_fixarray(cmp, 2);
		cmp->write(cmp, &val.value.a2_ui[0], sizeof(uint16_t));
		cmp->write(cmp, &val.value.a2_ui[1], sizeof(uint16_t));
		break;

	case float_array_2_type:
	case char_array_8_type:
	case unsigned_char_array_8_type:
		log_msg(LOG_WARN, "please implement serialization for type %hhd", val.type);
		break;

	case void_type:
		log_msg(LOG_WARN, "please implement serialization for type %hhd", val.type);
		break;

	case bin_type:
		cmp_write_bin32(cmp, val.value.bin, val.size);
		//log_debug_msg(LOG_DEBUG, "BIN size %"PRIu32, val.size);
		break;

	case dhkey_type:
	{
		__np_tree_serialize_write_type_dhkey(val.value.dhkey, cmp);
		break;
	}
	case special_char_ptr_type:
	{
		__np_tree_serialize_write_type_special_str(val.value.ush, cmp);
		break;
	}

	case hash_type:
		// log_debug_msg(LOG_DEBUG, "adding hash value %s to serialization", val.value.s);
		cmp_write_ext32(cmp, hash_type, val.size, val.value.bin);
		break;

	case jrb_tree_type:
	{
		cmp_ctx_t tree_cmp;
		char buffer[val.size];
		// log_debug_msg(LOG_DEBUG, "buffer size for subtree %u (%hd %llu)", val.size, val.value.tree->size, val.value.tree->byte_size);
		// log_debug_msg(LOG_DEBUG, "buffer size for subtree %u", val.size);
		void* buf_ptr = buffer;
		cmp_init(&tree_cmp, buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
		np_tree_serialize(val.value.tree, &tree_cmp);
		uint32_t buf_size = tree_cmp.buf - buf_ptr;

		// void* top_buf_ptr = cmp->buf;
		// write the serialized tree to the upper level buffer
		if (!cmp_write_ext32(cmp, jrb_tree_type, buf_size, buf_ptr))
		{
			log_msg(LOG_WARN, "couldn't write tree data -- ignoring for now");
		}
		// uint32_t top_buf_size = cmp->buf-top_buf_ptr;

		//			else {
		// log_debug_msg(LOG_DEBUG, "wrote tree structure size pre: %hu/%hu post: %hu %hu", val.size, val.value.tree->byte_size, buf_size, top_buf_size);
		//			}
	}
	break;
	default:
		log_msg(LOG_WARN, "please implement serialization for type %hhd", val.type);
		break;
	}
}

void __np_tree_deserialize_read_type(np_tree_t* tree, cmp_object_t* obj, cmp_ctx_t* cmp, np_treeval_t* value)
{
	log_msg(LOG_TRACE, "start: void __np_tree_deserialize_read_type(cmp_object_t* obj, cmp_ctx_t* cmp, np_treeval_t* value){");
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
				value->type = uint_array_2_type;
			}
			break;
		case CMP_TYPE_ARRAY16:
		case CMP_TYPE_ARRAY32:
			log_msg(LOG_WARN,
				"error de-serializing message to normal form, found array type");
			break;

		case CMP_TYPE_FIXSTR:
			if(obj->as.str_size == sizeof(char)){
				value->type = char_type;
				cmp->read(cmp, &value->value.c, sizeof(char));
				value->size = obj->as.str_size;
				break;
			}
		case CMP_TYPE_STR8:
		case CMP_TYPE_STR16:
		case CMP_TYPE_STR32:
		{
			value->type = char_ptr_type;
			value->size = obj->as.str_size - 1/*terminator*/;
		
			if ( tree->in_place == TRUE) {			
				value->value.s = _np_buffer_get_buffer(cmp);
				cmp->skip(cmp, obj->as.str_size);
			}else{
				value->value.s = (char*)malloc(obj->as.str_size * sizeof(char));
				CHECK_MALLOC(value->value.s);				
				cmp->read(cmp, value->value.s, obj->as.str_size);
			}			
		
			// to prevent undefined lengths. but should already hava terminator
			value->value.s[obj->as.str_size-1] = '\0';

			break;
		}
		case CMP_TYPE_BIN8:
		case CMP_TYPE_BIN16:
		case CMP_TYPE_BIN32:
		{
			value->type = bin_type;
			value->size = obj->as.bin_size;

			if (tree->in_place == TRUE) {
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

			if (obj->as.ext.type == jrb_tree_type)
			{
				// tree type
				np_tree_t* subtree = np_tree_create(tree->in_place);
				if(np_tree_deserialize(subtree, cmp) == FALSE) {
					//TODO: further error handeling								
					break;
				}			

				
				//if (subtree->rbh_root == NULL) {
				//	ASSERT(0 == subtree->size, "Size of tree does not match 0 size is: %"PRIu16, subtree->size);
				//	ASSERT(5/*the empty byte size (set in tree_create())*/ == obj->as.ext.size, "Bytesize of tree does not match , size is: %"PRIu32, obj->as.ext.size);
				//}else{
				//	ASSERT(
				//		np_tree_get_byte_size(subtree->rbh_root) == obj->as.ext.size, 
				//		"Bytesize of tree does not match. actual: %"PRIu32" expected: %"PRIu32, 
				//		np_tree_get_byte_size(subtree->rbh_root), obj->as.ext.size
				//	);
				//}
				// TODO: check if the complete buffer was read (byte count match)
				
				value->value.tree = subtree;
				value->type = jrb_tree_type;
				value->size = subtree->size;
			}
			else if (obj->as.ext.type == dhkey_type)
			{
				cmp->error = __np_tree_serialize_read_type_dhkey(buffer, value);
			}
			else if (obj->as.ext.type == special_char_ptr_type)
			{
				cmp->error = __np_tree_serialize_read_type_special_str(buffer, value);
			}
			else if (obj->as.ext.type == hash_type)
			{
				value->type = hash_type;
				value->size = obj->as.ext.size;

				if (tree->in_place == TRUE) {

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
				log_msg(LOG_WARN,
					"unknown de-serialization for given extension type %"PRIi8, obj->as.ext.type);
			}
			ASSERT(_np_buffer_get_buffer(cmp) == target_buffer,
				"buffer is not at expected position. actual: %p expected: %p",
				_np_buffer_get_buffer(cmp) ,target_buffer
			);
		}
		break;
		case CMP_TYPE_FLOAT:
			value->value.f = 0.0;
			value->value.f = obj->as.flt;
			value->type = float_type;
			break;

		case CMP_TYPE_DOUBLE:
			value->value.d = 0.0;
			value->value.d = obj->as.dbl;
			value->type = double_type;
			break;

		case CMP_TYPE_POSITIVE_FIXNUM:
		case CMP_TYPE_UINT8:
			value->value.ush = obj->as.u8;
			value->type = unsigned_short_type;
			break;
		case CMP_TYPE_UINT16:
			value->value.ui = 0;
			value->value.ui = obj->as.u16;
			value->type = unsigned_int_type;
			break;
		case CMP_TYPE_UINT32:
			value->value.ul = 0;
			value->value.ul = obj->as.u32;
			value->type = unsigned_long_type;
			break;
	#ifdef x64
		case CMP_TYPE_UINT64:
			value->value.ull = 0;
			value->value.ull = obj->as.u64;
			value->type = unsigned_long_long_type;
			break;
	#endif
		case CMP_TYPE_NEGATIVE_FIXNUM:
		case CMP_TYPE_SINT8:
			value->value.sh = obj->as.s8;
			value->type = short_type;
			break;

		case CMP_TYPE_SINT16:
			value->value.i = 0;
			value->value.i = obj->as.s16;
			value->type = int_type;
			break;

		case CMP_TYPE_SINT32:
			value->value.l = obj->as.s32;
			value->type = long_type;
			break;
	#ifdef x64
		case CMP_TYPE_SINT64:
			value->value.ll = 0;
			value->value.ll = obj->as.s64;
			value->type = long_long_type;
			break;
	#endif
		default:
			value->type = none_type;
			log_msg(LOG_WARN, "unknown deserialization for given type");
			break;
	}
}
