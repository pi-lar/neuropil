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

#include "np_jtree.h"
#include "jval.h"
#include "log.h"


RB_GENERATE(np_jtree, np_jtree_elem_s, link, jval_cmp);

//RB_GENERATE_STATIC(np_str_jtree, np_jtree_elem_s, link, jval_cmp);
//RB_GENERATE_STATIC(np_int_jtree, np_jtree_elem_s, link, jval_cmp);
//RB_GENERATE_STATIC(np_dbl_jtree, np_jtree_elem_s, link, jval_cmp);
//RB_GENERATE_STATIC(np_ulong_jtree, np_jtree_elem_s, link, jval_cmp);

np_jtree_t* make_jtree () {
	np_jtree_t* new_tree = (np_jtree_t*) malloc(sizeof(np_jtree_t));
	new_tree->rbh_root = NULL;
	new_tree->size = 0;
	new_tree->byte_size = 5;

	return new_tree;
}

int16_t jval_cmp(const np_jtree_elem_t* j1, const np_jtree_elem_t* j2) {

	np_jval_t jv1 = j1->key;
	np_jval_t jv2 = j2->key;

	if (jv1.type == jv2.type) {

		if (jv1.type == char_ptr_type)
			return strncmp(jv1.value.s, jv2.value.s, 64);

		if (jv1.type == double_type) {
			// log_msg(LOG_DEBUG, "comparing %f - %f = %d",
			// 		jv1.value.d, jv2.value.d, (int16_t) (jv1.value.d-jv2.value.d) );
			double res = jv1.value.d - jv2.value.d;
			if (res < 0) return -1;
			if (res > 0) return  1;
			return 0;
		}
		if (jv1.type == unsigned_long_type)
			return (int16_t) (jv1.value.ul - jv2.value.ul);

		if (jv1.type == int_type)
			return (int16_t) (jv1.value.i - jv2.value.i);
	}
	return (0);
};

np_jtree_elem_t* jrb_find_gte_str (np_jtree_t* n, const char *key, uint8_t *fnd)
{
	assert(n   != NULL);
	assert(key != NULL);

	np_jtree_elem_t* result = NULL;

	np_jval_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_jtree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_jtree, n, &search_elem);
	if (result) *fnd = 1;
	else        *fnd = 0;

	return result;
}

np_jtree_elem_t* jrb_find_str (np_jtree_t* n, const char *key)
{
	np_jval_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_jtree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_jtree, n, &search_elem);
}


np_jtree_elem_t* jrb_find_gte_int (np_jtree_t* n, int16_t ikey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_jtree_elem_t* result = NULL;

	np_jval_t search_key = { .type = int_type, .value.i = ikey };
	np_jtree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_jtree, n, &search_elem);
	if (result) *fnd = 1;
	else        *fnd = 0;

	return result;
}

np_jtree_elem_t* jrb_find_int (np_jtree_t* n, int16_t key)
{
	np_jval_t search_key = { .type = int_type, .value.i = key };
	np_jtree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_jtree, n, &search_elem);
}

np_jtree_elem_t* jrb_find_gte_ulong (np_jtree_t* n, uint32_t ulkey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_jtree_elem_t* result = NULL;

	np_jval_t search_key = { .type = unsigned_long_type, .value.ul = ulkey };
	np_jtree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_jtree, n, &search_elem);
	if (result) *fnd = 1;
	else        *fnd = 0;

	return result;
}

np_jtree_elem_t* jrb_find_ulong (np_jtree_t* n, uint32_t ulkey)
{
	np_jval_t search_key = { .type = unsigned_long_type, .value.ul = ulkey };
	np_jtree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_jtree, n, &search_elem);
}

np_jtree_elem_t* jrb_find_gte_dbl (np_jtree_t* n, double dkey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_jtree_elem_t* result = NULL;

	np_jval_t search_key = { .type = double_type, .value.d = dkey };
	np_jtree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_jtree, n, &search_elem);
	if (result) *fnd = 1;
	else        *fnd = 0;

	return result;
}

np_jtree_elem_t* jrb_find_dbl (np_jtree_t* n, double dkey)
{
	np_jval_t search_key = { .type = double_type, .value.d = dkey };
	np_jtree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_jtree, n, &search_elem);
}

void del_str_node (np_jtree_t* tree, const char *key) {

	np_jval_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_jtree_elem_t search_elem = { .key = search_key };

	np_jtree_elem_t* to_delete = RB_FIND(np_jtree, tree, &search_elem);
	if (to_delete != NULL) {

		RB_REMOVE(np_jtree, tree, to_delete);

		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;

		free(to_delete->key.value.s);

		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void del_int_node (np_jtree_t* tree, const int16_t key) {
	np_jval_t search_key = { .type = int_type, .value.i = key };
	np_jtree_elem_t search_elem = { .key = search_key };

	np_jtree_elem_t* to_delete = RB_FIND(np_jtree, tree, &search_elem);
	if (to_delete != NULL) {
		RB_REMOVE(np_jtree, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void del_dbl_node (np_jtree_t* tree, const double dkey) {

	np_jval_t search_key = { .type = double_type, .value.d = dkey };
	np_jtree_elem_t search_elem = { .key = search_key };

	np_jtree_elem_t* to_delete = RB_FIND(np_jtree, tree, &search_elem);
	if (to_delete != NULL) {
		RB_REMOVE(np_jtree, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);
		free (to_delete);
	}
}

void del_ulong_node (np_jtree_t* tree, const uint32_t key) {
	np_jval_t search_key = { .type = unsigned_long_type, .value.ul = key };
	np_jtree_elem_t search_elem = { .key = search_key };

	np_jtree_elem_t* to_delete = RB_FIND(np_jtree, tree, &search_elem);
	if (to_delete != NULL) {
		RB_REMOVE(np_jtree, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void np_clear_tree (np_jtree_t* n)
{
	np_jtree_elem_t* iter = RB_MIN(np_jtree, n);
	np_jtree_elem_t* tmp = NULL;

	if (NULL != iter) {
		do {
			tmp = iter;
			// log_msg(LOG_WARN, "jrb_free_tree: e->%p k->%p v->%p", tmp, tmp->key.value.s, &tmp->val);

			iter = RB_NEXT(np_jtree, n, iter);

			switch (tmp->key.type) {
			case (char_ptr_type) :
				del_str_node(n, tmp->key.value.s);
				break;
			case (int_type):
				del_int_node(n, tmp->key.value.i);
				break;
			case (double_type):
				del_dbl_node(n, tmp->key.value.d);
				break;
			case (unsigned_long_type):
				del_ulong_node(n, tmp->key.value.ul);
				break;
			}

		} while (iter != NULL);
	}
}

void np_free_tree (np_jtree_t* n)
{
	np_clear_tree(n);
	free (n);
}

void np_print_tree (np_jtree_t* n, uint8_t indent)
{
	np_jtree_elem_t* tmp = NULL;

	RB_FOREACH(tmp, np_jtree, n)
	{
		char s_indent[indent+1];
		memset(s_indent, ' ', indent);
		s_indent[indent] = '\0';

		if (tmp->key.type == char_ptr_type)      log_msg(LOG_DEBUG, "%s%s: %s", s_indent, jval_to_str(tmp->key), jval_to_str(tmp->val));
		if (tmp->key.type == int_type)           log_msg(LOG_DEBUG, "%s%s: %s", s_indent, jval_to_str(tmp->key), jval_to_str(tmp->val));
		if (tmp->key.type == double_type)        log_msg(LOG_DEBUG, "%s%s: %s", s_indent, jval_to_str(tmp->key), jval_to_str(tmp->val));
		if (tmp->key.type == unsigned_long_type) log_msg(LOG_DEBUG, "%s%s: %s", s_indent, jval_to_str(tmp->key), jval_to_str(tmp->val));

		if (tmp->val.type == jrb_tree_type) np_print_tree(tmp->val.value.v, indent+1);
	}
}

void jrb_replace_all_with_str(np_jtree_t* n, const char* key, np_jval_t val)
{
	np_clear_tree(n);
    jrb_insert_str(n, key, val);
}

np_jval_t jrb_val (np_jtree_elem_t* n)
{
	assert(n     != NULL);
    return n->val;
}

uint64_t jrb_get_byte_size(np_jtree_elem_t* node)
{
	assert(node  != NULL);

	// if (isint(node)) return 0;

	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculation", node);
	uint64_t byte_size = 0;

	switch(node->key.type) {
		// length is always 1 (to identify the type) + the length of the type
  		case short_type: 		  byte_size += 1 + sizeof(int8_t); break;
		case int_type: 			  byte_size += 1 + sizeof(int16_t); break;
		case long_type: 		  byte_size += 1 + sizeof(int32_t); break;
		case long_long_type:	  byte_size += 1 + sizeof(int64_t); break;
 		case float_type: 		  byte_size += 1 + sizeof(float); break;
		case double_type: 		  byte_size += 1 + sizeof(double); break;
		case char_ptr_type: 	  byte_size += 1 + sizeof(uint32_t) + node->key.size; break;
		case char_type: 		  byte_size += 1 + sizeof(char); break;
		case unsigned_char_type:  byte_size += 1 + sizeof(unsigned char); break;
 		case unsigned_short_type: byte_size += 1 + sizeof(uint8_t); break;
		case unsigned_int_type:   byte_size += 1 + sizeof(uint16_t); break;
		case unsigned_long_type:  byte_size += 1 + sizeof(uint32_t); break;
		case unsigned_long_long_type:  byte_size += 1 + sizeof(uint64_t); break;
// 		case int_array_2_type:    byte_size += 1 + 2*sizeof(int16_t); break;
// 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
// 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
// 		case unsigned_char_array_8_type: byte_size += 1 +8*sizeof(unsigned char); break;
// 		case void_type: 		  byte_size += 1 + sizeof(void*); break;
// 		case bin_type: 			  byte_size += 1 + node->key.size; break;
// 		case jrb_tree_type:       byte_size += jrb_get_byte_size(node->key.value.tree); break;
		case key_type:            byte_size += 1 + (4 * sizeof(uint64_t)); break;
		default:                  log_msg(LOG_WARN, "unsupported length calculation for key / type %hhd", node->key.type); break;
	}
	// assert(byte_size  >= 2);
	// log_msg(LOG_DEBUG, "key size (%hd) calculated to %llu", node->key.type, byte_size);

	switch(node->val.type) {
  		case short_type: 		  byte_size += 1 + sizeof(int8_t); break;
		case int_type: 			  byte_size += 1 + sizeof(int16_t); break;
		case long_type: 		  byte_size += 1 + sizeof(int32_t); break;
		case long_long_type:	  byte_size += 1 + sizeof(int64_t); break;
 		case float_type: 		  byte_size += 1 + sizeof(float); break;
		case double_type: 		  byte_size += 1 + sizeof(double); break;
		case char_ptr_type: 	  byte_size += 1 + sizeof(uint32_t) + node->val.size; break;
		case char_type: 		  byte_size += 1 + sizeof(char); break;
		case unsigned_char_type:  byte_size += 1 + sizeof(unsigned char); break;
 		case unsigned_short_type: byte_size += 1 + sizeof(uint8_t); break;
		case unsigned_int_type:   byte_size += 1 + sizeof(uint16_t); break;
		case unsigned_long_type:  byte_size += 1 + sizeof(uint32_t); break;
		case unsigned_long_long_type:  byte_size += 1 + sizeof(uint64_t); break;
 		case uint_array_2_type:    byte_size += 1 + 2 * sizeof(uint16_t); break;
 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
 		case unsigned_char_array_8_type: byte_size += 1+8*sizeof(unsigned char); break;
 		case void_type: 		  byte_size += 1 + sizeof(void*); break;
 		case bin_type: 			  byte_size += 1 + sizeof(uint32_t) + node->val.size; break;
		case jrb_tree_type:
			// use the real tree byte_size since data could have been altered
			byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + node->val.value.tree->byte_size;
			break;
		case key_type:            byte_size += 1 + (4 * sizeof(uint64_t)); break;
		default:                  log_msg(LOG_WARN, "unsupported length calculation for value / type %hhd", node->val.type ); break;
	}
	// log_msg(LOG_DEBUG, "value size (%hd) calculated to %llu", node->val.type, byte_size);
	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculated to %llu", node, byte_size);

	// assert(byte_size  >= 4);

	return byte_size;
}

void jrb_insert_str (np_jtree_t* tree, const char *key, np_jval_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	np_jtree_elem_t* found = jrb_find_str(tree, key);

	if (found == NULL) {
		// insert new value
		found = (np_jtree_elem_t*) malloc(sizeof(np_jtree_elem_t));

		found->key.value.s = strndup(key, 255);
	    found->key.type = char_ptr_type;
	    found->key.size = strlen(key);

	    found->val = copy_of_jval(val);
		// log_msg(LOG_WARN, "e->%p k->%p v->%p", found, found->key.value.s, &found->val);
		// log_msg(LOG_WARN, "e->%p k->%p v->%p", found, &found->key, &found->val);

		RB_INSERT(np_jtree, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void jrb_insert_int (np_jtree_t* tree, int16_t ikey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_int(tree, ikey);

	if (found == NULL) {
		// insert new value
		found = (np_jtree_elem_t*) malloc(sizeof(np_jtree_elem_t));
		// if (NULL == found) return;

	    found->key.value.i = ikey;
	    found->key.type = int_type;
	    found->key.size = sizeof(int16_t);
	    found->val = copy_of_jval(val);

		RB_INSERT(np_jtree, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}


void jrb_insert_ulong (np_jtree_t* tree, uint32_t ulkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_ulong(tree, ulkey);

	if (found == NULL) {
		// insert new value
		found = (np_jtree_elem_t*) malloc(sizeof(np_jtree_elem_t));
	    found->key.value.ul = ulkey;
	    found->key.type = unsigned_long_type;
	    found->key.size = sizeof(uint32_t);

	    found->val = copy_of_jval(val);

		RB_INSERT(np_jtree, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void jrb_insert_dbl (np_jtree_t* tree, double dkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_dbl(tree, dkey);

	if (found == NULL) {
		// insert new value
		found = (np_jtree_elem_t*) malloc(sizeof(np_jtree_elem_t));
		found->key.value.d = dkey;
	    found->key.type = double_type;
	    found->key.size = sizeof(double);

	    found->val = copy_of_jval(val);

		RB_INSERT(np_jtree, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	} else {
		// log_msg(LOG_WARN, "not inserting double key (%f) into jtree", dkey );
	}
}


void jrb_replace_str (np_jtree_t* tree, const char *key, np_jval_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	np_jtree_elem_t* found = jrb_find_str(tree, key);

	if (found == NULL) {
		// insert new value
		jrb_insert_str(tree, key, val);

	} else {
		// free up memory before replacing
		tree->byte_size -= jrb_get_byte_size(found);

		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

		// copy_jval(&val, &found->val);
	    found->val = copy_of_jval(val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void jrb_replace_int (np_jtree_t* tree, int16_t ikey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_int(tree, ikey);

	if (found == NULL) {
		// insert new value
		jrb_insert_int(tree, ikey, val);

	} else {
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

		// copy_jval(&val, &found->val);
	    found->val = copy_of_jval(val);

		tree->byte_size += jrb_get_byte_size(found);
	}
}

void jrb_replace_ulong (np_jtree_t* tree, uint32_t ulkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_ulong(tree, ulkey);

	if (found == NULL) {
		jrb_insert_ulong(tree, ulkey, val);

	} else {
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_jval(val);
	    // copy_jval(&val, &found->val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void jrb_replace_dbl (np_jtree_t* tree, double dkey, np_jval_t val)
{
	assert(tree    != NULL);

	np_jtree_elem_t* found = jrb_find_dbl(tree, dkey);

	if (found == NULL) {
		// insert new value
		jrb_insert_dbl(tree, dkey, val);

	} else {
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_jval(val);
	    // copy_jval(&val, &found->val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

