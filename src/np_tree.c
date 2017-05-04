//
// neuropil is copyright 2016 by pi-lar GmbH
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

#include "np_tree.h"

#include "np_log.h"

RB_GENERATE(np_tree_s, np_tree_elem_s, link, _val_cmp);

//RB_GENERATE_STATIC(np_str_jtree, np_tree_elem_s, link, _val_cmp);
//RB_GENERATE_STATIC(np_int_jtree, np_tree_elem_s, link, _val_cmp);
//RB_GENERATE_STATIC(np_dbl_jtree, np_tree_elem_s, link, _val_cmp);
//RB_GENERATE_STATIC(np_ulong_jtree, np_tree_elem_s, link, _val_cmp);

np_tree_t* make_nptree ()
{
	np_tree_t* new_tree = (np_tree_t*) malloc(sizeof(np_tree_t));
	CHECK_MALLOC(new_tree);

	new_tree->rbh_root = NULL;
	new_tree->size = 0;
	new_tree->byte_size = 5;

	return new_tree;
}

int16_t _val_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2)
{
	assert(NULL != j1);
	assert(NULL != j2);

	np_val_t jv1 = j1->key;
	np_val_t jv2 = j2->key;

	if (jv1.type == jv2.type)
	{
		if (jv1.type == char_ptr_type)
			return strncmp(jv1.value.s, jv2.value.s, 64);

		if (jv1.type == double_type)
		{
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

np_tree_elem_t* tree_find_gte_str (np_tree_t* n, const char *key, uint8_t *fnd)
{
	assert(n   != NULL);
	assert(key != NULL);

	np_tree_elem_t* result = NULL;

	np_val_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		0    == strncmp(result->key.value.s, key, strlen(key)) )
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}
	return (result);
}

np_tree_elem_t* tree_find_str (np_tree_t* n, const char *key)
{
	assert(NULL != n);
	assert(NULL != key);

	np_val_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_tree_elem_t search_elem = { .key = search_key };
	return RB_FIND(np_tree_s, n, &search_elem);
}

np_tree_elem_t* tree_find_gte_int (np_tree_t* n, int16_t ikey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_tree_elem_t* result = NULL;

	np_val_t search_key = { .type = int_type, .value.i = ikey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.i == ikey )
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}

np_tree_elem_t* tree_find_int (np_tree_t* n, int16_t key)
{
	np_val_t search_key = { .type = int_type, .value.i = key };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* tree_find_gte_ulong (np_tree_t* n, uint32_t ulkey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_tree_elem_t* result = NULL;

	np_val_t search_key = { .type = unsigned_long_type, .value.ul = ulkey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.ul == ulkey )
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}

np_tree_elem_t* tree_find_ulong (np_tree_t* n, uint32_t ulkey)
{
	np_val_t search_key = { .type = unsigned_long_type, .value.ul = ulkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

np_tree_elem_t* tree_find_gte_dbl (np_tree_t* n, double dkey, uint8_t *fnd)
{
	assert(n   != NULL);

	np_tree_elem_t* result = NULL;

	np_val_t search_key = { .type = double_type, .value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };

	result = RB_NFIND(np_tree_s, n, &search_elem);
	if (NULL != result &&
		result->key.value.d == dkey )
	{
		*fnd = 1;
	}
	else
	{
		*fnd = 0;
	}

	return (result);
}


np_tree_elem_t* tree_find_dbl (np_tree_t* n, double dkey)
{
	np_val_t search_key = { .type = double_type, .value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };
	return (RB_FIND(np_tree_s, n, &search_elem));
}

void tree_del_str (np_tree_t* tree, const char *key)
{
	np_val_t search_key = { .type = char_ptr_type, .value.s = (char*) key };
	np_tree_elem_t search_elem = { .key = search_key };

	np_tree_elem_t* to_delete = RB_FIND(np_tree_s, tree, &search_elem);
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);

		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		free(to_delete->key.value.s);

		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void tree_del_int (np_tree_t* tree, const int16_t key)
{
	np_val_t search_key = { .type = int_type, .value.i = key };
	np_tree_elem_t search_elem = { .key = search_key };

	np_tree_elem_t* to_delete = RB_FIND(np_tree_s, tree, &search_elem);
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void tree_del_double (np_tree_t* tree, const double dkey)
{
	np_val_t search_key = { .type = double_type, .value.d = dkey };
	np_tree_elem_t search_elem = { .key = search_key };

	np_tree_elem_t* to_delete = RB_FIND(np_tree_s, tree, &search_elem);
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);
		free (to_delete);
	}
}

void tree_del_ulong (np_tree_t* tree, const uint32_t key)
{
	np_val_t search_key = { .type = unsigned_long_type, .value.ul = key };
	np_tree_elem_t search_elem = { .key = search_key };

	np_tree_elem_t* to_delete = RB_FIND(np_tree_s, tree, &search_elem);
	if (to_delete != NULL)
	{
		RB_REMOVE(np_tree_s, tree, to_delete);
		tree->byte_size -= jrb_get_byte_size(to_delete);
		tree->size--;
		if (to_delete->val.type == char_ptr_type) free(to_delete->val.value.s);
		if (to_delete->val.type == bin_type) free(to_delete->val.value.bin);
		if (to_delete->val.type == jrb_tree_type) np_free_tree(to_delete->val.value.tree);

		free (to_delete);
	}
}

void np_clear_tree (np_tree_t* n)
{
	np_tree_elem_t* iter = RB_MIN(np_tree_s, n);
	np_tree_elem_t* tmp = NULL;

	if (NULL != iter)
	{
		do
		{
			tmp = iter;
			// log_msg(LOG_WARN, "jrb_free_tree: e->%p k->%p v->%p", tmp, tmp->key.value.s, &tmp->val);
			iter = RB_NEXT(np_tree_s, n, iter);
			// log_msg(LOG_WARN, "jrb_free_tree: t->%p i->%p", tmp, iter);

			switch (tmp->key.type)
			{
			case (char_ptr_type):
				tree_del_str(n, tmp->key.value.s);
				break;
			case (int_type):
				tree_del_int(n, tmp->key.value.i);
				break;
			case (double_type):
				tree_del_double(n, tmp->key.value.d);
				break;
			case (unsigned_long_type):
				tree_del_ulong(n, tmp->key.value.ul);
				break;
			default:
				break;
			}

		} while (NULL != iter);
	}
}

void np_free_tree (np_tree_t* n)
{
	if(NULL != n) {
		if(n->size > 0) {
			np_clear_tree(n);
		}
		free (n);
		n = NULL;
	}
}

void np_print_tree (np_tree_t* n, uint8_t indent)
{
	np_tree_elem_t* tmp = NULL;

	RB_FOREACH(tmp, np_tree_s, n)
	{
		char s_indent[indent+1];
		memset(s_indent, ' ', indent);
		s_indent[indent] = '\0';

		if (tmp->key.type == char_ptr_type)      log_msg(LOG_DEBUG, "%s%s: %s", s_indent, val_to_str(tmp->key), val_to_str(tmp->val));
		if (tmp->key.type == int_type)           log_msg(LOG_DEBUG, "%s%s: %s", s_indent, val_to_str(tmp->key), val_to_str(tmp->val));
		if (tmp->key.type == double_type)        log_msg(LOG_DEBUG, "%s%s: %s", s_indent, val_to_str(tmp->key), val_to_str(tmp->val));
		if (tmp->key.type == unsigned_long_type) log_msg(LOG_DEBUG, "%s%s: %s", s_indent, val_to_str(tmp->key), val_to_str(tmp->val));

		if (tmp->val.type == jrb_tree_type) np_print_tree(tmp->val.value.v, indent+1);
	}
}

void _tree_replace_all_with_str(np_tree_t* n, const char* key, np_val_t val)
{
	np_clear_tree(n);
    tree_insert_str(n, key, val);
}

np_val_t jrb_val (np_tree_elem_t* n)
{
	assert(n     != NULL);
    return n->val;
}

uint64_t jrb_get_byte_size(np_tree_elem_t* node)
{
	assert(node  != NULL);

	// if (isint(node)) return 0;

	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculation", node);
	uint64_t byte_size = 0;

	switch(node->key.type)
	{
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

	switch(node->val.type)
	{
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
 		case uint_array_2_type:   byte_size += 1 + 2*sizeof(uint16_t); break;
 		case float_array_2_type:  byte_size += 1 + 2*sizeof(float); break;
 		case char_array_8_type:   byte_size += 1 + 8*sizeof(char); break;
 		case unsigned_char_array_8_type: byte_size += 1+8*sizeof(unsigned char); break;
 		case void_type: 		  byte_size += 1 + sizeof(void*); break;
 		case bin_type: 			  byte_size += 1 + sizeof(uint32_t) + node->val.size; break;
 		case hash_type: 		  byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + node->val.size; break;
		case jrb_tree_type:       byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + node->val.value.tree->byte_size; break;
		case key_type:            byte_size += 1 + sizeof(uint32_t) + sizeof(int8_t) + (4 * sizeof(uint64_t)); break;
		default:                  log_msg(LOG_WARN, "unsupported length calculation for value / type %hhd", node->val.type ); break;
	}
	// log_msg(LOG_DEBUG, "value size (%hd) calculated to %llu", node->val.type, byte_size);
	// log_msg(LOG_DEBUG, "c: %p -> key/value size calculated to %llu", node, byte_size);

	// assert(byte_size  >= 4);

	return byte_size;
}

void tree_insert_str (np_tree_t* tree, const char *key, np_val_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	np_tree_elem_t* found = tree_find_str(tree, key);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*) malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.s = strndup(key, 255);
	    found->key.type = char_ptr_type;
	    found->key.size = strlen(key);

	    found->val = copy_of_val(val);
		// log_msg(LOG_WARN, "e->%p k->%p v->%p", found, found->key.value.s, &found->val);
		// log_msg(LOG_WARN, "e->%p k->%p v->%p", found, &found->key, &found->val);

		RB_INSERT(np_tree_s, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_insert_int (np_tree_t* tree, int16_t ikey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_int(tree, ikey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*) malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		// if (NULL == found) return;

	    found->key.value.i = ikey;
	    found->key.type = int_type;
	    found->key.size = sizeof(int16_t);
	    found->val = copy_of_val(val);

		RB_INSERT(np_tree_s, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_insert_ulong (np_tree_t* tree, uint32_t ulkey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_ulong(tree, ulkey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*) malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

	    found->key.value.ul = ulkey;
	    found->key.type = unsigned_long_type;
	    found->key.size = sizeof(uint32_t);

	    found->val = copy_of_val(val);

		RB_INSERT(np_tree_s, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_insert_dbl (np_tree_t* tree, double dkey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_dbl(tree, dkey);

	if (found == NULL)
	{
		// insert new value
		found = (np_tree_elem_t*) malloc(sizeof(np_tree_elem_t));
		CHECK_MALLOC(found);

		found->key.value.d = dkey;
	    found->key.type = double_type;
	    found->key.size = sizeof(double);

	    found->val = copy_of_val(val);

		RB_INSERT(np_tree_s, tree, found);
	    tree->size++;
		tree->byte_size += jrb_get_byte_size(found);
	}
	else
	{
		// log_msg(LOG_WARN, "not inserting double key (%f) into jtree", dkey );
	}
}

void tree_replace_str (np_tree_t* tree, const char *key, np_val_t val)
{
	assert(tree    != NULL);
	assert(key     != NULL);

	np_tree_elem_t* found = tree_find_str(tree, key);

	if (found == NULL)
	{
		// insert new value
		tree_insert_str(tree, key, val);
	}
	else
	{
		// free up memory before replacing
		tree->byte_size -= jrb_get_byte_size(found);

		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_val(val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_replace_int (np_tree_t* tree, int16_t ikey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_int(tree, ikey);

	if (found == NULL)
	{
		// insert new value
		tree_insert_int(tree, ikey, val);
	}
	else
	{
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_val(val);

		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_replace_ulong (np_tree_t* tree, uint32_t ulkey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_ulong(tree, ulkey);

	if (found == NULL)
	{
		tree_insert_ulong(tree, ulkey, val);
	}
	else
	{
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_val(val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

void tree_replace_dbl (np_tree_t* tree, double dkey, np_val_t val)
{
	assert(tree    != NULL);

	np_tree_elem_t* found = tree_find_dbl(tree, dkey);

	if (found == NULL)
	{
		// insert new value
		tree_insert_dbl(tree, dkey, val);
	}
	else
	{
		tree->byte_size -= jrb_get_byte_size(found);
		// free up memory before replacing
		if (found->val.type == char_ptr_type) free(found->val.value.s);
		if (found->val.type == bin_type)      free(found->val.value.bin);
		if (found->val.type == jrb_tree_type) np_free_tree(found->val.value.tree);

	    found->val = copy_of_val(val);
		tree->byte_size += jrb_get_byte_size(found);
	}
}

np_tree_t* np_tree_copy(np_tree_t* source) {

	np_tree_t* ret =	make_nptree();
	np_tree_elem_t* tmp = NULL;
	RB_FOREACH(tmp, np_tree_s, source)
	{
		if (tmp->key.type == char_ptr_type)      tree_insert_str(ret, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           tree_insert_int(ret, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        tree_insert_dbl(ret, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) tree_insert_ulong(ret, tmp->key.value.ul, tmp->val);
	}
	return ret;
}

