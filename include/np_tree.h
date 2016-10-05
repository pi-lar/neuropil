//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// Original version taken from chimera project, copyright (C) 2001 James S. Plank
/*
Published under the GNU Lesser General Public License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version

modified and refactored to use the BSD tree algorithms (:ref tree.h:):
Copyright 2002 Niels Provos <provos@citi.umich.edu>
*/
#ifndef	_NP_JTREE_H_
#define	_NP_JTREE_H_

#include "tree/tree.h"

#include "np_types.h"
#include "np_val.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
.. c:type:: np_tree_t

   np_tree_t is the structure to store a hierarchical key-value list.
   Internally a red-black-tree algorithm is used to identify and store values.
   The functions to store data in the np_tree_t structure will create a copy.
   It should be safe to free/delete your own data structures after you've passed in a value to the tree.
   Values could be a np_tree_t structure again, there is no limit to the nesting depth defined

   The np_tree_t structure is re-used in many aspects in the neuropil library.
   One main usage is for the np_message_t structure, which mainly consists of several np_tree_t elements
   that form the different message parts.
*/

struct np_tree_s
{
	struct np_tree_elem_s *rbh_root;

	uint16_t size;
	uint64_t byte_size;
} NP_API_EXPORT;

typedef struct np_tree_elem_s np_tree_elem_t;
struct np_tree_elem_s
{
	RB_ENTRY(np_tree_elem_s) link;

	np_val_t key;
    np_val_t val;
} NP_API_INTERN;


NP_API_INTERN
int16_t _val_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2);

RB_PROTOTYPE(np_tree_s, np_tree_elem_s, link, _val_cmp);

/**
.. c:function:: make_nptree

   create a new instance of a np_tree_t structure

   :return: the newly constructed np_tree_t
*/
NP_API_EXPORT
np_tree_t*   make_nptree ();

/**
.. c:function:: void np_free_tree(np_tree_t* root)

   Delete and free an entire tree

   :param root: the np_tree_t struture which should be freed
*/
NP_API_EXPORT
void np_free_tree (np_tree_t* root);

/**
.. c:function:: void np_clear_tree(np_tree_t* root)

   clear a np_tree_t structure, but keep the root node for re-use

   :param root: the np_tree_t structure which should be freed
*/
NP_API_EXPORT
void np_clear_tree (np_tree_t* root);

/**
.. c:function:: void tree_insert_str(np_tree_t *tree, const char *key, np_val_t val)
.. c:function:: void tree_insert_int(np_tree_t *tree, int16_t ikey, np_val_t val)
.. c:function:: void tree_insert_ulong(np_tree_t *tree, uint32_t ulkey, np_val_t val)
.. c:function:: void tree_insert_dbl(np_tree_t *tree, double dkey, np_val_t val)

   insert a value into the np_tree_t with the given key. mixing key types in one np_tree_t
   is not prohibited, but useless since then there is no ordering of elements and lookup of keys
   will fail. However, you can use a different key type when adding subtree's to you tree structure

   Inserting a value will not override an already existing value

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param val: a generic np_val_t structure to add any kind of values to the structure
*/
NP_API_EXPORT
void tree_insert_str (np_tree_t *tree, const char *key, np_val_t val);
NP_API_EXPORT
void tree_insert_int (np_tree_t *tree, int16_t ikey, np_val_t val);
NP_API_EXPORT
void tree_insert_ulong (np_tree_t *tree, uint32_t ulkey, np_val_t val);
NP_API_EXPORT
void tree_insert_dbl (np_tree_t *tree, double dkey, np_val_t val);

/**
.. c:function:: void tree_replace_str(np_tree_t *tree, const char *key, np_val_t val)
.. c:function:: void tree_replace_int(np_tree_t *tree, int16_t ikey, np_val_t val)
.. c:function:: void tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, np_val_t val)
.. c:function:: void tree_replace_dbl(np_tree_t *tree, double dkey, np_val_t val)

   Replace a value into the np_tree_t with the given key, and insert if it not already existed.
   Otherwise the same rules as for jrb_insert_[str|int|ulong|dbl] functions apply.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param val: a generic np_val_t structure to add any kind of values to the structure
*/
NP_API_EXPORT
void tree_replace_str (np_tree_t *tree, const char *key, np_val_t val);
NP_API_EXPORT
void tree_replace_int (np_tree_t *tree, int16_t ikey, np_val_t val);
NP_API_EXPORT
void tree_replace_ulong (np_tree_t *tree, uint32_t ulkey, np_val_t val);
NP_API_EXPORT
void tree_replace_dbl (np_tree_t *tree, double dkey, np_val_t val);

/**
.. c:function:: np_tree_elem_t* tree_find_str(np_tree_t *tree, const char *key)
.. c:function:: np_tree_elem_t* tree_replace_int(np_tree_t *tree, int16_t ikey)
.. c:function:: np_tree_elem_t* tree_replace_ulong(np_tree_t *tree, uint32_t ulkey)
.. c:function:: np_tree_elem_t* tree_replace_dbl(np_tree_t *tree, double dkey)

   Lookup a value in the tree structure for a given key. You have to check the return value
   for NULL before accessing the np_val_t structure.

   Searching an element is not recursively stepping into subtree structures.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :return np_tree_elem_t*: a pointer to a np_tree_elem_t element which contains the np_val_t under the val member
*/
NP_API_EXPORT
np_tree_elem_t* tree_find_str (np_tree_t* root, const char *key);
NP_API_EXPORT
np_tree_elem_t* tree_find_int (np_tree_t* root, int16_t ikey);
NP_API_EXPORT
np_tree_elem_t* tree_find_ulong (np_tree_t* root, uint32_t ikey);
NP_API_EXPORT
np_tree_elem_t* tree_find_dbl (np_tree_t* root, double dkey);

/**
.. c:function:: np_tree_elem_t* tree_find_str(np_tree_t *tree, const char *key, uint8_t *found)
.. c:function:: np_tree_elem_t* tree_replace_int(np_tree_t *tree, int16_t ikey, uint8_t *found)
.. c:function:: np_tree_elem_t* tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, uint8_t *found)
.. c:function:: np_tree_elem_t* tree_replace_dbl(np_tree_t *tree, double dkey, uint8_t *found)

   Lookup a value in the tree structure for a given key. Returns an external node in the np_tree_t
   whose value is equal k or whose value is the smallest value greater than k. Sets found to
   1 if the key was found, and 0 otherwise. You still have to check the return value for NULL before
   accessing the np_val_t structure.

   Searching an element is not recursively stepping into subtree structures.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param found: point to a local uint8_t variable to store whether an result has been found
   :return np_tree_elem_t*: a pointer to a np_tree_elem_t element which contains the np_val_t under the val member
  */
NP_API_EXPORT
np_tree_elem_t* tree_find_gte_str (np_tree_t* root, const char *key, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* tree_find_gte_int (np_tree_t* root, int16_t ikey, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* tree_find_gte_ulong (np_tree_t* root, uint32_t ikey, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* tree_find_gte_dbl (np_tree_t* root, double dkey, uint8_t *found);

// replace the entire tree with the new jval
NP_API_INTERN
void _tree_replace_all_with_str(np_tree_t* root, const char* key, np_val_t val);

/* Deletes and frees a node */
NP_API_EXPORT
void tree_del_str (np_tree_t* tree, const char *key);
NP_API_EXPORT
void tree_del_int (np_tree_t* tree, const int16_t key);
NP_API_EXPORT
void tree_del_double (np_tree_t* tree, const double key);
NP_API_EXPORT
void tree_del_ulong (np_tree_t* tree, const uint32_t key);

// print the contents of the tree to the log file,
// TODO will leak memory right now
NP_API_INTERN
void np_print_tree (np_tree_t* n, uint8_t indent);

NP_API_INTERN
uint64_t jrb_get_byte_size(np_tree_elem_t* node);


#ifdef __cplusplus
}
#endif

#endif // _NP_JTREE_H_