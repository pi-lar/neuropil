//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// Original version taken from chimera project, copyright (C) 2001 James S. Plank

/*
Published under the GNU Lesser General Public License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version

modified and refactored to use the BSD tree algorithms (:ref tree.h:):
Copyright 2002 Niels Provos <provos@citi.umich.edu>
*/
#ifndef	_NP_TREE_H_
#define	_NP_TREE_H_

#include <stdint.h>

#include "tree/tree.h"
#include "msgpack/cmp.h"

#include "np_types.h"
#include "np_treeval.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * convenience helper macros when messages are received
 * check the existence of a field and extracts it, otherwise continues with a goto __cleanup__
 */
#define CHECK_STR_FIELD(TREE, FIELD_NAME, VAR_NAME) 						\
np_treeval_t VAR_NAME = np_treeval_NULL; 									\
if (NULL == np_tree_find_str(TREE, FIELD_NAME)){							\
    if (NULL != np_tree_find_str(TREE, _NP_MSG_HEADER_SUBJECT)){			\
        log_msg(LOG_WARN,"Missing field \"%s\" in message for \"%s\"",		\
            FIELD_NAME,														\
            np_treeval_to_str(np_tree_find_str(TREE, _NP_MSG_HEADER_SUBJECT)->val,NULL));	\
    }else {																	\
        log_msg(LOG_WARN,"Missing field \"%s\" in tree", FIELD_NAME);		\
    }																		\
    goto __np_cleanup__; 													\
} 																			\
else VAR_NAME = np_tree_find_str(TREE, FIELD_NAME)->val;

#define CHECK_STR_FIELD_BOOL(TREE, FIELD_NAME, VAR_NAME, ERROR_MSG, ...) 					 \
np_tree_elem_t* VAR_NAME = NULL;                                                             \
if(!np_tree_check_field(context, TREE, FIELD_NAME, _NP_MSG_HEADER_SUBJECT, &VAR_NAME)) {     \
    log_debug(LOG_ERROR,ERROR_MSG, __VA_ARGS__);                                               \
} else

/**
.. c:type:: np_tree_conf_t

   additional configuration attributes for a tree

   in_place:bool: true = allow the tree to use the original pointers instead of creating a copy every time. false = make a copy of every value
   immutable:bool: true = dont't allow the tree to be modified. false = allow modifications

*/
struct np_tree_conf_s {
    bool in_place;
    bool immutable;
    bool disable_special_str;
} NP_API_EXPORT;

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
    uint32_t byte_size;
    np_tree_conf_t attr;
} NP_API_EXPORT;

#ifndef SWIG
typedef struct np_tree_elem_s np_tree_elem_t;
struct np_tree_elem_s
{
    RB_ENTRY(np_tree_elem_s) link;

    np_treeval_t key;
    np_treeval_t val;
} NP_API_INTERN;
#endif

NP_API_INTERN
int16_t _np_tree_elem_cmp(const np_tree_elem_t* j1, const np_tree_elem_t* j2);

RB_PROTOTYPE(np_tree_s, np_tree_elem_s, link, _val_cmp);

/**
.. c:function:: np_tree_create

   create a new instance of a np_tree_t structure

   :return: the newly constructed np_tree_t

*/
NP_API_EXPORT
np_tree_t*   np_tree_create ();

/**
.. c:function:: void np_free_tree(np_tree_t* root)

   Delete and free an entire tree

   :param root: the np_tree_t struture which should be freed

*/
NP_API_EXPORT
void np_tree_free (np_tree_t* root);

/**
.. c:function:: void np_clear_tree(np_tree_t* root)

   clear a np_tree_t structure, but keep the root node for re-use

   :param root: the np_tree_t structure which should be freed

*/
NP_API_EXPORT
void np_tree_clear(np_tree_t* root);

/**
.. c:function:: void tree_insert_str(np_tree_t *tree, const char *key, np_treeval_t val)
.. c:function:: void np_tree_insert_int(np_tree_t *tree, int16_t ikey, np_treeval_t val)
.. c:function:: void np_tree_insert_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val)
.. c:function:: void np_tree_insert_dbl( np_tree_t *tree, double dkey, np_treeval_t val)

   insert a value into the np_tree_t with the given key. mixing key types in one np_tree_t
   is not prohibited, but useless since then there is no ordering of elements and lookup of keys
   will fail. However, you can use a different key type when adding subtree's to you tree structure

   Inserting a value will not override an already existing value

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param val: a generic np_treeval_t structure to add any kind of values to the structure

*/
NP_API_EXPORT
void np_tree_insert_str(np_tree_t *tree, const char *key, np_treeval_t val);
NP_API_EXPORT
void np_tree_insert_int(np_tree_t *tree, int16_t ikey, np_treeval_t val);
NP_API_EXPORT
void np_tree_insert_dhkey(np_tree_t *tree, np_dhkey_t key, np_treeval_t val);
NP_API_EXPORT
void np_tree_insert_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val);
NP_API_EXPORT
void np_tree_insert_dbl( np_tree_t *tree, double dkey, np_treeval_t val);

/**
.. c:function:: void np_tree_replace_str(np_tree_t *tree, const char *key, np_treeval_t val)
.. c:function:: void np_tree_replace_int(np_tree_t *tree, int16_t ikey, np_treeval_t val)
.. c:function:: void np_tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val)
.. c:function:: void np_tree_replace_dbl( np_tree_t *tree, double dkey, np_treeval_t val)

   Replace a value into the np_tree_t with the given key, and insert if it not already existed.
   Otherwise the same rules as for jrb_insert_[str|int|ulong|dbl] functions apply.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param val: a generic np_treeval_t structure to add any kind of values to the structure

*/
NP_API_EXPORT
void np_tree_replace_str(np_tree_t *tree, const char *key, np_treeval_t val);
NP_API_EXPORT
void np_tree_replace_int(np_tree_t *tree, int16_t ikey, np_treeval_t val);
NP_API_EXPORT
void np_tree_replace_dhkey(np_tree_t *tree, np_dhkey_t key, np_treeval_t val);
NP_API_EXPORT
void np_tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, np_treeval_t val);
NP_API_EXPORT
void np_tree_replace_dbl( np_tree_t *tree, double dkey, np_treeval_t val);

/**
.. c:function:: np_tree_elem_t* np_tree_find_str(np_tree_t *tree, const char *key)
.. c:function:: np_tree_elem_t* np_tree_replace_int(np_tree_t *tree, int16_t ikey)
.. c:function:: np_tree_elem_t* np_tree_replace_ulong(np_tree_t *tree, uint32_t ulkey)
.. c:function:: np_tree_elem_t* np_tree_replace_dbl( np_tree_t *tree, double dkey)

   Lookup a value in the tree structure for a given key. You have to check the return value
   for NULL before accessing the np_treeval_t structure.

   Searching an element is not recursively stepping into subtree structures.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :return np_tree_elem_t*: a pointer to a np_tree_elem_t element which contains the np_treeval_t under the val member

*/
NP_API_EXPORT
np_tree_elem_t* np_tree_find_str (np_tree_t* root, const char *key);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_int(np_tree_t* root, int16_t ikey);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_dhkey(np_tree_t* root, np_dhkey_t key);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_ulong (np_tree_t* root, uint32_t ikey);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_dbl (np_tree_t* root, double dkey);

/**
.. c:function:: np_tree_elem_t* np_tree_find_str(np_tree_t *tree, const char *key, uint8_t *found)
.. c:function:: np_tree_elem_t* np_tree_replace_int(np_tree_t *tree, int16_t ikey, uint8_t *found)
.. c:function:: np_tree_elem_t* np_tree_replace_ulong(np_tree_t *tree, uint32_t ulkey, uint8_t *found)
.. c:function:: np_tree_elem_t* np_tree_replace_dbl( np_tree_t *tree, double dkey, uint8_t *found)

   Lookup a value in the tree structure for a given key. Returns an external node in the np_tree_t
   whose value is equal k or whose value is the smallest value greater than k. Sets found to
   1 if the key was found, and 0 otherwise. You still have to check the return value for NULL before
   accessing the np_treeval_t structure.

   Searching an element is not recursively stepping into subtree structures.

   :param tree: the np_tree_t structure where the value should be inserted
   :param key: the key that should be used to insert/lookup values
   :param found: point to a local uint8_t variable to store whether an result has been found
   :return np_tree_elem_t*: a pointer to a np_tree_elem_t element which contains the np_treeval_t under the val member

  */
NP_API_EXPORT
np_tree_elem_t* np_tree_find_gte_str (np_tree_t* root, const char *key, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_gte_int (np_tree_t* root, int16_t ikey, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_gte_ulong (np_tree_t* root, uint32_t ikey, uint8_t *found);
NP_API_EXPORT
np_tree_elem_t* np_tree_find_gte_dbl (np_tree_t* root, double dkey, uint8_t *found);

// replace the entire tree with the new jval
NP_API_INTERN
void _np_tree_replace_all_with_str(np_tree_t* root, const char* key, np_treeval_t val);

/* Deletes and frees a node */
NP_API_EXPORT
void np_tree_del_str (np_tree_t* tree, const char *key);
NP_API_EXPORT
void np_tree_del_int(np_tree_t* tree, const int16_t key);
NP_API_EXPORT
void np_tree_del_dhkey(np_tree_t* tree, const np_dhkey_t key);
NP_API_EXPORT
void np_tree_del_double (np_tree_t* tree, const double key);
NP_API_EXPORT
void np_tree_del_ulong (np_tree_t* tree, const uint32_t key);

NP_API_INTERN
uint32_t np_tree_get_byte_size(np_tree_elem_t* node);

/**
.. c:function:: np_tree_t* np_tree_clone(np_tree_t* source)

   convenience function to create a full clone of a given tree

   :param tree: the np_tree_t structure to copy

  */
NP_API_EXPORT
np_tree_t* np_tree_clone(np_tree_t* source);

/**
.. c:function:: np_tree_t* np_tree_copy(np_tree_t* source, np_tree_t* target)

   convenience function to copy data from a given tree into an other tree (may NOT override the source)

   :param tree: the np_tree_t structure to copy

*/
NP_API_EXPORT
void np_tree_copy(np_tree_t* source, np_tree_t* target);

/**
.. c:function:: np_tree_t* np_tree_copy_inplace(np_tree_t* source, np_tree_t* target)

   convenience function to copy data from a given tree into an other tree (may override the source)

   :param tree: the np_tree_t structure to copy

*/
NP_API_EXPORT
void np_tree_copy_inplace(np_tree_t* source, np_tree_t* target);

NP_API_INTERN
void np_tree_serialize(np_state_t* context, np_tree_t* jrb, cmp_ctx_t* cmp);
NP_API_INTERN
bool np_tree_deserialize( np_state_t* context, np_tree_t* jrb, cmp_ctx_t* cmp);

NP_API_INTERN
uint8_t __np_tree_serialize_read_type_dhkey(cmp_ctx_t* cmp_key, np_treeval_t* target);
NP_API_INTERN
void __np_tree_serialize_write_type_dhkey(np_dhkey_t source, cmp_ctx_t* target);
NP_API_INTERN
void __np_tree_serialize_write_type(np_state_t* context, np_treeval_t val, cmp_ctx_t* cmp);
NP_API_INTERN
void __np_tree_deserialize_read_type(np_state_t* context, np_tree_t* tree, cmp_object_t* obj, cmp_ctx_t* cmp, np_treeval_t* value, NP_UNUSED char* key_to_read_for);
NP_API_INTERN
void np_tree_insert_special_str(np_tree_t* tree, const uint8_t key, np_treeval_t val);
NP_API_INTERN
bool _np_tree_is_special_str(const char* in_question, uint8_t* idx_on_found);
NP_API_INTERN
const char* _np_tree_get_special_str(uint8_t idx);
NP_API_INTERN
void np_tree_del_element(np_tree_t* tree, np_tree_elem_t* to_delete);
NP_API_INTERN
void np_tree_insert_element(np_tree_t* tree, np_tree_elem_t* ele);
NP_API_INTERN
void np_tree_replace_treeval(np_tree_t* tree, np_tree_elem_t* element, np_treeval_t val);
NP_API_INTERN
void np_tree_set_treeval(np_tree_t* tree, np_tree_elem_t* element, np_treeval_t val);
NP_API_EXPORT
unsigned char* np_tree_get_hash(np_tree_t* self);
NP_API_INTERN
bool np_tree_check_field(np_state_t* context, np_tree_t* tree, const char* field_name, const  char* _NP_MSG_HEADER_SUBJECT, np_tree_elem_t** buffer) ;
#ifdef __cplusplus
}
#endif

#endif // _NP_TREE_H_
