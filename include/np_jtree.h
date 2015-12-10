/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef	_NP_JTREE_H_
#define	_NP_JTREE_H_

#include "include.h"
#include "tree.h"
#include "np_key.h"


struct np_jtree {
	struct np_jtree_elem_s *rbh_root;

	uint16_t size;
	uint64_t byte_size;
};

struct np_jtree_elem_s
{
	RB_ENTRY(np_jtree_elem_s) link;

	np_jval_t key;
    np_jval_t val;
};

int16_t jval_cmp(const np_jtree_elem_t* j1, const np_jtree_elem_t* j2);

RB_PROTOTYPE(np_jtree, np_jtree_elem_s, link, jval_cmp);

/* Creates a new jtree */
np_jtree_t*   make_jtree ();

/* Delete and free an entire tree */
void np_free_tree (np_jtree_t* root);
/* delete an tree, but keep the root node for re-use */
void np_clear_tree (np_jtree_t* root);

// insert a jval into the tree using different keys
void jrb_insert_str (np_jtree_t *tree, const char *key, np_jval_t val);
void jrb_insert_int (np_jtree_t *tree, int16_t ikey, np_jval_t val);
void jrb_insert_ulong (np_jtree_t *tree, uint32_t ulkey, np_jval_t val);
void jrb_insert_dbl (np_jtree_t *tree, double dkey, np_jval_t val);

// replace a jval in the tree, inserts the jval if the key is not present
void jrb_replace_str (np_jtree_t *tree, const char *key, np_jval_t val);
void jrb_replace_int (np_jtree_t *tree, int16_t ikey, np_jval_t val);
void jrb_replace_ulong (np_jtree_t *tree, uint32_t ulkey, np_jval_t val);
void jrb_replace_dbl (np_jtree_t *tree, double dkey, np_jval_t val);

/* returns an external node in t whose value is equal k. Returns NULL if
   there is no such node in the tree */
np_jtree_elem_t* jrb_find_str (np_jtree_t* root, const char *key);
np_jtree_elem_t* jrb_find_int (np_jtree_t* root, int16_t ikey);
np_jtree_elem_t* jrb_find_ulong (np_jtree_t* root, uint32_t ikey);
np_jtree_elem_t* jrb_find_dbl (np_jtree_t* root, double dkey);

/* returns an external node in t whose value is equal
  k or whose value is the smallest value greater than k. Sets found to
  1 if the key was found, and 0 otherwise.  */
np_jtree_elem_t* jrb_find_gte_str (np_jtree_t* root, const char *key, uint8_t *found);
np_jtree_elem_t* jrb_find_gte_int (np_jtree_t* root, int16_t ikey, uint8_t *found);
np_jtree_elem_t* jrb_find_gte_ulong (np_jtree_t* root, uint32_t ikey, uint8_t *found);
np_jtree_elem_t* jrb_find_gte_dbl (np_jtree_t* root, double dkey, uint8_t *found);

// replacce the entire tree with the new jval
void jrb_replace_all_with_str(np_jtree_t* root, const char* key, np_jval_t val);

/* Deletes and frees a node */
void del_str_node (np_jtree_t* tree, const char *key);
void del_int_node (np_jtree_t* tree, const int16_t key);
void del_dbl_node (np_jtree_t* tree, const double key);
void del_ulong_node (np_jtree_t* tree, const uint32_t key);

// print the contents of the tree to the log file,
// TODO will leak memory right now
void np_print_tree (np_jtree_t* n, uint8_t indent);

uint64_t jrb_get_byte_size(np_jtree_elem_t* node);

#endif // _NP_JTREE_H_
