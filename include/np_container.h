#ifndef _NP_CONTAINER_H
#define _NP_CONTAINER_H

#include "include.h"

#include "jval.h"
#include "np_list.h"
#include "tree.h"

// NP_DLL_GENERATE_PROTOTYPES(np_key_t);
NP_SLL_GENERATE_PROTOTYPES(np_key_t);
NP_SLL_GENERATE_PROTOTYPES(np_obj_t);

// used for logging
NP_SLL_GENERATE_PROTOTYPES(char);

/**
 ** create a key/value rbtree using strings as the key
 **/
typedef struct strjval_tree np_strjval_tree;
typedef struct strjval_s np_strjval_t;

struct strjval_s {
	RB_ENTRY(strjval_s) link;
	const char* key;
    np_jval_t val;
};

int strjval_cmp(struct strjval_s *e1, struct strjval_s *e2);

#define RB_INSERT_NEW(head, TYPE, key_elem, val_elem) \
do {\
	TYPE* new_elem = (TYPE*) malloc(sizeof(TYPE)); \
	new_elem->key = key_elem; \
	new_elem->val = val_elem; \
	RB_INSERT(strjval_tree, head, new_elem); \
} while(0);

RB_HEAD(strjval_tree, strjval_s); // head = RB_INITIALIZER(&head);
RB_PROTOTYPE(strjval_tree, strjval_s, link, strjval_cmp);

#endif // _NP_CONTAINER_H
