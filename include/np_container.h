/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_CONTAINER_H
#define _NP_CONTAINER_H

#include "include.h"

#include "jval.h"
#include "np_list.h"
#include "tree.h"

#ifdef __cplusplus
extern "C" {
#endif

NP_SLL_GENERATE_PROTOTYPES(np_job_t);
NP_SLL_GENERATE_PROTOTYPES(np_key_t);
NP_SLL_GENERATE_PROTOTYPES(np_message_t);
NP_SLL_GENERATE_PROTOTYPES(np_msgproperty_t);
NP_SLL_GENERATE_PROTOTYPES(np_aaatoken_t);

NP_PLL_GENERATE_PROTOTYPES(np_aaatoken_ptr);

// the floowing list type is used for logging
NP_SLL_GENERATE_PROTOTYPES(char);

// priority list for jobs
NP_PLL_GENERATE_PROTOTYPES(np_job_ptr);


/**
 ** create a key/value rbtree using strings as the key
 **/
typedef struct strjval_s_tree np_strjval_t_tree;
typedef struct strjval_s np_strjval_t;

struct strjval_s {
	RB_ENTRY(strjval_s) link;
	const char* key;
    np_jval_t val;
};

int16_t strjval_cmp(struct strjval_s *e1, struct strjval_s *e2);

RB_HEAD(strjval_s_tree, strjval_s); // head = RB_INITIALIZER(&head);
RB_PROTOTYPE(strjval_s_tree, strjval_s, link, strjval_cmp);

#ifdef __cplusplus
}
#endif

#endif // _NP_CONTAINER_H
