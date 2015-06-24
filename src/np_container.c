#include <pthread.h>

#include "np_container.h"

#include "key.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_key_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_obj_t);

// used for logging
NP_SLL_GENERATE_IMPLEMENTATION(char);

int strjval_cmp(struct strjval_s *e1, struct strjval_s *e2) {
	return strncmp(e1->key, e1->key, 64);
}

RB_GENERATE(strjval_tree, strjval_s, link, strjval_cmp);
