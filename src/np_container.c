#include <assert.h>
#include <pthread.h>
#include <stdlib.h>

#include "np_container.h"

#include "np_key.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_key_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_job_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_message_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_msgproperty_t);
NP_SLL_GENERATE_IMPLEMENTATION(np_aaatoken_t);

// used for logging
NP_SLL_GENERATE_IMPLEMENTATION(char);

NP_PLL_GENERATE_IMPLEMENTATION(np_job_ptr);

int16_t strjval_cmp(struct strjval_s *e1, struct strjval_s *e2) {
	return strncmp(e1->key, e1->key, 64);
}


RB_GENERATE(strjval_s_tree, strjval_s, link, strjval_cmp);
