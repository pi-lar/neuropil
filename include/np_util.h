/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef	_NP_UTIL_H_
#define	_NP_UTIL_H_

#include "cmp.h"

#include "np_jtree.h"

#define START_LOCK(x) { pthread_mutex_lock(&x->lock);
#define END_LOCK(x)     pthread_mutex_unlock(&x->lock); }


np_bool buffer_reader(cmp_ctx_t *ctx, void *data, size_t count);
size_t buffer_writer(cmp_ctx_t *ctx, const void *data, size_t count);

void serialize_jrb_node_t(np_jtree_t* jrb, cmp_ctx_t* cmp);
void deserialize_jrb_node_t(np_jtree_t* jrb, cmp_ctx_t* cmp);

#endif // _NP_UTIL_H_
