
#include <assert.h>
#include <errno.h>

#include "aaatoken.h"
#include "jrb.h"
#include "dtime.h"
#include "log.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);


np_aaatoken_cache_t* np_init_aaa_cache() {

	np_aaatoken_cache_t* aaa_cache = (np_aaatoken_cache_t*) malloc(sizeof(np_aaatoken_cache_t));

	aaa_cache->authentication_token = make_jrb();
	aaa_cache->authorization_token = make_jrb();
	aaa_cache->accounting_token = make_jrb();

	if (pthread_mutex_init(&aaa_cache->lock, NULL) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL);
	}

	return aaa_cache;
}

void np_aaatoken_t_new(void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
	aaa_token->token_id = NULL;
    aaa_token->issued_at = dtime();
    // set expiration to one day and recreate each day by default
    // TODO: make it configurable or use random timeframe
    struct timeval e_exp = dtotv(aaa_token->issued_at);
    e_exp.tv_sec += 86400;
    aaa_token->expiration = tvtod(e_exp);
    uuid_generate(aaa_token->uuid);
    aaa_token->extensions = make_jrb();
	aaa_token->valid = 0;
}

void np_aaatoken_t_del (void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
	// clean up extensions
	jrb_free_tree(aaa_token->extensions);
}

// deprecated ???
void np_free_aaatoken(np_aaatoken_cache_t* cache, np_obj_t* token) {

	np_jrb_t* node = NULL;
	np_aaatoken_t* tmp_token;
	np_bind(np_aaatoken_t, token, tmp_token);

	node = jrb_find_key(cache->accounting_token, tmp_token->token_id);
	if (node) {
		np_free(np_aaatoken_t, node->val.value.obj);
		jrb_delete_node(node);
		np_unbind(np_aaatoken_t, token, tmp_token);
		return;
	}

	node = jrb_find_key(cache->authorization_token, tmp_token->token_id);
	if (node) {
		np_free(np_aaatoken_t, node->val.value.obj);
		jrb_delete_node(node);
		np_unbind(np_aaatoken_t, token, tmp_token);
		return;
	}

	node = jrb_find_key(cache->authentication_token, tmp_token->token_id);
	if (node) {
		np_free(np_aaatoken_t, node->val.value.obj);
		jrb_delete_node(node);
		np_unbind(np_aaatoken_t, token, tmp_token);
		return;
	}
	np_unbind(np_aaatoken_t, token, tmp_token);
}

void np_register_authorization_token(np_aaatoken_cache_t* cache, np_obj_t* token, np_key_t* key)
{
	np_jrb_t* tmp = jrb_find_key(cache->authorization_token, key);
	if (tmp) {
		np_free(np_aaatoken_t, tmp->val.value.obj);
		jrb_delete_node(tmp);
	}
	jrb_insert_key(cache->authorization_token, key, new_jval_obj (token));
}

void np_register_authentication_token(np_aaatoken_cache_t* cache, np_obj_t* token, np_key_t* key)
{
	np_jrb_t* tmp = jrb_find_key(cache->authentication_token, key);
	if (tmp) {
		np_free(np_aaatoken_t, tmp->val.value.obj);
		jrb_delete_node(tmp);
	}
	jrb_insert_key(cache->authentication_token, key, new_jval_obj (token));
}

void np_register_accounting_token(np_aaatoken_cache_t* cache, np_obj_t* token, np_key_t* key)
{
	np_jrb_t* tmp = jrb_find_key(cache->accounting_token, key);
	if (tmp) {
		np_free(np_aaatoken_t, tmp->val.value.obj);
		jrb_delete_node(tmp);
	}
	jrb_insert_key(cache->accounting_token, key, new_jval_obj (token));
}

np_obj_t* np_get_authorization_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	np_obj_t* o_ret_token;
	np_jrb_t* jrb_node = jrb_find_key(cache->authorization_token, key);

	if (jrb_node == NULL) {
		np_new(np_aaatoken_t, o_ret_token);
		jrb_insert_key(cache->authorization_token, key, new_jval_obj(o_ret_token) );
	} else {
		o_ret_token = jrb_node->val.value.obj;
	}
	return o_ret_token;
}

np_obj_t* np_get_authentication_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	np_obj_t* o_ret_token;
	np_jrb_t* jrb_node = jrb_find_key(cache->authentication_token, key);

	if (jrb_node == NULL) {
		np_new(np_aaatoken_t, o_ret_token);
		jrb_insert_key(cache->authentication_token, key, new_jval_obj(o_ret_token) );
	} else {
		o_ret_token = jrb_node->val.value.obj;
	}
	return o_ret_token;
}

np_obj_t* np_get_accounting_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	np_obj_t* o_ret_token;
	np_jrb_t* jrb_node = jrb_find_key(cache->accounting_token, key);

	if (jrb_node == NULL) {
		np_new(np_aaatoken_t, o_ret_token);
		jrb_insert_key(cache->accounting_token, key, new_jval_obj(o_ret_token) );
	} else {
		o_ret_token = jrb_node->val.value.obj;
	}
	return o_ret_token;
}

