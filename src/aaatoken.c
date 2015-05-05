
#include <errno.h>

#include "aaatoken.h"
#include "jrb.h"
#include "dtime.h"
#include "log.h"


np_aaatoken_cache_t* np_init_aaa_cache() {

	np_aaatoken_cache_t* aaa_cache = (np_aaatoken_cache_t*) malloc(sizeof(np_aaatoken_cache_t));

	aaa_cache->authentication_token = make_jrb();
	aaa_cache->authorization_token = make_jrb();
	aaa_cache->accounting_token = make_jrb();

	if (pthread_mutex_init(&aaa_cache->aaa_account_mutex, NULL) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL );
	}
	if (pthread_mutex_init(&aaa_cache->aaa_authorize_mutex, NULL) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL );
	}
	if (pthread_mutex_init(&aaa_cache->aaa_authenticate_mutex, NULL) != 0) {
		log_msg(LOG_ERROR, "pthread_mutex_init: %s", strerror (errno));
		return (NULL );
	}

	return aaa_cache;
}

np_aaatoken_t* np_aaatoken_create(np_aaatoken_cache_t* cache) {

	np_aaatoken_t* aaa_token = (np_aaatoken_t*) malloc(sizeof(np_aaatoken_t));
	aaa_token->token_id = NULL;
    aaa_token->issued_at = dtime();
    // set expiration to one day and recreate each day by default
    // TODO: make it configurable or use random timeframe
    struct timeval e_exp = dtotv(aaa_token->issued_at);
    e_exp.tv_sec += 86400;
    aaa_token->expiration = tvtod(e_exp);
    uuid_generate(aaa_token->uuid);
    aaa_token->ref_count = 0;
    aaa_token->extensions = make_jrb();
	aaa_token->valid = 0;

    return aaa_token;
}

void np_aaatoken_retain(np_aaatoken_t* token) {
	// TODO could be error prone in multithreading, needs a mutex ?
	token->ref_count++;
}

void np_aaatoken_release (np_aaatoken_t* aaatoken)
{
	aaatoken->ref_count--;

	if (aaatoken->ref_count <= 0) {
		// clean up cache
		np_free_aaatoken(aaatoken->cache, aaatoken);
		jrb_delete_node(aaatoken->extensions);
		free(aaatoken);
	}
}


void np_free_aaatoken(np_aaatoken_cache_t* cache, const np_aaatoken_t* token) {

	np_jrb_t* node = NULL;

	pthread_mutex_lock(&cache->aaa_account_mutex);
	node = jrb_find_key(cache->accounting_token, token->token_id);
	if (node) {
		jrb_delete_node(node);
		pthread_mutex_unlock(&cache->aaa_account_mutex);
		return;
	}
	pthread_mutex_unlock(&cache->aaa_account_mutex);

	pthread_mutex_lock(&cache->aaa_authorize_mutex);
	node = jrb_find_key(cache->authorization_token, token->token_id);
	if (node) {
		jrb_delete_node(node);
		pthread_mutex_unlock(&cache->aaa_authorize_mutex);
		return;
	}
	pthread_mutex_unlock(&cache->aaa_authorize_mutex);

	pthread_mutex_lock(&cache->aaa_authenticate_mutex);
	node = jrb_find_key(cache->authentication_token, token->token_id);
	if (node) {
		jrb_delete_node(node);
		pthread_mutex_unlock(&cache->aaa_authenticate_mutex);
		return;
	}
	pthread_mutex_unlock(&cache->aaa_authenticate_mutex);
}

void np_register_authorization_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_authorize_mutex);
	jrb_insert_key(cache->authorization_token, key, new_jval_v (token));
	pthread_mutex_unlock(&cache->aaa_authorize_mutex);

}

void np_register_authentication_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_authenticate_mutex);
	jrb_insert_key(cache->authentication_token, key, new_jval_v (token));
	pthread_mutex_unlock(&cache->aaa_authenticate_mutex);
}

void np_register_accounting_token(np_aaatoken_cache_t* cache, const np_aaatoken_t* token, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_account_mutex);
	jrb_insert_key(cache->accounting_token, key, new_jval_v (token));
	pthread_mutex_unlock(&cache->aaa_account_mutex);
}

np_aaatoken_t* np_get_authorization_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_authorize_mutex);
	np_jrb_t* jrb_node = jrb_find_key(cache->authorization_token, key);
	pthread_mutex_unlock(&cache->aaa_authorize_mutex);

	if (jrb_node) return (np_aaatoken_t*) jrb_node->val.value.v;

	return NULL;
}

np_aaatoken_t* np_get_authentication_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_authenticate_mutex);
	np_jrb_t* jrb_node = jrb_find_key(cache->authentication_token, key);
	pthread_mutex_unlock(&cache->aaa_authenticate_mutex);

	if (jrb_node) return (np_aaatoken_t*) jrb_node->val.value.v;

	return NULL;

}

np_aaatoken_t* np_get_accounting_token(np_aaatoken_cache_t* cache, np_key_t* key)
{
	pthread_mutex_lock(&cache->aaa_account_mutex);
	np_jrb_t* jrb_node = jrb_find_key(cache->accounting_token, key);
	pthread_mutex_unlock(&cache->aaa_account_mutex);

	if (jrb_node) return (np_aaatoken_t*) jrb_node->val.value.v;

	return NULL;
}

