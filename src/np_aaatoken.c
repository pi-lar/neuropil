/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#include <assert.h>
#include <errno.h>

#include "event/ev.h"

#include "np_aaatoken.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_tree.h"
#include "np_keycache.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_threads.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);

NP_SLL_GENERATE_IMPLEMENTATION(np_aaatoken_t);

NP_PLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

void _np_aaatoken_t_new(void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

	aaa_token->realm[0]      = '\0';

	aaa_token->issuer[0]     = '\0';
	aaa_token->subject[0]    = '\0';
	aaa_token->audience[0]   = '\0';

	aaa_token->public_key[0] = '\0';

	aaa_token->uuid = NULL;

	aaa_token->issued_at = ev_time();
    // set expiration to one day and recreate each day by default
    // TODO: make it configurable or use random timeframe
    aaa_token->expiration = aaa_token->issued_at + 120;
    aaa_token->extensions = make_jtree();
    aaa_token->state |= AAA_INVALID;
}

void _np_aaatoken_t_del (void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
	// clean up extensions
	if (NULL != aaa_token->extensions)
	{
		np_free_tree(aaa_token->extensions);
	}
	if (NULL != aaa_token->uuid)
	{
		free(aaa_token->uuid);
	}
}

void np_encode_aaatoken(np_tree_t* data, np_aaatoken_t* token)
{
	// add e2e encryption details for sender
	tree_insert_str(data, "_np.realm", new_val_s(token->realm));

	tree_insert_str(data, "_np.subject", new_val_s(token->subject));
	tree_insert_str(data, "_np.issuer", new_val_s(token->issuer));
	tree_insert_str(data, "_np.audience", new_val_s(token->audience));

	tree_insert_str(data, "_np.uuid", new_val_s(token->uuid));

	tree_insert_str(data, "_np.not_before", new_val_d(token->not_before));
	tree_insert_str(data, "_np.expiration", new_val_d(token->expiration));

	tree_insert_str(data, "_np.public_key", new_val_bin(token->public_key, crypto_sign_PUBLICKEYBYTES));
	tree_insert_str(data, "_np.ext", new_val_tree(token->extensions));
}

void np_decode_aaatoken(np_tree_t* data, np_aaatoken_t* token)
{
	assert (NULL != data);
	assert (NULL != token);

	// get e2e encryption details of sending entity
	if (NULL != tree_find_str(data, "_np.realm"))
	{
		strncpy(token->realm, tree_find_str(data, "_np.realm")->val.value.s, 255);
	}

	if (NULL != tree_find_str(data, "_np.subject"))
	{
		strncpy(token->subject, tree_find_str(data, "_np.subject")->val.value.s, 255);
	}
	if (NULL != tree_find_str(data, "_np.issuer"))
	{
		strncpy(token->issuer, tree_find_str(data, "_np.issuer")->val.value.s, 255);
	}
	if (NULL != tree_find_str(data, "_np.audience"))
	{
		strncpy(token->audience, tree_find_str(data, "_np.audience")->val.value.s, 255);
	}

	if (NULL != tree_find_str(data, "_np.uuid"))
	{
		token->uuid = strndup(tree_find_str(data, "_np.uuid")->val.value.s, 255);
	}

	if (NULL != tree_find_str(data, "_np.not_before"))
	{
		token->not_before = tree_find_str(data, "_np.not_before")->val.value.d;
	}
	if (NULL != tree_find_str(data, "_np.expiration"))
	{
		token->expiration = tree_find_str(data, "_np.expiration")->val.value.d;
	}

	if (NULL != tree_find_str(data, "_np.public_key"))
	{
		memcpy(token->public_key, tree_find_str(data, "_np.public_key")->val.value.bin, crypto_sign_PUBLICKEYBYTES);
	}

	// decode extensions
	if (NULL != tree_find_str(data, "_np.ext"))
	{
		np_clear_tree(token->extensions);
		np_tree_t* from = tree_find_str(data, "_np.ext")->val.value.tree;
		np_tree_elem_t* tmp = NULL;
		RB_FOREACH(tmp, np_tree_s, from)
		{
			if (tmp->key.type == char_ptr_type)      tree_insert_str(token->extensions, tmp->key.value.s, tmp->val);
			if (tmp->key.type == int_type)           tree_insert_int(token->extensions, tmp->key.value.i, tmp->val);
			if (tmp->key.type == double_type)        tree_insert_dbl(token->extensions, tmp->key.value.d, tmp->val);
			if (tmp->key.type == unsigned_long_type) tree_insert_ulong(token->extensions, tmp->key.value.ul, tmp->val);
		}
	}

//	log_msg(LOG_DEBUG, "realm             : %s", token->realm);
//	log_msg(LOG_DEBUG, "issuer            : %s", token->issuer);
//	log_msg(LOG_DEBUG, "subject           : %s", token->subject);
//	log_msg(LOG_DEBUG, "audience          : %s", token->audience);
//	log_msg(LOG_DEBUG, "uuid              : %s", token->uuid);

//	struct timeval token_time;
//	struct tm token_ts;
//	char time_entry[27];
//	token_time.tv_sec = (long) token->issued_at;
//	token_time.tv_usec = (long) ((token->issued_at - (double) token_time.tv_sec) * 1000000.0);
//	localtime_r(&token_time.tv_sec, &token_ts);
//	strftime(time_entry,    19, "%Y-%m-%d %H:%M:%S", &token_ts);
//	snprintf(time_entry+19,  6, ".%6d", token_time.tv_usec);
//	log_msg(LOG_DEBUG, "issued date       : %s", time_entry);
//
//	token_time.tv_sec = (long) token->expiration;
//	token_time.tv_usec = (long) ((token->expiration - (double) token_time.tv_sec) * 1000000.0);
//	localtime_r(&token_time.tv_sec, &token_ts);
//	strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
//	snprintf(time_entry+19, 6, ".%6d", token_time.tv_usec);
//	log_msg(LOG_DEBUG, "expiration        : %s", time_entry);
//
//	char pub_key[2*crypto_sign_PUBLICKEYBYTES+1];
//	sodium_bin2hex(pub_key, 2*crypto_sign_PUBLICKEYBYTES+1, token->public_key, crypto_sign_PUBLICKEYBYTES);
//	log_msg(LOG_DEBUG, "public_key        : %s", pub_key);

	// log_msg(LOG_DEBUG, "extensions        : %s");
}

np_dhkey_t _np_create_dhkey_for_token(np_aaatoken_t* identity)
{
	// build a hash to find a place in the dhkey table, not for signing !
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, sizeof hash);

	crypto_generichash_update(&gh_state, (const unsigned char*) identity->realm, strlen(identity->realm));
	crypto_generichash_update(&gh_state, (const unsigned char*) identity->issuer, strlen(identity->issuer));
	crypto_generichash_update(&gh_state, (const unsigned char*) identity->subject, strlen(identity->subject));
	// TODO: useful extension for building the dhkey ?
	// crypto_generichash_update(&gh_state, (const unsigned char*) identity->audience, strlen(identity->audience));
	crypto_generichash_update(&gh_state, (const unsigned char*) identity->uuid, strlen(identity->uuid));

	crypto_generichash_final(&gh_state, hash, sizeof hash);

	char key[65];
	sodium_bin2hex(key, 65, hash, 32);
	np_dhkey_t search_key = dhkey_create_from_hash(key);
	return (search_key);
}

np_bool token_is_valid(np_aaatoken_t* token)
{
	assert (NULL != token);

	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.token_is_valid");

	// TODO: useful extension ?
	// unsigned char key[crypto_generichash_KEYBYTES];
	// randombytes_buf(key, sizeof key);
	unsigned char hash[crypto_generichash_BYTES];

	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, sizeof hash);
	crypto_generichash_update(&gh_state, (unsigned char*) token->realm, strlen(token->realm));
	crypto_generichash_update(&gh_state, (unsigned char*) token->issuer, strlen(token->issuer));
	crypto_generichash_update(&gh_state, (unsigned char*) token->subject, strlen(token->subject));
	crypto_generichash_update(&gh_state, (unsigned char*) token->audience, strlen(token->audience));
	if (NULL != token->uuid)
		crypto_generichash_update(&gh_state, (unsigned char*) token->uuid, strlen(token->uuid));
	crypto_generichash_update(&gh_state, (unsigned char*) token->public_key, crypto_sign_PUBLICKEYBYTES);
	// TODO: hash 'not_before' and 'expiration' values as well ?
	crypto_generichash_final(&gh_state, hash, sizeof hash);

	char hash_hex[crypto_generichash_BYTES*2+1];
	sodium_bin2hex(hash_hex, crypto_generichash_BYTES*2+1, hash, crypto_generichash_BYTES);
	log_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s", hash_hex);
//	log_msg(LOG_DEBUG, "##%s##", token->realm);
//	log_msg(LOG_DEBUG, "##%s##", token->issuer);
//	log_msg(LOG_DEBUG, "##%s##", token->subject);
//	log_msg(LOG_DEBUG, "##%s##", token->audience);
//	log_msg(LOG_DEBUG, "##%s##", token->uuid);
//	log_msg(LOG_DEBUG, "##%s##", token->public_key);

	// verify inserted signature first
	char* signature = NULL;
	unsigned long long signature_len = 0;
	if (NULL != tree_find_str(token->extensions, NP_HS_SIGNATURE))
	{
		signature = tree_find_str(token->extensions, NP_HS_SIGNATURE)->val.value.bin;
		signature_len = crypto_sign_BYTES; // tree_find_str(token->extensions, NP_HS_SIGNATURE)->val.size;
		log_msg(LOG_AAATOKEN | LOG_DEBUG, "found signature with length %llu for checksum verification", signature_len);
	}

	if (NULL != signature)
	{
		int16_t ret = crypto_sign_verify_detached((unsigned char*) signature, hash, crypto_generichash_BYTES, token->public_key);
		if (ret < 0)
		{
			log_msg(LOG_WARN, "token checksum verification failed");
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state &= AAA_INVALID;
			return (FALSE);
		}
	}
	else
	{
		log_msg(LOG_WARN, "signature missing in token, not continuing without checksum verification");
		return (FALSE);
	}

	// check timestamp
	double now = ev_time();
	if (now > (token->expiration))
	{
		log_msg(LOG_DEBUG, "token has expired: %f>%f", now, token->expiration);
		log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
		token->state &= AAA_INVALID;
		return (FALSE);
	}

	// TODO: only if this is a message token
	if (tree_find_str(token->extensions, "max_threshold") &&
		tree_find_str(token->extensions, "msg_threshold"))
	{
		uint16_t token_max_threshold = tree_find_str(token->extensions, "max_threshold")->val.value.ui;
		uint16_t token_msg_threshold = tree_find_str(token->extensions, "msg_threshold")->val.value.ui;

		if (0                   <=  token_msg_threshold &&
			token_msg_threshold <   token_max_threshold)
		{
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state |= AAA_VALID;
			return (TRUE);
		}
		else
		{
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "token was already used: 0<=%d<%d", token_msg_threshold, token_max_threshold);
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			token->state &= AAA_INVALID;
			return (FALSE);
		}
	}

	token->state |= AAA_VALID;
	return (TRUE);
}

static int8_t _token_cmp (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
	int8_t ret_check = 0;

	if (first == second) return (0);

	ret_check = strncmp(first->issuer, second->issuer, strlen(first->issuer));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->subject, second->subject, (strlen(first->subject)));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	return (0);
}

static int8_t _token_cmp_exact (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
	int8_t ret_check = 0;

	if (first == second) return (0);

	ret_check = sodium_memcmp(first->public_key, second->public_key, crypto_sign_PUBLICKEYBYTES);
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->uuid, second->uuid, strlen(first->uuid));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->issuer, second->issuer, strlen(first->issuer));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->subject, second->subject, strlen(first->subject));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
	if (0 != ret_check )
	{
		return (ret_check);
	}

	return (0);
}

void _create_token_ledger(np_key_t* subject_key, char* subject)
{
	np_msgproperty_t* prop = NULL;

	if (NULL == subject_key->recv_tokens)
		pll_init(np_aaatoken_ptr, subject_key->recv_tokens);

	if (NULL == subject_key->send_tokens)
		pll_init(np_aaatoken_ptr, subject_key->send_tokens);

	if (NULL != (prop = np_msgproperty_get(OUTBOUND, subject)) )
	{
		// sender
		if (NULL == subject_key->send_property)
		{
			subject_key->send_property = prop;
		}
	}
	else if (NULL != (prop = np_msgproperty_get(INBOUND, subject)) )
	{
		// receiver
		if (NULL == subject_key->recv_property)
		{
			subject_key->recv_property = prop;
		}
	}
	else
	{
		np_new_obj(np_msgproperty_t, prop);
	}

	if (NULL == subject_key->send_property)
		subject_key->send_property = prop;

	if (NULL == subject_key->recv_property)
		subject_key->recv_property = prop;
}

// update internal structure and return a interest if a matching pair has been found
void _np_add_sender_token(char* subject, np_aaatoken_t *token)
{
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.np_add_sender_token");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
		_create_token_ledger(subject_key, subject);
	}

	// should never happen
	if (NULL == subject_key) return;

	log_msg(LOG_AAATOKEN | LOG_DEBUG,
			"update in global sender msg token structures (%p)...",
			subject_key->send_property);

	// insert new token
	LOCK_CACHE(subject_key->send_property)
	{
		// update #2 subject specific data
		subject_key->send_property->mep_type |= (tree_find_str(token->extensions, "mep_type")->val.value.ul & SENDER_MASK);
		subject_key->send_property->ack_mode = tree_find_str(token->extensions, "ack_mode")->val.value.ush;

		subject_key->send_property->last_update = ev_time();

		uint16_t max_threshold = tree_find_str(token->extensions, "max_threshold")->val.value.ui;
		np_aaatoken_t *tmp_token = NULL;

		if (max_threshold > 0)
		{
			np_msg_mep_type sender_mep_type = subject_key->send_property->mep_type & SENDER_MASK;

			np_aaatoken_ptr_cmp_func_t cmp_aaatoken_add     = _token_cmp;
			np_aaatoken_ptr_cmp_func_t cmp_aaatoken_replace = _token_cmp_exact;
			np_bool allow_dups = TRUE;

			if (SINGLE_SENDER == (SINGLE_SENDER & sender_mep_type))
			{
				cmp_aaatoken_replace   = _token_cmp;
				allow_dups = FALSE;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token);
			tmp_token = pll_replace(np_aaatoken_ptr, subject_key->send_tokens, token, cmp_aaatoken_replace);
			if (NULL == tmp_token)
			{
				pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = tmp_token->state;
				np_unref_obj(np_aaatoken_t, tmp_token);
			}
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_key_as_str(subject_key) );
		}
	}

	// check for outdated token
	LOCK_CACHE(subject_key->send_property)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter)
		{
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "checking sender msg tokens %p/%p", iter, iter->val);
			np_aaatoken_t* tmp_token = iter->val;
			pll_next(iter);

			if (NULL  != tmp_token &&
				FALSE == token_is_valid(tmp_token) )
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "deleting old / invalid sender msg tokens %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->send_tokens, tmp_token, _token_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token);
				break;
			}
		}
	}

	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .np_add_sender_token");
}

/** np_get_sender_token
 ** retrieve a list of valid sender tokens from the cache
 ** TODO extend this function with a key and an amount of messages
 ** TODO use a different function for mitm and leaf nodes ?
 **/
sll_return(np_aaatoken_t) _np_get_sender_token_all(char* subject)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
	    // look up target structures or create them
		_create_token_ledger(subject_key, subject);
	}

	// log_msg(LOG_DEBUG, "available %hd interests %hd", subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list) = NULL;
	sll_init(np_aaatoken_t, return_list);

	// should never happen
	if (NULL == subject_key)
	{
		return (return_list);
	}

	pll_iterator(np_aaatoken_ptr) tmp = NULL;

	log_msg(LOG_AAATOKEN | LOG_DEBUG,
			"lookup in global sender msg token structures (%p)...",
			subject_key->send_property);

	LOCK_CACHE(subject_key->send_property)
	{
		tmp = pll_first(subject_key->send_tokens);
		while (NULL != tmp)
		{
			if (FALSE == token_is_valid(tmp->val))
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->val->issuer);
			}
			else
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", tmp->val->issuer );
				// only pick key from a list if the subject msg_treshold is bigger than zero
				// and the sending threshold is bigger than zero as well
				// and we actually have a receiver node in the list
				np_ref_obj(np_aaatoken_t, tmp->val);
				sll_append(np_aaatoken_t, return_list, tmp->val);
			}
			pll_next(tmp);
		}
	}
	return (return_list);
}

np_aaatoken_t* _np_get_sender_token(char* subject, char* sender)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
	    // look up target structures or create them
		_create_token_ledger(subject_key, subject);
	}

	// should never happen
	if (NULL == subject_key)
	{
		return (NULL);
	}

	log_msg(LOG_AAATOKEN | LOG_DEBUG,
			"lookup in global sender msg token structures (%p)...",
			subject_key->send_property);

//	log_msg(LOG_DEBUG, "available %hd interests %hd",
//						subject_key->send_property->max_threshold,
//						subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	np_bool found_return_token = FALSE;

	LOCK_CACHE(subject_key->send_property)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->send_tokens);
		while (NULL != iter &&
			   FALSE == found_return_token)
		{
			return_token = iter->val;
			if (FALSE == token_is_valid(return_token))
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid sender token for issuer %s", return_token->issuer);
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and we actually have the correct sender node in the list
			if (0 != strncmp(return_token->issuer, sender, 64))
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring sender token for issuer %s / send_hk: %s",
						return_token->issuer, sender);
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			if (IS_AUTHORIZED(return_token->state) && IS_AUTHENTICATED(return_token->state))
			{
				found_return_token = TRUE;
				np_ref_obj(np_aaatoken_t, return_token);
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", return_token->issuer);
			}
		}
	}
	return (return_token);
}

// update internal structure and clean invalid tokens
void _np_add_receiver_token(char* subject, np_aaatoken_t *token)
{
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".start.np_add_receiver_token");

	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
	    _create_token_ledger(subject_key, subject);
	}

	// should never happen
	if (NULL == subject_key) return;

	log_msg(LOG_AAATOKEN | LOG_DEBUG, "update on global receiving msg token structures ... %p", subject_key->recv_property);

	// insert new token
	LOCK_CACHE(subject_key->recv_property)
	{
		// update #2 subject specific data
//		log_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x mask %03x",
//										  subject_key->recv_property->mep_type, (RECEIVER_MASK | FILTER_MASK) );

		subject_key->recv_property->mep_type |= (tree_find_str(token->extensions, "mep_type")->val.value.ul & RECEIVER_MASK);

//		log_msg(LOG_AAATOKEN | LOG_DEBUG, "receiver token %03x %03x",
//				                          subject_key->recv_property->mep_type, tree_find_str(token->extensions, "mep_type")->val.value.ul );

		// subject_key->recv_property->ack_mode = tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->recv_property->last_update = ev_time();

		uint16_t max_threshold = tree_find_str(token->extensions, "max_threshold")->val.value.ui;

		log_msg(LOG_AAATOKEN | LOG_DEBUG, "adding receiver token %p threshold %d", token, max_threshold );

		if (max_threshold > 0)
		{	// only add if there are messages to receive
			np_msg_mep_type receiver_mep_type = (subject_key->recv_property->mep_type & RECEIVER_MASK);
			np_aaatoken_t* tmp_token = NULL;

			np_aaatoken_ptr_cmp_func_t cmp_aaatoken_replace = _token_cmp_exact;
			np_aaatoken_ptr_cmp_func_t cmp_aaatoken_add     = _token_cmp;
			np_bool allow_dups = TRUE;

			if (SINGLE_RECEIVER == (SINGLE_RECEIVER & receiver_mep_type))
			{
				cmp_aaatoken_replace   = _token_cmp;
				allow_dups = FALSE;
			}

			// update #1 key specific data
			np_ref_obj(np_aaatoken_t, token);
			tmp_token = pll_replace(np_aaatoken_ptr, subject_key->recv_tokens, token, cmp_aaatoken_replace);
			if (NULL == tmp_token)
			{
				pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, allow_dups, cmp_aaatoken_add);
			}
			else
			{
				token->state = tmp_token->state;
				np_unref_obj(np_aaatoken_t, tmp_token);
			}
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s",
					_key_as_str(subject_key) );
		}
	}

	// check for old and outdated token
	LOCK_CACHE(subject_key->recv_property)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);

		while (NULL != iter)
		{
			np_aaatoken_t* tmp_token = iter->val;
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);

			pll_next(iter);

			if (NULL  != tmp_token &&
				FALSE == token_is_valid(tmp_token) )
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "deleting old / invalid receiver msg tokens %p", tmp_token);
				pll_remove(np_aaatoken_ptr, subject_key->recv_tokens, tmp_token, _token_cmp_exact);
				np_unref_obj(np_aaatoken_t, tmp_token);
				break;
			}
		}
	}
	log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .np_add_receiver_token");
}

np_aaatoken_t* _np_get_receiver_token(char* subject)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
		_create_token_ledger(subject_key, subject);
	}

	// should never happen
	if (NULL == subject_key) return (NULL);

	// log_msg(LOG_DEBUG, "available %hd interests %hd",
	// subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	np_bool found_return_token = FALSE;

	LOCK_CACHE(subject_key->recv_property)
	{
		pll_iterator(np_aaatoken_ptr) iter = pll_first(subject_key->recv_tokens);
		while (NULL != iter &&
			   FALSE == found_return_token)
		{
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "checking receiver msg tokens %p/%p", iter, iter->val);
			return_token = iter->val;

			if (FALSE == token_is_valid(return_token))
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg tokens %p", return_token );
				pll_next(iter);
				return_token = NULL;
				continue;
			}

			log_msg(LOG_AAATOKEN | LOG_DEBUG,
					"found valid receiver token (%s)", return_token->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			// sll_append(np_aaatoken_t, return_list, tmp);
			if (IS_AUTHORIZED(return_token->state) && IS_AUTHENTICATED(return_token->state))
			{
				found_return_token = TRUE;
				np_ref_obj(np_aaatoken_t, return_token);
				break;
			}
		}
	}
	return (return_token);
}

sll_return(np_aaatoken_t) _np_get_receiver_token_all(char* subject)
{
	np_key_t* subject_key = NULL;
	np_dhkey_t search_key = dhkey_create_from_hostport(subject, "0");

	_LOCK_MODULE(np_keycache_t)
	{
		subject_key = _np_key_find_create(search_key);
		_create_token_ledger(subject_key, subject);
	}

//	log_msg(LOG_DEBUG, "available %hd interests %hd",
//			subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list) = NULL;
	sll_init(np_aaatoken_t, return_list);

	// should never happen
	if (NULL == subject_key) return (return_list);

	pll_iterator(np_aaatoken_ptr) tmp = NULL;

	LOCK_CACHE(subject_key->recv_property)
	{
		tmp = pll_first(subject_key->recv_tokens);
		while (NULL != tmp)
		{
			if (FALSE == token_is_valid(tmp->val))
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "ignoring invalid receiver msg token" );
			}
			else
			{
				log_msg(LOG_AAATOKEN | LOG_DEBUG,
						"found valid receiver token (%s)", tmp->val->issuer );
				np_ref_obj(np_aaatoken_t, tmp->val);

				// only pick key from a list if the subject msg_treshold is bigger than zero
				// and the sending threshold is bigger than zero as well
				// and we actually have a receiver node in the list
				sll_append(np_aaatoken_t, return_list, tmp->val);
			}
			pll_next(tmp);
			// tmp = pll_head(np_aaatoken_ptr, subject_key->recv_tokens);
		}
	}
	return (return_list);
}

void _np_aaatoken_add_signature(np_aaatoken_t* msg_token)
{
	log_msg(LOG_TRACE | LOG_AAATOKEN, ".start._np_aaatoken_add_signature");
	// fingerprinting and signing the token
	unsigned char hash[crypto_generichash_BYTES];
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, sizeof hash);
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->realm, strlen(msg_token->realm));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->issuer, strlen(msg_token->issuer));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->subject, strlen(msg_token->subject));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->audience, strlen(msg_token->audience));
	if (NULL != msg_token->uuid)
		crypto_generichash_update(&gh_state, (unsigned char*) msg_token->uuid, strlen(msg_token->uuid));
	crypto_generichash_update(&gh_state, (unsigned char*) msg_token->public_key, crypto_sign_PUBLICKEYBYTES);

	// TODO: hash 'not_before' and 'expiration' values as well ?
	crypto_generichash_final(&gh_state, hash, sizeof hash);
	char hash_hex[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, hash,
			crypto_generichash_BYTES);
	log_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s",
			hash_hex);

	// TODO: signature could be filled with padding zero's, remove them for efficiency
	char signature[crypto_sign_BYTES];
	// uint64_t signature_len;
	int16_t ret = crypto_sign_detached((unsigned char*) signature, NULL /* signature_len */,
			(const unsigned char*) hash, crypto_generichash_BYTES,
			msg_token->private_key);

	if (ret < 0)
	{
		log_msg(LOG_WARN,
				"checksum creation for token failed, using unsigned token");
	}
	else
	{
		// TODO: refactor name NP_HS_SIGNATURE to a common name NP_SIGNATURE
		tree_replace_str(msg_token->extensions, NP_HS_SIGNATURE,
				new_val_bin(signature, crypto_sign_BYTES));
	}
	log_msg(LOG_TRACE | LOG_AAATOKEN, ".end  ._np_aaatoken_add_signature");
}


