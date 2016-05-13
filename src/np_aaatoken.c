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
	tree_insert_str(data, "_np.aaa.realm", new_val_s(token->realm));

	tree_insert_str(data, "_np.aaa.subject", new_val_s(token->subject));
	tree_insert_str(data, "_np.aaa.issuer", new_val_s(token->issuer));
	tree_insert_str(data, "_np.aaa.audience", new_val_s(token->audience));

	tree_insert_str(data, "_np.aaa.uuid", new_val_s(token->uuid));

	tree_insert_str(data, "_np.aaa.not_before", new_val_d(token->not_before));
	tree_insert_str(data, "_np.aaa.expiration", new_val_d(token->expiration));

	tree_insert_str(data, "_np.aaa.public_key", new_val_bin(token->public_key, crypto_sign_BYTES));
	tree_insert_str(data, "_np.aaa.extensions", new_val_tree(token->extensions));
}

void np_decode_aaatoken(np_tree_t* data, np_aaatoken_t* token)
{
	// get e2e encryption details of sending entity
	strncpy(token->realm, tree_find_str(data, "_np.aaa.realm")->val.value.s, 255);

	strncpy(token->subject, tree_find_str(data, "_np.aaa.subject")->val.value.s, 255);
	strncpy(token->issuer, tree_find_str(data, "_np.aaa.issuer")->val.value.s, 255);
	strncpy(token->audience, tree_find_str(data, "_np.aaa.audience")->val.value.s, 255);

	token->uuid = strndup(tree_find_str(data, "_np.aaa.uuid")->val.value.s, 255);

	token->not_before = tree_find_str(data, "_np.aaa.not_before")->val.value.d;
	token->expiration = tree_find_str(data, "_np.aaa.expiration")->val.value.d;

	memcpy(token->public_key, tree_find_str(data, "_np.aaa.public_key")->val.value.bin, crypto_sign_BYTES);

	// decode extensions
	np_tree_t* old_extensions = token->extensions;
	np_val_t new_extensions = copy_of_val(tree_find_str(data, "_np.aaa.extensions")->val);
	token->extensions = new_extensions.value.tree;
	np_free_tree(old_extensions);
}

np_bool token_is_valid(np_aaatoken_t* token)
{
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
	{
		crypto_generichash_update(&gh_state, (unsigned char*) token->uuid, strlen(token->uuid));
	}
	crypto_generichash_update(&gh_state, (unsigned char*) token->public_key, crypto_sign_BYTES);
	// TODO: hash 'not_before' and 'expiration' values as well ?
	crypto_generichash_final(&gh_state, hash, sizeof hash);


	// verify inserted signature first
	char* signature = NULL;
	unsigned long long signature_len = 0;
	if (NULL != tree_find_str(token->extensions, NP_HS_SIGNATURE))
	{
		signature = tree_find_str(token->extensions, NP_HS_SIGNATURE)->val.value.bin;
		signature_len = tree_find_str(token->extensions, NP_HS_SIGNATURE)->val.size;
		log_msg(LOG_AAATOKEN | LOG_DEBUG, "found signature with length %llu for checksum verification", signature_len);
	}

	if (NULL != signature)
	{
		int16_t ret = crypto_sign_verify_detached((unsigned char*) signature, hash, crypto_generichash_BYTES, token->public_key);
		if (ret < 0)
		{
			log_msg(LOG_WARN, "token checksum verification failed");
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			return FALSE;
		}
	}
	else
	{
		log_msg(LOG_WARN, "signature missing in token, continuing without checksum verification");
	}

	// check timestamp
	double now = ev_time();
	if (now > token->expiration)
	{
		log_msg(LOG_DEBUG, "token has expired: %f>%f", now, token->expiration);
		log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
		return FALSE;
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
			return TRUE;
		}
		else
		{
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "token was already used: 0<=%d<%d", token_msg_threshold, token_max_threshold);
			log_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
			return FALSE;
		}
	}

	return TRUE;
}

static int8_t _token_cmp (np_aaatoken_ptr first, np_aaatoken_ptr second)
{
	int8_t ret_check = 0;

	if (first == second) return 0;

	ret_check = strncmp(first->issuer, second->issuer, strlen(first->issuer));
	if (0 != ret_check )
	{
		return ret_check;
	}

	ret_check = strncmp(first->subject, second->subject, (strlen(first->subject)));
	if (0 != ret_check )
	{
		return ret_check;
	}

	ret_check = strncmp(first->realm, second->realm, strlen(first->realm));
	if (0 != ret_check )
	{
		return ret_check;
	}

	return 0;
}

void _create_token_ledger(np_key_t* subject_key, char* subject)
{
	np_msgproperty_t* prop = NULL;

	if (NULL == subject_key->recv_tokens)
		pll_init(np_aaatoken_ptr, subject_key->recv_tokens, _token_cmp);

	if (NULL == subject_key->send_tokens)
		pll_init(np_aaatoken_ptr, subject_key->send_tokens, _token_cmp);


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
				pll_remove(np_aaatoken_ptr, subject_key->send_tokens, tmp_token);
				np_unref_obj(np_aaatoken_t, tmp_token);
			}
		}
	}

	LOCK_CACHE(subject_key->send_property)
	{
		// update #2 subject specific data
		subject_key->send_property->mep_type |= (tree_find_str(token->extensions, "mep_type")->val.value.ush & SENDER_MASK);
		subject_key->send_property->ack_mode = tree_find_str(token->extensions, "ack_mode")->val.value.ush;

		subject_key->send_property->last_update = ev_time();

		uint16_t max_threshold = tree_find_str(token->extensions, "max_threshold")->val.value.ui;
		np_aaatoken_t *tmp_token = NULL;

		if (max_threshold > 0)
		{
			np_msg_mep_type sender_mep_type = subject_key->send_property->mep_type & SENDER_MASK;

			switch(sender_mep_type)
			{
			case SINGLE_SENDER:
				// update #1 key specific data
				np_ref_obj(np_aaatoken_t, token);
				tmp_token = pll_replace(np_aaatoken_ptr, subject_key->send_tokens, token);
				if (NULL == tmp_token)
				{
					pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, FALSE);
				}
				else
				{
					np_unref_obj(np_aaatoken_t, tmp_token);
				}
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single sender token for message hash %s", _key_as_str(subject_key) );
				break;

			case GROUP_SENDER:
				pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, TRUE);
				np_ref_obj(np_aaatoken_t, token);
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new group sender token for message hash %s", _key_as_str(subject_key) );
				break;

			case ANY_SENDER:
				// TODO check whether token has been really added
				pll_insert(np_aaatoken_ptr, subject_key->send_tokens, token, TRUE);
				np_ref_obj(np_aaatoken_t, token);
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new any sender token for message hash %s", _key_as_str(subject_key) );
				break;

			default:
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
	if (NULL == subject_key) return return_list;

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
				// np_unref_obj(np_aaatoken_t, tmp);
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
	return return_list;
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
	if (NULL == subject_key) return NULL;

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

			found_return_token = TRUE;
			np_ref_obj(np_aaatoken_t, return_token);
			log_msg(LOG_AAATOKEN | LOG_DEBUG, "found valid sender token (%s)", return_token->issuer);
		}
	}
	return return_token;
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
				pll_remove(np_aaatoken_ptr, subject_key->recv_tokens, tmp_token);
				np_unref_obj(np_aaatoken_t, tmp_token);
			}
		}
	}

	LOCK_CACHE(subject_key->recv_property)
	{
		// update #2 subject specific data
		subject_key->recv_property->mep_type |= (tree_find_str(token->extensions, "mep_type")->val.value.ush & RECEIVER_MASK);
		subject_key->recv_property->ack_mode = tree_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->recv_property->last_update = ev_time();

		uint16_t max_threshold = tree_find_str(token->extensions, "max_threshold")->val.value.ui;

		if (max_threshold > 0)
		{
			np_msg_mep_type receiver_mep_type = subject_key->recv_property->mep_type & RECEIVER_MASK;
			np_aaatoken_t* tmp_token = NULL;
			// only add if there are messages to send
			switch(receiver_mep_type)
			{
			case SINGLE_RECEIVER:
				// update #1 key specific data
				np_ref_obj(np_aaatoken_t, token);
				tmp_token = pll_replace(np_aaatoken_ptr, subject_key->recv_tokens, token);
				if (NULL == tmp_token)
				{
					pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, FALSE);
				}
				else
				{
					np_unref_obj(np_aaatoken_t, tmp_token);
				}
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new single receiver token %p for message hash %s", token, _key_as_str(subject_key) );
				break;

			case GROUP_RECEIVER:
				pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, TRUE);
				np_ref_obj(np_aaatoken_t, token);
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new group receiver token %p for message hash %s", token, _key_as_str(subject_key) );
				break;

			case ANY_RECEIVER:
				pll_insert(np_aaatoken_ptr, subject_key->recv_tokens, token, TRUE);
				np_ref_obj(np_aaatoken_t, token);
				log_msg(LOG_AAATOKEN | LOG_DEBUG, "added new any receiver token %p for message hash %s", token, _key_as_str(subject_key) );
				break;
			default:
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
	if (NULL == subject_key) return NULL;

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
			found_return_token = TRUE;
			np_ref_obj(np_aaatoken_t, return_token);
			break;
		}
	}
	return return_token;
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
	if (NULL == subject_key) return return_list;

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
	return return_list;
}


