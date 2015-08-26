
#include <assert.h>
#include <errno.h>

#include "np_aaatoken.h"

#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_message.h"
#include "np_threads.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);

void np_aaatoken_t_new(void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

	aaa_token->realm[0]      = '\0';
	aaa_token->subject[0]    = '\0';
	aaa_token->issuer[0]     = '\0';
	aaa_token->public_key[0] = '\0';

	aaa_token->issued_at = dtime();
    // set expiration to one day and recreate each day by default
    // TODO: make it configurable or use random timeframe
    struct timeval e_exp = dtotv(aaa_token->issued_at);
    e_exp.tv_sec += 86400;
    aaa_token->expiration = tvtod(e_exp);
    uuid_generate(aaa_token->uuid);
    aaa_token->extensions = make_jtree();
	aaa_token->valid = 0;
}

void np_aaatoken_t_del (void* token)
{
	np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
	// clean up extensions
	if (NULL != aaa_token->extensions) {
		np_free_tree(aaa_token->extensions);
	    aaa_token->extensions = NULL;
	}
}

void np_encode_aaatoken(np_jtree_t* data, np_aaatoken_t* token) {
	// add e2e encryption details for sender
	jrb_insert_str(data, "_np.aaa.realm", new_jval_s(token->realm));
	jrb_insert_str(data, "_np.aaa.subject", new_jval_s(token->subject));
	jrb_insert_str(data, "_np.aaa.issuer", new_jval_s(token->issuer));
	jrb_insert_str(data, "_np.aaa.not_before", new_jval_d(token->not_before));
	jrb_insert_str(data, "_np.aaa.expiration", new_jval_d(token->expiration));

	jrb_insert_str(data, "_np.aaa.public_key", new_jval_bin(token->public_key, crypto_scalarmult_curve25519_BYTES));

	np_jtree_t* subtree = make_jtree();
	// encode extensions by copying all of them
	np_jtree_elem_t* tmp = NULL;
	RB_FOREACH(tmp, np_jtree, token->extensions)
	{
		if (tmp->key.type == char_ptr_type)      jrb_insert_str(subtree, tmp->key.value.s, tmp->val);
		if (tmp->key.type == int_type)           jrb_insert_int(subtree, tmp->key.value.i, tmp->val);
		if (tmp->key.type == double_type)        jrb_insert_dbl(subtree, tmp->key.value.d, tmp->val);
		if (tmp->key.type == unsigned_long_type) jrb_insert_ulong(subtree, tmp->key.value.ul, tmp->val);

	}
	jrb_insert_str(data, "_np.aaa.extensions", new_jval_tree(subtree));
}

void np_decode_aaatoken(np_jtree_t* data, np_aaatoken_t* token) {

	// get e2e encryption details of sending entity
	strncpy(token->realm, jrb_find_str(data, "_np.aaa.realm")->val.value.s, 255);
	strncpy(token->subject, jrb_find_str(data, "_np.aaa.subject")->val.value.s, 255);
	strncpy(token->issuer, jrb_find_str(data, "_np.aaa.issuer")->val.value.s, 255);
	token->not_before = jrb_find_str(data, "_np.aaa.not_before")->val.value.d;
	token->expiration = jrb_find_str(data, "_np.aaa.expiration")->val.value.d;

	memcpy(token->public_key, jrb_find_str(data, "_np.aaa.public_key")->val.value.bin, crypto_scalarmult_curve25519_BYTES);

	// decode extensions
	np_free_tree(token->extensions);
	token->extensions = jrb_find_str(data, "_np.aaa.extensions")->val.value.tree;
}

np_bool token_is_valid(np_aaatoken_t* token) {

	uint16_t token_max_threshold = jrb_find_str(token->extensions, "max_threshold")->val.value.ui;
	uint16_t token_msg_threshold = jrb_find_str(token->extensions, "msg_threshold")->val.value.ui;
	double now = dtime();

	log_msg(LOG_DEBUG, "token values (max %hd / cur %hd / %f) now %f",
			token_max_threshold, token_msg_threshold, token->expiration, now);

	// TODO: move this to boolean math and just add(&) TRUE/FALSE values
	// if (now < token->not_before) return 0;
	if (now > token->expiration) return FALSE;

	if (token_max_threshold <= token_msg_threshold) return FALSE;

	if (token_msg_threshold >= 0) return TRUE;
	else                          return FALSE;
}

void create_token_ledger(np_state_t* state, np_key_t* subject_key, char* subject) {

	np_msgproperty_t* prop = NULL;

	if (NULL == subject_key->recv_tokens)
		sll_init(np_aaatoken_t, subject_key->recv_tokens);
	if (NULL == subject_key->send_tokens)
		sll_init(np_aaatoken_t, subject_key->send_tokens);

	prop = np_message_get_handler(state, OUTBOUND, subject);
	if (NULL == subject_key->send_property && NULL != prop) {
		subject_key->send_property = prop;
		np_ref_obj(np_msgproperty_t, subject_key->send_property);
	}
	if (NULL == subject_key->send_property)
		np_new_obj(np_msgproperty_t, subject_key->send_property);

	prop = np_message_get_handler(state, INBOUND, subject);
	if (NULL == subject_key->send_property && NULL != prop) {
		subject_key->recv_property = prop;
		np_ref_obj(np_msgproperty_t, subject_key->recv_property);
	}
	if (NULL == subject_key->recv_property)
		np_new_obj(np_msgproperty_t, subject_key->recv_property);
}


// update internal structure and return a interest if a matching pair has been found
void np_add_sender_token(np_state_t *state, char* subject, np_aaatoken_t *token)
{
	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);

	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }

		create_token_ledger(state, subject_key, subject);
	}

	log_msg(LOG_DEBUG, "update in global sender msg token structures ..." );

	LOCK_CACHE(subject_key->send_property) {

		sll_iterator(np_aaatoken_t) iter = sll_first(subject_key->send_tokens);
		while (NULL != iter) {

			np_aaatoken_t* tmp_token = iter->val;

			if (FALSE == token_is_valid(tmp_token) ||
				0 == strncmp(token->issuer, tmp_token->issuer, strlen(token->issuer)) )
			{
//				uint16_t max_threshold = jrb_find_str(tmp_token->extensions, "max_threshold")->val.value.ui;
//				uint16_t msg_threshold = jrb_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui;
//				subject_key->send_property->max_threshold -= max_threshold;
//				subject_key->send_property->msg_threshold -= msg_threshold;

				log_msg(LOG_DEBUG, "deleting old / invalid sender msg tokens");
				np_unref_obj(np_aaatoken_t, tmp_token);
				np_free_obj(np_aaatoken_t, tmp_token);

				sll_iterator(np_aaatoken_t) tbr = iter;
				iter = sll_next(iter);
				sll_delete(np_aaatoken_t, subject_key->send_tokens, tbr);

			} else {
				iter = sll_next(iter);
			}
		}
	}

	LOCK_CACHE(subject_key->send_property) {
		// update #2 subject specific data
		subject_key->send_property->mep_type = jrb_find_str(token->extensions, "mep_type")->val.value.ush;
		subject_key->send_property->ack_mode = jrb_find_str(token->extensions, "ack_mode")->val.value.ush;

		subject_key->send_property->last_update = dtime();

		uint16_t max_threshold = jrb_find_str(token->extensions, "max_threshold")->val.value.ui;

		if (max_threshold > 0) {
			// only add if there are messages to send
			switch(subject_key->send_property->mep_type) {
			case ONE_WAY:
				// update #1 key specific data
				sll_append(np_aaatoken_t, subject_key->send_tokens, token);
				np_ref_obj(np_aaatoken_t, token);
				break;
			default:
				break;
			}
			// subject_key->send_property->msg_threshold += msg_threshold;
		}
	}
	log_msg(LOG_DEBUG, "handled new sender token for message hash %s", key_get_as_string(subject_key) );
}

/** np_get_sender_token
 ** retrieve a list of valid sender tokens from the cache
 ** TODO extend this function with a key and an amount of messages
 ** TODO use a different function for mitm and leaf nodes ?
 **/
sll_return(np_aaatoken_t) np_get_sender_token_all(np_state_t *state, char* subject) {

	np_key_t* subject_key;

	np_key_t* search_key = key_create_from_hostport(subject, 0);
	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }
		// look up target structures or create them
		create_token_ledger(state, subject_key, subject);
	}

	// log_msg(LOG_DEBUG, "available %hd interests %hd", subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list);
	sll_init(np_aaatoken_t, return_list);
	np_aaatoken_t* tmp = NULL;

	LOCK_CACHE(subject_key->send_property)
	{
		while (NULL != (tmp = sll_head(np_aaatoken_t, subject_key->send_tokens))) {

			if (FALSE == token_is_valid(tmp)) {
				log_msg(LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->issuer);
				continue;
			}

			log_msg(LOG_DEBUG, "found valid sender token (%s)", tmp->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			sll_append(np_aaatoken_t, return_list, tmp);
			// subject_key->send_property->msg_threshold -= token_threshold;
			// TODO: return a copy of the token or use reference counting
		}
	}
	return return_list;
}

np_aaatoken_t* np_get_sender_token(np_state_t *state, char* subject, char* sender) {

	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);

	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }

		// look up target structures or create them
		create_token_ledger(state, subject_key, subject);
	}

//	log_msg(LOG_DEBUG, "available %hd interests %hd",
//						subject_key->send_property->max_threshold,
//						subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;
	np_bool found_return_token = FALSE;

	LOCK_CACHE(subject_key->send_property)
	{
		// if (0 < subject_key->send_property->msg_threshold) {

			sll_iterator(np_aaatoken_t) iter = sll_first(subject_key->send_tokens);
			while (NULL != iter &&
				   FALSE == found_return_token)
			{
				return_token = iter->val;
				if (FALSE == token_is_valid(return_token)) {
					// TODO delete invalid tokens, this is a different behaviour from node to node
					log_msg(LOG_DEBUG, "ignoring invalid sender token for issuer %s", return_token->issuer);
					iter = sll_next(iter);
					return_token = NULL;
					continue;
				}

				// unsigned int token_threshold = 0;
				// token_threshold = jrb_find_str(return_token->extensions, "msg_threshold")->val.value.ui;

				// only pick key from a list if the subject msg_treshold is bigger than zero
				// and we actually have the correct sender node in the list
				if (0 != strncmp(return_token->issuer, sender, 64))
				{
					log_msg(LOG_DEBUG, "ignoring sender token for issuer %s / send_hk: %s",
							return_token->issuer, sender);
					iter = sll_next(iter);
					return_token = NULL;
					continue;
				}

				jrb_find_str(return_token->extensions, "msg_threshold")->val.value.ui--;
				// subject_key->send_property->msg_threshold++;

				found_return_token = TRUE;
				log_msg(LOG_DEBUG, "found valid sender token (%s)", return_token->issuer );
				np_ref_obj(np_aaatoken_t, return_token);
			}
		// }
	}
	return return_token;
}

// update internal structure and clean invalid tokens
void np_add_receiver_token(np_state_t *state, char* subject, np_aaatoken_t *token)
{
	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);

	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }

		create_token_ledger(state, subject_key, subject);
	}

	log_msg(LOG_DEBUG, "update on global receiving msg token structures ... %p", subject_key->recv_property);

	LOCK_CACHE(subject_key->recv_property) {

		sll_iterator(np_aaatoken_t) iter = sll_first(subject_key->recv_tokens);

		while (NULL != iter) {
			np_aaatoken_t* tmp_token = iter->val;

			if (FALSE == token_is_valid(tmp_token) ||
				0 == strncmp(token->issuer, tmp_token->issuer, strlen(token->issuer)) )
			{
//				uint16_t max_threshold = jrb_find_str(tmp_token->extensions, "max_threshold")->val.value.ui;
//				uint16_t msg_threshold = jrb_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui;
//				subject_key->recv_property->max_threshold -= max_threshold;
//				subject_key->recv_property->msg_threshold -= msg_threshold;

				log_msg(LOG_DEBUG, "deleting old / invalid receiver msg tokens");
				np_unref_obj(np_aaatoken_t, tmp_token);
				np_free_obj(np_aaatoken_t, tmp_token);

				sll_iterator(np_aaatoken_t) tbr = iter;
				iter = sll_next(iter);
				sll_delete(np_aaatoken_t, subject_key->recv_tokens, tbr);

			} else {
				iter = sll_next(iter);
			}
		}
	}

	LOCK_CACHE(subject_key->recv_property) {
		// update #2 subject specific data
		subject_key->recv_property->mep_type = jrb_find_str(token->extensions, "mep_type")->val.value.ush;
		subject_key->recv_property->ack_mode = jrb_find_str(token->extensions, "ack_mode")->val.value.ush;
		subject_key->recv_property->last_update = dtime();

		uint16_t max_threshold = jrb_find_str(token->extensions, "max_threshold")->val.value.ui;
		// subject_key->recv_property->max_threshold += max_threshold;

		if (max_threshold > 0) {
			// only add if there are messages to send
			switch(subject_key->recv_property->mep_type) {
			case ONE_WAY:
				// update #1 key specific data
				sll_append(np_aaatoken_t, subject_key->recv_tokens, token);
				np_ref_obj(np_aaatoken_t, token);
				break;
			default:
				break;
			}
			// subject_key->recv_property->msg_threshold += msg_threshold;
		}
	}
	log_msg(LOG_DEBUG, "handled new receiver token for message hash %s",
			key_get_as_string(subject_key) );
}

np_aaatoken_t* np_get_receiver_token(np_state_t *state, char* subject)
{
	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);

	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }

		create_token_ledger(state, subject_key, subject);
	}

//	log_msg(LOG_DEBUG, "available %hd interests %hd",
//			subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_aaatoken_t* return_token = NULL;

	LOCK_CACHE(subject_key->recv_property) {

		sll_iterator(np_aaatoken_t) iter = sll_first(subject_key->recv_tokens);

		while (NULL != iter)
		{
			return_token = iter->val;
			if (FALSE == token_is_valid(return_token))
			{
				log_msg(LOG_DEBUG, "ignoring invalid receiver msg tokens" );
				iter = sll_next(iter);
				return_token = NULL;
				continue;
			}

			log_msg(LOG_DEBUG,
					"found valid receiver token (%s)", return_token->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			// sll_append(np_aaatoken_t, return_list, tmp);
			jrb_find_str(return_token->extensions, "msg_threshold")->val.value.ui++;
			subject_key->recv_property->msg_threshold++;

			np_ref_obj(np_aaatoken_t, return_token);
			break;
		}
	}
	return return_token;
}

sll_return(np_aaatoken_t) np_get_receiver_token_all(np_state_t *state, char* subject) {

	np_key_t* subject_key;
	np_key_t* search_key = key_create_from_hostport(subject, 0);

	LOCK_CACHE(state) {
		if (NULL == (subject_key = SPLAY_FIND(spt_key, &state->key_cache, search_key)) ) {
			SPLAY_INSERT(spt_key, &state->key_cache, search_key);
			subject_key = search_key;
			np_ref_obj(np_key_t, subject_key);
	    } else {
	    	np_free_obj(np_key_t, search_key);
	    }

		create_token_ledger(state, subject_key, subject);
	}

//	log_msg(LOG_DEBUG, "available %hd interests %hd",
//			subject_key->send_property->max_threshold, subject_key->recv_property->max_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list);
	sll_init(np_aaatoken_t, return_list);
	np_aaatoken_t* tmp = NULL;

	LOCK_CACHE(subject_key->recv_property) {
		while (NULL != (tmp = sll_head(np_aaatoken_t, subject_key->recv_tokens))) {

			if (FALSE == token_is_valid(tmp)) {
				log_msg(LOG_DEBUG, "deleting invalid receiver msg tokens" );
				np_unref_obj(np_aaatoken_t, tmp);
				np_free_obj(np_aaatoken_t, tmp);
				continue;
			}

			log_msg(LOG_DEBUG,
					"found valid receiver token (%s)", tmp->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			sll_append(np_aaatoken_t, return_list, tmp);
			// np_bool add_again = FALSE;

//			if (token_threshold > subject_key->recv_property->msg_threshold) {
//				// token_threshold -= subject_key->recv_property->msg_threshold;
//				subject_key->recv_property->msg_threshold = 0;
//				// done later
//				// jrb_find_str(tmp->extensions, "_np.msg_threshold")->val.value.ul -= token_threshold;
//				add_again = TRUE;
//			} else {
			// subject_key->recv_property->msg_threshold -= token_threshold;
			// np_unref_obj(np_aaatoken_t, tmp);
//			}

// 			if (add_again == TRUE) sll_append(np_aaatoken_t, subject_key->recv_tokens, tmp);
		}
	}
	return return_list;
}


