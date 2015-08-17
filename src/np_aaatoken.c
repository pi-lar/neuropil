
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

	double now = dtime();
	// if (now < token->not_before) return 0;
	if (now > token->expiration) return FALSE;

	return TRUE;
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
	uint16_t msg_threshold = 0;
	uint16_t max_threshold = 0;

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
				msg_threshold = jrb_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui;
				subject_key->send_property->msg_threshold -= msg_threshold;

				log_msg(LOG_DEBUG, "deleting old / invalid sender msg tokens" );
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

		max_threshold = jrb_find_str(token->extensions, "max_threshold")->val.value.ui;
		if (max_threshold < subject_key->send_property->max_threshold)
			subject_key->send_property->max_threshold = max_threshold;

		subject_key->send_property->last_update = dtime();

		msg_threshold = jrb_find_str(token->extensions, "msg_threshold")->val.value.ui;

		if (msg_threshold > 0) {
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
			subject_key->send_property->msg_threshold += msg_threshold;
		}
	}
	log_msg(LOG_DEBUG, "added a new sender token (now %hd slots) for message hash %s",
			subject_key->send_property->msg_threshold, key_get_as_string(subject_key) );
}

sll_return(np_aaatoken_t) np_get_sender_token(np_state_t *state, char* subject) {

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

		// look up target stuctures or create it
		create_token_ledger(state, subject_key, subject);
	}

	log_msg(LOG_DEBUG, "available %hd interests %hd", subject_key->send_property->msg_threshold, subject_key->recv_property->msg_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list);
	sll_init(np_aaatoken_t, return_list);
	np_aaatoken_t* tmp = NULL;

	LOCK_CACHE(subject_key->send_property)
	{
		while (subject_key->send_property->msg_threshold > 0 &&
			   NULL != (tmp = sll_head(np_aaatoken_t, subject_key->send_tokens))) {

			if (!token_is_valid(tmp)) {
				log_msg(LOG_DEBUG, "ignoring invalid sender token for issuer %s", tmp->issuer);
				continue;
			}

			uint16_t token_threshold = jrb_find_str(tmp->extensions, "msg_threshold")->val.value.ui;
			log_msg(LOG_DEBUG,
					"found valid sender token (%hd slots / %s)",
					token_threshold, tmp->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			sll_append(np_aaatoken_t, return_list, tmp);
			np_bool add_again = FALSE;

			if (token_threshold > subject_key->send_property->msg_threshold) {
				subject_key->send_property->msg_threshold = 0;
				// not fully used token, re-add it to our token queue
				add_again = TRUE;

			} else {
				subject_key->send_property->msg_threshold -= token_threshold;
				np_unref_obj(np_aaatoken_t, tmp);
			}

			if (TRUE == add_again) sll_append(np_aaatoken_t, subject_key->send_tokens, tmp);
		}
	}
	return return_list;
}

// update internal structure and clean invalid tokens
void np_add_receiver_token(np_state_t *state, char* subject, np_aaatoken_t *token)
{
	uint16_t msg_threshold = 0;

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

			if (0 == token_is_valid(tmp_token) ||
				0 == strncmp(token->issuer, tmp_token->issuer, strlen(token->issuer)) )
			{
				msg_threshold = jrb_find_str(tmp_token->extensions, "msg_threshold")->val.value.ui;
				subject_key->recv_property->msg_threshold -= msg_threshold;

				log_msg(LOG_DEBUG, "deleting old / invalid receiver msg tokens" );
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

		uint16_t max_threshold = jrb_find_str(token->extensions, "max_threshold")->val.value.ui;
		if (max_threshold < subject_key->recv_property->max_threshold)
			subject_key->recv_property->max_threshold = max_threshold;

		subject_key->recv_property->last_update = dtime();

		msg_threshold = jrb_find_str(token->extensions, "msg_threshold")->val.value.ui;

		if (msg_threshold > 0) {
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
			subject_key->recv_property->msg_threshold += msg_threshold;
		}
	}
	log_msg(LOG_DEBUG, "added a new receiver token (now %hd slots) for message hash %s",
			subject_key->recv_property->msg_threshold, key_get_as_string(subject_key) );
}


sll_return(np_aaatoken_t) np_get_receiver_token(np_state_t *state, char* subject) {

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

	log_msg(LOG_DEBUG, "available %hd interests %hd", subject_key->send_property->msg_threshold, subject_key->recv_property->msg_threshold );
	// look up sources to see whether a sender already exists
	np_sll_t(np_aaatoken_t, return_list);
	sll_init(np_aaatoken_t, return_list);
	np_aaatoken_t* tmp = NULL;

	LOCK_CACHE(subject_key->recv_property) {
		while (subject_key->recv_property->msg_threshold > 0 &&
			   NULL != (tmp = sll_head(np_aaatoken_t, subject_key->recv_tokens))) {

			if (!token_is_valid(tmp)) {
				log_msg(LOG_DEBUG, "deleting invalid receiver msg tokens" );
				np_unref_obj(np_aaatoken_t, tmp);
				np_free_obj(np_aaatoken_t, tmp);
				continue;
			}

			uint16_t token_threshold = jrb_find_str(tmp->extensions, "msg_threshold")->val.value.ui;
			log_msg(LOG_DEBUG,
					"found valid receiver token (%hd slots / %s)",
					token_threshold, tmp->issuer );

			// only pick key from a list if the subject msg_treshold is bigger than zero
			// and the sending threshold is bigger than zero as well
			// and we actually have a receiver node in the list
			sll_append(np_aaatoken_t, return_list, tmp);
			np_bool add_again = FALSE;

			if (token_threshold > subject_key->recv_property->msg_threshold) {
				// token_threshold -= subject_key->recv_property->msg_threshold;
				subject_key->recv_property->msg_threshold = 0;
				// done later
				// jrb_find_str(tmp->extensions, "_np.msg_threshold")->val.value.ul -= token_threshold;
				add_again = TRUE;

			} else {
				subject_key->recv_property->msg_threshold -= token_threshold;
				np_unref_obj(np_aaatoken_t, tmp);
			}

			if (add_again == TRUE) sll_append(np_aaatoken_t, subject_key->recv_tokens, tmp);
		}
	}
	return return_list;
}


