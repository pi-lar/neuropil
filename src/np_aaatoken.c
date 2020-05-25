//
// neuropil is copyright 2016-2020 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <math.h>

#include "event/ev.h"
#include "sodium.h"

#include "np_aaatoken.h"

#include "np_dhkey.h"
#include "util/np_event.h"

#include "dtime.h"
#include "np_log.h"
#include "np_legacy.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_key.h"
#include "np_keycache.h"
#include "np_message.h"
#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"
#include "np_threads.h"
#include "np_settings.h"
#include "np_util.h"
#include "np_constants.h"
#include "neuropil.h"
#include "np_serialization.h"

_NP_GENERATE_MEMORY_IMPLEMENTATION(np_aaatoken_t);

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_aaatoken_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

NP_PLL_GENERATE_IMPLEMENTATION(np_aaatoken_ptr);

void _np_aaatoken_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* token)
{
    log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: void _np_aaatoken_t_new(void* token){");
    np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;

    aaa_token->version = 0.90;

    // aaa_token->issuer;
    memset(aaa_token->realm,    0, 255);
    memset(aaa_token->issuer,   0,  65);
    memset(aaa_token->subject,  0, 255);
    memset(aaa_token->audience, 0, 255);

    aaa_token->private_key_is_set = false;
    aaa_token->crypto.ed25519_secret_key_is_set = false;
    aaa_token->crypto.ed25519_public_key_is_set = false;

    memset(aaa_token->crypto.derived_kx_public_key, 0, crypto_sign_PUBLICKEYBYTES*(sizeof(unsigned char)));
    memset(aaa_token->crypto.derived_kx_secret_key, 0, crypto_sign_SECRETKEYBYTES*(sizeof(unsigned char)));
    memset(aaa_token->crypto.ed25519_public_key, 0, crypto_sign_ed25519_PUBLICKEYBYTES*(sizeof(unsigned char)));
    memset(aaa_token->crypto.ed25519_secret_key, 0, crypto_sign_ed25519_SECRETKEYBYTES*(sizeof(unsigned char)));

    memset(aaa_token->signature, 0, crypto_sign_BYTES*(sizeof(unsigned char)));
    aaa_token->is_signature_verified = false;

    char* uuid = aaa_token->uuid;
    np_uuid_create("generic_aaatoken", 0, &uuid);

    aaa_token->issued_at = np_time_now();
    aaa_token->not_before = aaa_token->issued_at;

    int expire_sec =  ((int)randombytes_uniform(20)+10);

    aaa_token->expires_at = aaa_token->not_before + expire_sec;
    log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "aaatoken expires in %d sec", expire_sec);

    aaa_token->extensions = np_tree_create();
    aaa_token->state = AAA_UNKNOWN;

    aaa_token->type = np_aaatoken_type_undefined;
    aaa_token->scope = np_aaatoken_scope_undefined;
    aaa_token->issuer_token = aaa_token;
    
    log_debug_msg(LOG_DEBUG, "token %p / extensions %p", aaa_token, aaa_token->extensions);

}

void _np_aaatoken_t_del (NP_UNUSED np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* token)
{

    np_aaatoken_t* aaa_token = (np_aaatoken_t*) token;
    log_debug_msg(LOG_DEBUG, "token %p / extensions %p", aaa_token, aaa_token->extensions);

    
    // clean up extensions
    np_tree_free(aaa_token->extensions);
}

void _np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token, bool trace)
{
    log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token){");

    np_state_t* context = np_ctx_by_memory(token);
    // if(trace) _np_aaatoken_trace_info("encode", token);
    // included into np_token_handshake
    
    np_tree_replace_str( data, "np.t.type", np_treeval_new_ush(token->type));
    np_tree_replace_str( data, "np.t.u",    np_treeval_new_s(token->uuid));
    np_tree_replace_str( data, "np.t.r",    np_treeval_new_s(token->realm));
    np_tree_replace_str( data, "np.t.i",    np_treeval_new_s(token->issuer));
    np_tree_replace_str( data, "np.t.s",    np_treeval_new_s(token->subject));
    np_tree_replace_str( data, "np.t.a",    np_treeval_new_s(token->audience));
    np_tree_replace_str( data, "np.t.p",    np_treeval_new_bin(token->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES));
                                           
    np_tree_replace_str( data, "np.t.ex",   np_treeval_new_d(token->expires_at));
    np_tree_replace_str( data, "np.t.ia",   np_treeval_new_d(token->issued_at));
    np_tree_replace_str( data, "np.t.nb",   np_treeval_new_d(token->not_before));
    np_tree_replace_str( data, "np.t.si",   np_treeval_new_bin(token->signature, crypto_sign_BYTES));

    log_debug_msg(LOG_DEBUG, "token %p / extensions %p", token, token->extensions);

    np_tree_replace_str( data, "np.t.e",    np_treeval_new_tree(token->extensions));
    if(token->scope <= np_aaatoken_scope_private_available) {
        _np_aaatoken_update_extensions_signature(token);
    }
    np_tree_replace_str( data, "np.t.sie", np_treeval_new_bin(token->signature_extensions, crypto_sign_BYTES));

//#ifdef DEBUG
//	char pubkey[65];
//	sodium_bin2hex(pubkey, 65, token->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
//	pubkey[64] = '\0';
//	fprintf(stdout, "L: uuid: %s ## subj: %s ## pk: %s\n", token->uuid, token->subject, pubkey);
//#endif

}

void np_aaatoken_encode(np_tree_t* data, np_aaatoken_t* token)
{
    _np_aaatoken_encode(data, token, true);
}

/*
    @return: true if all medatory filds are present
*/
bool np_aaatoken_decode(np_tree_t* data, np_aaatoken_t* token)
{
    assert (NULL != data);
    assert (NULL != token);
    np_ctx_memory(token);

    bool ret = true;
    // get e2e encryption details of sending entity

    np_tree_elem_t* tmp;
    token->scope = np_aaatoken_scope_undefined;
    token->type = np_aaatoken_type_undefined;

    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.u")))
    {
        strncpy(token->uuid, np_treeval_to_str(tmp->val, NULL), NP_UUID_BYTES);
    }
    else { ret = false;/*Mandatory field*/ }

    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.type")))
    {
        token->type = tmp->val.value.ush;
    }
    else { ret = false;/*Mandatory field*/ }
    
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.r")))
    {
        strncpy(token->realm,  np_treeval_to_str(tmp->val, NULL), 255);
    }
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.i")))
    {
        strncpy(token->issuer,  np_treeval_to_str(tmp->val, NULL), 65);
    }
    else { ret = false;/*Mandatory field*/ }
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.s")))
    {
        strncpy(token->subject,  np_treeval_to_str(tmp->val, NULL), 255);
    }
    else { ret = false;/*Mandatory field*/ }
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.a")))
    {
        strncpy(token->audience,  np_treeval_to_str(tmp->val, NULL), 255);
    }
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.p")))
    {
        if (NULL == np_cryptofactory_by_public(context, &token->crypto, tmp->val.value.bin)) {
            log_msg(LOG_ERROR, "Could not decode crypto details from token");
            ret = false;/*Mandatory field*/
        }
    }
    else { ret = false; /* Mandatory field*/ }

    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.ex")))
    {
        token->expires_at = tmp->val.value.d;
    }
    else { ret = false;/*Mandatory field*/ }

    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.ia")))
    {
        token->issued_at = tmp->val.value.d;
    }
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.nb")))
    {
        token->not_before = tmp->val.value.d;
    }

    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.si")))
    {
        memcpy(token->signature, tmp->val.value.bin, crypto_sign_BYTES);
        token->is_signature_verified = false;
    }
    else { ret = false;/*Mandatory field*/ }

    // decode extensions
    if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.e")))
    {
        ASSERT(tmp->val.type == np_treeval_type_jrb_tree, 
            "token (%s) type is %"PRIu32" instead of np_treeval_type_jrb_tree(%"PRIu32")",
            token->uuid, tmp->val.type, np_treeval_type_jrb_tree
        );

        np_tree_clear( token->extensions);
        np_tree_copy( tmp->val.value.tree, token->extensions);


        if (ret && NULL != (tmp = np_tree_find_str(data, "np.t.sie")))
        {
            memcpy(token->signature_extensions, tmp->val.value.bin, fmin(tmp->val.size, crypto_sign_BYTES));
            token->is_signature_extensions_verified = false;
        }
        else { ret = false;/*Mandatory field if extensions provided*/ }
    }

    _np_aaatoken_update_scope(token);

    return ret;
}

void _np_aaatoken_update_scope(np_aaatoken_t* self) {

    assert (NULL != self);

    if(self->private_key_is_set){
        self->scope = np_aaatoken_scope_private;
    } else {
        self->scope = np_aaatoken_scope_public;
    }
}

np_dhkey_t np_aaatoken_get_fingerprint(np_aaatoken_t* self, bool include_extensions)
{
    assert (NULL != self);
    // np_ctx_memory(self);
    np_dhkey_t ret;

	// build a hash to find a place in the dhkey table, not for signing !
	unsigned char* hash_attributes = _np_aaatoken_get_hash(self);
	ASSERT(hash_attributes != NULL, "cannot sign NULL hash");

	unsigned char hash[crypto_generichash_BYTES] = { 0 };
	crypto_generichash_state gh_state;
	crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);
	crypto_generichash_update(&gh_state, hash_attributes, crypto_generichash_BYTES);
	crypto_generichash_update(&gh_state, self->signature, crypto_sign_BYTES);

	if (true == include_extensions) {
		unsigned char* hash = __np_aaatoken_get_extensions_hash(self);
		crypto_generichash_update(&gh_state, hash, crypto_generichash_BYTES);
		free(hash);
	}
	// TODO: generichash_final already produces the dhkey value, just memcpy it.
	crypto_generichash_final(&gh_state, hash, crypto_generichash_BYTES);

	char key[crypto_generichash_BYTES * 2 + 1];
	sodium_bin2hex(key, crypto_generichash_BYTES * 2 + 1, hash, crypto_generichash_BYTES);
	ret = np_dhkey_create_from_hash(key);

	free(hash_attributes);
    // }
    return ret;
}

bool _np_aaatoken_is_valid(np_aaatoken_t* token, enum np_aaatoken_type expected_type)
{
    log_trace_msg(LOG_TRACE | LOG_AAATOKEN, "start: bool _np_aaatoken_is_valid(np_aaatoken_t* token){");
    
    if (NULL == token) return false;

    np_state_t* context = np_ctx_by_memory(token);

    log_debug(LOG_AAATOKEN, "checking token (%s) validity for token of type %"PRIu32" and scope %"PRIu32, token->uuid, token->type, token->scope);


    if (FLAG_CMP(token->type, expected_type) == false)
    {
        log_warn(LOG_AAATOKEN, "token (%s) for subject \"%s\": is not from correct type (%"PRIu32" != (expected:=)%"PRIu32"). verification failed",
            token->uuid, token->subject, token->type, expected_type);
#ifdef DEBUG
        ASSERT(false, "token (%s) for subject \"%s\": is not from correct type (%"PRIu32" != (expected:=)%"PRIu32"). verification failed",
            token->uuid, token->subject, token->type, expected_type);
#endif // DEBUG

        token->state &= AAA_INVALID;
        log_trace_msg(LOG_AAATOKEN, ".end  .token_is_valid");
        return (false);
    }
    else 
    {
        log_debug(LOG_AAATOKEN, "token has expected type");
    }


    // check timestamp
    double now = np_time_now();
    if (now > (token->expires_at))
    {
        log_msg(LOG_WARN, "token (%s) for subject \"%s\": expired (%f = %f - %f). verification failed",
                token->uuid, token->subject, token->expires_at - now, now, token->expires_at);
        token->state &= AAA_INVALID;
        log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
        return (false);
    }
    else 
    {
        log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token has not expired");
    }

    if (token->scope > np_aaatoken_scope_private_available) 
    {
        if (token->is_signature_verified == false) {
            unsigned char* hash = _np_aaatoken_get_hash(token);

            // verify inserted signature first
            unsigned char* signature = token->signature;

            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to check signature checksum");
            int ret = crypto_sign_verify_detached((unsigned char*)signature, hash, crypto_generichash_BYTES, token->crypto.ed25519_public_key);

#ifdef DEBUG
            char signature_hex[crypto_sign_BYTES * 2 + 1] = { 0 };
            sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
                signature, crypto_sign_BYTES);
                
            char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = { 0 };
            sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
                token->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
            char kx_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = { 0 };
            sodium_bin2hex(kx_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
            		token->crypto.derived_kx_public_key, crypto_sign_PUBLICKEYBYTES);

            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG,
                "(token: %s) signature is%s valid: (pk: 0x%s) sig: 0x%s = %"PRId32,
                token->uuid, ret != 0? " not":"", pk_hex, signature_hex, ret);				
#endif
            free(hash);

            if (ret < 0)
            {
                log_msg(LOG_WARN, "token (%s) for subject \"%s\": checksum verification failed", token->uuid, token->subject);
                log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
                token->state &= AAA_INVALID;
                return (false);
            }
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) for subject \"%s\": checksum verification success", token->uuid, token->subject);
            token->is_signature_verified = true;
        }

        if (token->is_signature_extensions_verified == false) 
        {
            unsigned char* hash = __np_aaatoken_get_extensions_hash(token);

            // verify inserted signature first
            unsigned char* signature = token->signature_extensions;

            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to check extension signature checksum");
            int ret = crypto_sign_verify_detached((unsigned char*)signature, hash, crypto_generichash_BYTES, token->crypto.ed25519_public_key);

#ifdef DEBUG
            if (ret != 0)
            {
                char hash_hex[crypto_generichash_BYTES * 2 + 1] = { 0 };
                sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, 
                    hash, crypto_generichash_BYTES);

                char signature_hex[crypto_sign_BYTES * 2 + 1] = { 0 };
                sodium_bin2hex(signature_hex, crypto_sign_BYTES * 2 + 1,
                    signature, crypto_sign_BYTES);

                char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1] = { 0 };
                sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
                    token->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);

                log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "(token: %s) extension signature: is_valid (hash: 0x%s) (pk: 0x%s) 0x%s = %"PRId32, token->uuid, hash_hex, pk_hex, signature_hex, ret);
            }
#endif
            free(hash);
            if (ret < 0)
            {
                log_msg(LOG_WARN, "token (%s) for subject \"%s\": extension signature checksum verification failed", token->uuid, token->subject);
                log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
                token->state &= AAA_INVALID;
                
                return (false);
            }
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) for subject \"%s\": extension signature checksum verification success", token->uuid, token->subject);
            token->is_signature_extensions_verified = true;
        }
    }
    /*
        If we received a full token we may already got a handshake token,
        if so we need to validate the new tokens signature against the already received token sig
        and an successfully verifying the new token identity is the same as in the handshake token
    */
    if (FLAG_CMP(token->type, np_aaatoken_type_node))
    {   // check for already received handshake token
		np_dhkey_t handshake_token_dhkey = np_aaatoken_get_fingerprint(token, false);
        np_key_t* handshake_key = _np_keycache_find(context, handshake_token_dhkey);
        if (handshake_key != NULL)
        {
            np_aaatoken_t* existing_token = _np_key_get_token(handshake_key);
            if (existing_token != NULL && existing_token != token /* reference compare! */ &&
                FLAG_CMP(existing_token->type, np_aaatoken_type_handshake) /*&& _np_aaatoken_is_valid(handshake_token)*/)
            {   // FIXME: Change to signature check with other tokens pub key
                if (memcmp(existing_token->crypto.derived_kx_public_key, token->crypto.derived_kx_public_key, crypto_sign_PUBLICKEYBYTES *(sizeof(unsigned char))) != 0) 
                {
                    np_unref_obj(np_key_t, handshake_key, "_np_keycache_find");
                    log_msg(LOG_WARN, "Someone tried to impersonate a token (%s). verification failed", token->uuid);
                    return (false);
                }
            }
            np_unref_obj(np_key_t, handshake_key, "_np_keycache_find");
        }
    }

    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token checksum verification completed");

    // TODO: only if this is a message token
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "try to find max/msg threshold ");
    np_tree_elem_t* max_threshold = np_tree_find_str(token->extensions, "max_threshold");
    np_tree_elem_t* msg_threshold = np_tree_find_str(token->extensions, "msg_threshold");
    
    if ( max_threshold && msg_threshold)
    {
        log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "found max/msg threshold");
        uint8_t token_max_threshold = max_threshold->val.value.ush;
        uint8_t token_msg_threshold = msg_threshold->val.value.ush;

        if (0                   <= token_msg_threshold &&
            token_msg_threshold <= token_max_threshold)
        {
            log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token for subject \"%s\": %s can be used for %"PRIu8" msgs", token->subject, token->issuer, token_max_threshold-token_msg_threshold);
        }
        else
        {
            log_msg(LOG_WARN, "verification failed. token (%s) for subject \"%s\": %s was already used, 0<=%"PRIu8"<%"PRIu8, token->uuid, token->subject, token->issuer, token_msg_threshold, token_max_threshold);
            log_trace_msg(LOG_AAATOKEN | LOG_TRACE, ".end  .token_is_valid");
            token->state &= AAA_INVALID;
            return (false);
        }
    }
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "token (%s) validity for subject \"%s\": verification valid", token->uuid, token->subject);
    token->state |= AAA_VALID;
    return (true);
}

np_dhkey_t _np_aaatoken_get_issuer(np_aaatoken_t* self){
    np_dhkey_t ret =
        np_dhkey_create_from_hash(self->issuer);
    return ret;
}

unsigned char* _np_aaatoken_get_hash(np_aaatoken_t* self) {

    assert(self != NULL);// "cannot get token hash of NULL
    np_ctx_memory(self);
    unsigned char* ret = calloc(1, crypto_generichash_BYTES);
    crypto_generichash_state gh_state;
    crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

    //crypto_generichash_update(&gh_state, (unsigned char*)&self->type, sizeof(uint8_t));
    //log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting type      : %d", self->type);

    ASSERT(self->uuid != NULL, "cannot get token hash of uuid NULL");
    crypto_generichash_update(&gh_state, (unsigned char*)self->uuid, strnlen(self->uuid, NP_UUID_BYTES));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting uuid      : %s", self->uuid);

    crypto_generichash_update(&gh_state, (unsigned char*)self->realm, strnlen(self->realm, 255));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting realm     : %s", self->realm);

    crypto_generichash_update(&gh_state, (unsigned char*)self->issuer, strnlen(self->issuer, 65));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting issuer    : %s", self->issuer);

    crypto_generichash_update(&gh_state, (unsigned char*)self->subject, strnlen(self->subject, 255));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting subject   : %s", self->subject);

    crypto_generichash_update(&gh_state, (unsigned char*)self->audience, strnlen(self->audience, 255));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting audience  : %s", self->audience);

    crypto_generichash_update(&gh_state, (unsigned char*)self->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);

#ifdef DEBUG
    char pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
    sodium_bin2hex(pk_hex, crypto_sign_PUBLICKEYBYTES * 2 + 1,
        self->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting public_key: %s", pk_hex);
#else
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting public_key: <...>");
#endif

    // if(FLAG_CMP(self->type, np_aaatoken_type_handshake) == false) {
    // TODO: expires_at in handshake?
    crypto_generichash_update(&gh_state, (unsigned char*)&(self->expires_at), sizeof(double));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting expiration: %f", self->expires_at);
    crypto_generichash_update(&gh_state, (unsigned char*)&(self->issued_at), sizeof(double));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting issued_at : %f", self->issued_at);
    crypto_generichash_update(&gh_state, (unsigned char*)&(self->not_before), sizeof(double));
    log_debug_msg(LOG_AAATOKEN | LOG_DEBUG, "fingerprinting not_before: %f", self->not_before);
    // }
    crypto_generichash_final(&gh_state, ret, crypto_generichash_BYTES);

#ifdef DEBUG
    char hash_str[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_str, crypto_generichash_BYTES * 2 + 1, ret, crypto_generichash_BYTES);
    log_debug_msg(LOG_DEBUG| LOG_AAATOKEN, "token hash for %s is %s", self->uuid, hash_str);
#endif
    ASSERT(ret != NULL, "generated hash cannot be NULL");
    return ret;
}

int __np_aaatoken_generate_signature(np_state_t* context, unsigned char* hash, unsigned char* private_key, unsigned char* save_to) {

    // unsigned long long signature_len = 0;

#ifdef DEBUG
    char hash_hex[crypto_generichash_BYTES * 2 + 1];
    sodium_bin2hex(hash_hex, crypto_generichash_BYTES * 2 + 1, hash,
        crypto_generichash_BYTES);
    log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token hash key fingerprint: %s",
        hash_hex);
#endif

#ifdef DEBUG
    char sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];
    sodium_bin2hex(sk_hex, crypto_sign_SECRETKEYBYTES * 2 + 1, private_key, crypto_sign_SECRETKEYBYTES);
    log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "token signature private key: %s", sk_hex);
#endif

    int ret = crypto_sign_detached(save_to, NULL,
                (const unsigned char*)hash, crypto_generichash_BYTES, private_key);

    ASSERT(ret == 0,  "checksum creation for token failed, using unsigned token");
    return ret;
}


void np_aaatoken_set_partner_fp(np_aaatoken_t*self, np_dhkey_t partner_fp) {
    assert(self != NULL);
    // np_state_t* context = np_ctx_by_memory(self);

    np_tree_replace_str( self->extensions, "_np.partner_fp", np_treeval_new_dhkey(partner_fp));
}

np_dhkey_t np_aaatoken_get_partner_fp(np_aaatoken_t* self) {

    assert(self != NULL);    
    np_dhkey_t ret = { 0 };

    np_tree_elem_t* ele = np_tree_find_str(self->extensions, "_np.partner_fp");
    if (ele != NULL) {
        ret = ele->val.value.dhkey;
    }
    else {
        _np_str_dhkey(self->issuer, &ret);
    }

    return ret;
}

void _np_aaatoken_set_signature(np_aaatoken_t* self, np_aaatoken_t* signee) {

	assert(self != NULL);
    np_state_t* context = np_ctx_by_memory(self);

    ASSERT(self->crypto.ed25519_public_key_is_set == true, "cannot sign token without public key");
    
    if (signee != NULL) {
        ASSERT(signee != NULL, "Cannot sign extensions with empty signee");
        ASSERT(signee->private_key_is_set == true, "Cannot sign extensions without private key");
        ASSERT(signee->crypto.ed25519_secret_key_is_set == true, "Cannot sign extensions without private key");
    } else {
        ASSERT(self->scope <= np_aaatoken_scope_private_available, "Cannot sign extensions without a private key");
        ASSERT(self->issuer_token != NULL, "Cannot sign extensions without a private key");
    }

    int ret = 0;

    // create the hash of the core token data
    unsigned char* hash = _np_aaatoken_get_hash(self);

    if (signee == NULL) {
        // set the signature of the token
        ret = __np_aaatoken_generate_signature(context, hash, self->issuer_token->crypto.ed25519_secret_key, self->signature);
    
    } else {
        // add a field to the exension containing an additional signature
        char signee_token_fp[65];
        signee_token_fp [64] = '\0';
        np_dhkey_t my_token_fp = np_aaatoken_get_fingerprint(signee, false);
        _np_dhkey_str(&my_token_fp, signee_token_fp);

        assert( 0 == strncmp(signee_token_fp, self->issuer, 64) );

        unsigned char signer_pubsig[crypto_sign_PUBLICKEYBYTES+crypto_sign_BYTES];
        // copy public key
        memcpy(signer_pubsig, signee->crypto.ed25519_public_key, crypto_sign_PUBLICKEYBYTES);
        // add signature of signer to extensions
        ret = __np_aaatoken_generate_signature(context, self->signature, signee->crypto.ed25519_secret_key, signer_pubsig + crypto_sign_PUBLICKEYBYTES );
        // insert into extension table
        np_tree_replace_str(self->extensions, signee_token_fp, np_treeval_new_bin(signer_pubsig, 96));
    }

    free(hash);

#ifdef DEBUG
    char sign_hex[crypto_sign_BYTES * 2 + 1];
    sodium_bin2hex(sign_hex, crypto_sign_BYTES * 2 + 1, self->signature, crypto_sign_BYTES);
    log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "signature hash for %s is %s", self->uuid, sign_hex);
#endif

    ASSERT(ret == 0, "Error in token signature creation");
}

void _np_aaatoken_update_extensions_signature(np_aaatoken_t* self) {

    assert(self != NULL);
    ASSERT(self->scope <= np_aaatoken_scope_private_available, "Cannot sign extensions without a private key");
    ASSERT(self->issuer_token != NULL, "Cannot sign extensions without a private key");

    np_ctx_memory(self);

    unsigned char* hash = __np_aaatoken_get_extensions_hash(self);
    int ret = __np_aaatoken_generate_signature(context, hash, self->issuer_token->crypto.ed25519_secret_key, self->signature_extensions);

    ASSERT(ret == 0, "Error in extended token signature creation");

#ifdef DEBUG
    char sign_hex[crypto_sign_BYTES * 2 + 1];
    sodium_bin2hex(sign_hex, crypto_sign_BYTES * 2 + 1, self->signature_extensions, crypto_sign_BYTES);
    log_debug_msg(LOG_DEBUG | LOG_AAATOKEN, "extension signature hash for %s is %s", self->uuid, sign_hex);
#endif

    free(hash);
}

unsigned char* __np_aaatoken_get_extensions_hash(np_aaatoken_t* self) {
    assert(self != NULL);
    // np_state_t* context = np_ctx_by_memory(self);

    unsigned char* ret = calloc(1, crypto_generichash_BYTES);

    crypto_generichash_state gh_state;
    crypto_generichash_init(&gh_state, NULL, 0, crypto_generichash_BYTES);

    unsigned char* hash = np_tree_get_hash(self->extensions);
    ASSERT(hash != NULL, "cannot sign NULL hash");

    crypto_generichash_update(&gh_state, hash, crypto_generichash_BYTES);
    crypto_generichash_update(&gh_state, self->signature, crypto_sign_BYTES);

    crypto_generichash_final(&gh_state, ret, crypto_generichash_BYTES);

    free(hash);

    return ret;
}

void np_aaatoken_ref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason, const char* reason_desc)
{
    np_state_t* context = NULL;

    sll_iterator(np_aaatoken_ptr) iter = sll_first(sll_list);
    while (NULL != iter)
    {
        if (context == NULL && iter->val != NULL) context = np_ctx_by_memory(iter->val);
        np_ref_obj(np_aaatoken_t, (iter->val), reason, reason_desc);
        sll_next(iter);
    }
}
 
void np_aaatoken_unref_list(np_sll_t(np_aaatoken_ptr, sll_list), const char* reason)
{	
    np_state_t* context = NULL;

    sll_iterator(np_aaatoken_ptr) iter = sll_first(sll_list);
    while (NULL != iter)
    {
        if (context == NULL && iter->val!=NULL) context = np_ctx_by_memory(iter->val);
        np_unref_obj(np_aaatoken_t, (iter->val), reason);
        sll_next(iter);
    }
}


#ifdef DEBUG
void _np_aaatoken_trace_info(char* desc, np_aaatoken_t* self) {
    assert(self != NULL);
    np_ctx_memory(self);

    char* info_str = NULL;
    info_str = np_str_concatAndFree(info_str, "AAATokenTrace_%s", desc);

    np_tree_t* data = np_tree_create();
    _np_aaatoken_encode(data, self, false);
    np_tree_elem_t* tmp = NULL;
    bool free_key, free_value;
    char *key, *value;

    char tmp_c[65] = { 0 };
	np_dhkey_t tmp_d = np_aaatoken_get_fingerprint(self, false);
    _np_dhkey_str(&tmp_d, tmp_c);

    info_str = np_str_concatAndFree(info_str, " fingerprint: %s ; TREE: (",tmp_c);
    RB_FOREACH(tmp, np_tree_s, (data))
    {
        key = np_treeval_to_str(tmp->key, &free_key);
        value = np_treeval_to_str(tmp->val, &free_value);
        info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
        if (free_value) free(value);
        if (free_key) free(key);
    }	
    np_tree_free(data);
    info_str = np_str_concatAndFree(info_str, "): %s", self->uuid);

    log_msg(LOG_DEBUG, "%s", info_str);
    free(info_str);
}
#endif

struct np_token* np_aaatoken4user(struct np_token* dest, np_aaatoken_t* src) {

    assert(src != NULL);
    assert(dest!= NULL);
    np_ctx_memory(src);

    dest->expires_at = src->expires_at;
    dest->issued_at	 = src->issued_at;
    dest->not_before = src->not_before;

    strncpy(dest->uuid, src->uuid, NP_UUID_BYTES);

    // TODO: convert to np_id
    strncpy(dest->issuer, src->issuer, 65);
    strncpy(dest->realm, src->realm, 255);
    strncpy(dest->audience, src->audience, 255);
    strncpy(dest->subject, src->subject, 255);

    assert(crypto_sign_PUBLICKEYBYTES == NP_PUBLIC_KEY_BYTES);
    memcpy(dest->public_key, src->crypto.ed25519_public_key, NP_PUBLIC_KEY_BYTES);
    assert(crypto_sign_SECRETKEYBYTES == NP_SECRET_KEY_BYTES);
    memcpy(dest->secret_key, src->crypto.ed25519_secret_key, NP_SECRET_KEY_BYTES);

    memcpy(dest->signature, src->signature, NP_SIGNATURE_BYTES);

    // TODO: warning/error if NP_EXTENSION_BYTES < src->extensions->byte_size 
    cmp_ctx_t cmp;
    _np_obj_buffer_container_t buffer_container;
    buffer_container.buffer = dest->extensions;
    buffer_container.bufferCount = 0;
    buffer_container.bufferMaxCount = NP_EXTENSION_BYTES;
    buffer_container.obj = src;
    cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);
    np_tree_serialize(context, src->extensions, &cmp);
    dest->extension_length = src->extensions->byte_size;
    assert(dest->extension_length <= NP_EXTENSION_BYTES);

    memcpy(dest->ext_signature, src->signature_extensions, NP_SIGNATURE_BYTES);

    return dest;
}

np_aaatoken_t* np_user4aaatoken(np_aaatoken_t* dest, struct np_token* src) {
    assert(src != NULL);
    assert(dest != NULL);
    np_ctx_memory(dest);

    dest->expires_at = src->expires_at;
    dest->issued_at = src->issued_at;
    dest->not_before = src->not_before;

    strncpy(dest->uuid, src->uuid, NP_UUID_BYTES);

    //TODO: convert to np_id
    strncpy(dest->issuer, src->issuer, 65);
    strncpy(dest->realm, src->realm, 255);
    strncpy(dest->audience, src->audience, 255);
    strncpy(dest->subject, src->subject, 255);

    // copy public key
    memcpy(dest->crypto.ed25519_public_key, src->public_key, NP_PUBLIC_KEY_BYTES);
    dest->crypto.ed25519_public_key_is_set = true;

    memcpy(dest->signature, src->signature, NP_SIGNATURE_BYTES);
    
    cmp_ctx_t cmp;
    _np_obj_buffer_container_t buffer_container;
    buffer_container.buffer = src->extensions;
    buffer_container.bufferCount = 0;
    buffer_container.bufferMaxCount = NP_EXTENSION_BYTES;
    buffer_container.obj = dest;
    cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);
    np_tree_deserialize(context, dest->extensions, &cmp);

    memcpy(dest->signature_extensions, src->ext_signature, NP_SIGNATURE_BYTES);

    _np_aaatoken_update_scope(dest);

    return dest;
}
