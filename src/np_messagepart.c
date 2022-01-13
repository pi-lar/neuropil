//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "inttypes.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "msgpack/cmp.h"
#include "sodium.h"
#include "tree/tree.h"

#include "np_legacy.h"
#include "np_types.h"
#include "np_memory.h"

#include "neuropil_log.h"
#include "np_log.h"
#include "np_message.h"
#include "core/np_comp_msgproperty.h"
#include "util/np_tree.h"
#include "np_util.h"
#include "np_serialization.h"
#include "np_messagepart.h"

NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2)
{
	uint16_t part_1 = value1->part; // np_tree_find_str(value1->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];
	uint16_t part_2 = value2->part; // np_tree_find_str(value2->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];

	np_ctx_memory(value1);
	log_debug(LOG_MESSAGE | LOG_VERBOSE, "message part compare %d / %d / %d", part_1, part_2, part_1 - part_2);

	if (part_2 > part_1) return ( 1);
	if (part_1 > part_2) return (-1);
	return (0);
}


bool _np_messagepart_decrypt(np_state_t* context, 
							np_tree_t* source,
							unsigned char* enc_nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key,
							np_tree_t* target)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: bool _np_messagepart_decrypt(context, np_tree_t* msg_part,							unsigned char* enc_nonce,							unsigned char* public_key,							NP_UNUSED unsigned char* secret_key){");
	np_tree_elem_t* enc_msg_part = np_tree_find_str(source, NP_ENCRYPTED);
	if (NULL == enc_msg_part)
	{
		log_msg(LOG_ERROR, "couldn't find encrypted msg part");
		return (false);
	}

	unsigned char dec_part[enc_msg_part->val.size - crypto_box_MACBYTES];
	int16_t ret = crypto_secretbox_open_easy(
			dec_part,
			enc_msg_part->val.value.bin,
			enc_msg_part->val.size,
			enc_nonce,
			public_key);
//	int16_t ret = crypto_box_open_easy(
//			dec_part,
//			enc_msg_part->val.value.bin,
//			enc_msg_part->val.size,
//			enc_nonce,
//			public_key,
//			secret_key);
//	int16_t ret = crypto_box_open_easy_afternm(
//			dec_part,
//			enc_msg_part->val.value.bin,
//			enc_msg_part->val.size,
//			enc_nonce,
//			public_key);
	if (ret < 0)
	{
#ifdef DEBUG
		char public_key_hex[crypto_secretbox_KEYBYTES*2+1];
		sodium_bin2hex(public_key_hex, crypto_secretbox_KEYBYTES*2+1, public_key, crypto_secretbox_KEYBYTES);
		log_debug_msg(LOG_DEBUG, "couldn't decrypt msg part with session key %s", public_key_hex);
#endif

		log_debug_msg(LOG_ERROR, "couldn't decrypt msg part with session key");
		return (false);
	}

	// Allow deserialisation as the encryption may
	cmp_ctx_t cmp = {0};
	cmp_init(&cmp, dec_part, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	if(np_tree_deserialize( context, target, &cmp) == false) {
		log_debug_msg(LOG_ERROR, "couldn't deserialize msg part after decryption");
		return false;
	}
	// TODO: check if the complete buffer was read (byte count match)

	return (true);
}

bool _np_messagepart_encrypt(np_state_t* context,
							np_tree_t* msg_part,
							unsigned char* nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: bool _np_messagepart_encrypt(context, np_tree_t* msg_part,							unsigned char* nonce,							unsigned char* public_key,							NP_UNUSED unsigned char* secret_key){");
	cmp_ctx_t cmp = {0};

	unsigned char msg_part_buffer[msg_part->byte_size*2];
	void* msg_part_buf_ptr = msg_part_buffer;

	cmp_init(&cmp, msg_part_buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	np_tree_serialize(context, msg_part, &cmp);

	uint32_t msg_part_len = cmp.buf-msg_part_buf_ptr;

	uint32_t enc_msg_part_len = msg_part_len + crypto_box_MACBYTES;

	unsigned char enc_msg_part[enc_msg_part_len];
	int16_t ret = crypto_secretbox_easy(enc_msg_part,
										msg_part_buf_ptr,
										msg_part_len,
										nonce,
										public_key);
//	int16_t ret = crypto_box_easy(enc_msg_part,
//							  msg_part_buf_ptr,
//							  msg_part_len,
//							  nonce,
//							  public_key,
//							  secret_key);
//	int16_t ret = crypto_box_easy_afternm(enc_msg_part,
//								msg_part_buf_ptr,
//								msg_part_len,
//								nonce,
//								public_key);
	if (ret < 0)
	{
		return (false);
	}

	_np_tree_replace_all_with_str(msg_part, NP_ENCRYPTED,
			np_treeval_new_bin(enc_msg_part, enc_msg_part_len));
	return (true);
}


void _np_messagepart_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* nw)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_del(void* nw){");
	np_messagepart_t* part = (np_messagepart_t*) nw;

	if(part->msg_part != NULL) np_memory_free(context, part->msg_part);
}

void _np_messagepart_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED  size_t size, void* nw)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_new(void* nw){");
	np_messagepart_t* part = (np_messagepart_t *) nw;

	memset(part->uuid, 0, NP_UUID_BYTES);
	part->msg_part  = NULL;
}

char* np_messagepart_printcache(np_state_t* context, bool asOneLine)
{
	char* ret = NULL;
	char* new_line = "\n";
	if(asOneLine == true){
		new_line = "    ";
	}

	ret = np_str_concatAndFree(ret, "--- Messagepart cache (%"PRIu16") ---%s", context->msg_part_cache->size, new_line);
	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_tree_elem_t* tmp = NULL;

		RB_FOREACH(tmp, np_tree_s, context->msg_part_cache)
		{

			np_message_t* msg = tmp->val.value.v;
			char tmp_msg_subject[65];
			// TODO: tmp_msg_subject (this is an ugly cast from dhkey* to char*)
			sodium_bin2hex(tmp_msg_subject, 65, _np_message_get_subject(msg), NP_FINGERPRINT_BYTES);

			ret = np_str_concatAndFree(ret,
					"%s   received %2"PRIu32" of %2"PRIu16" expected parts. msg subject: %s%s",
					msg->uuid,
					pll_size(msg->msg_chunks),
					msg->no_of_chunks,
					tmp_msg_subject,
					new_line
					);
		}		
	}
	ret = np_str_concatAndFree(ret, "--- Messagepart cache end ---%s", new_line);

	return (ret);
}


void _np_messagepart_trace_info(char* desc, np_messagepart_t * msg_in) {

    np_ctx_memory(msg_in);
    char * info_str = NULL;
    info_str = np_str_concatAndFree(info_str, "MessagePartTrace_%s", desc);

#ifdef DEBUG
    bool free_key, free_value;
    char *key, *value;
    info_str = np_str_concatAndFree(info_str, " Header (");
    np_tree_elem_t * tmp;
    if(msg_in->header != NULL){
        RB_FOREACH(tmp, np_tree_s, (msg_in->header))
        {
            key = np_treeval_to_str(tmp->key, &free_key);
            value = np_treeval_to_str(tmp->val, &free_value);
            info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
            if (free_value) free(value);
            if (free_key) free(key);
        }
    }
    info_str = np_str_concatAndFree(info_str, ") Instructions (");
    if (msg_in->instructions != NULL) {
        RB_FOREACH(tmp, np_tree_s, (msg_in->instructions))
        {
            key = np_treeval_to_str(tmp->key, &free_key);
            value = np_treeval_to_str(tmp->val, &free_value);
            info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
            if (free_value) free(value);
            if (free_key) free(key);
        }
    }
    info_str = np_str_concatAndFree(info_str, ")");
#else
    info_str = np_str_concatAndFree(info_str, ": %s / %"PRIu16, msg_in->uuid, msg_in->part);
#endif

    log_debug(LOG_MESSAGE, info_str);
    free(info_str);
}
