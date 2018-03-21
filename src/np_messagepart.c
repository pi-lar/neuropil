//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#include "inttypes.h"

#include "msgpack/cmp.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_log.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_tree.h"
#include "np_util.h"
#include "np_serialization.h"
#include "np_messagepart.h"

NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2)
{
	uint16_t part_1 = value1->part; // np_tree_find_str(value1->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];
	uint16_t part_2 = value2->part; // np_tree_find_str(value2->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];

	log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "message part compare %d / %d / %d", part_1, part_2, part_1 - part_2);

	if (part_2 > part_1) return ( 1);
	if (part_1 > part_2) return (-1);
	return (0);
}


np_bool _np_messagepart_decrypt(np_tree_t* source,
							unsigned char* enc_nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key,
							np_tree_t* target)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: np_bool _np_messagepart_decrypt(np_tree_t* msg_part,							unsigned char* enc_nonce,							unsigned char* public_key,							NP_UNUSED unsigned char* secret_key){");
	np_tree_elem_t* enc_msg_part = np_tree_find_str(source, NP_ENCRYPTED);
	if (NULL == enc_msg_part)
	{
		log_msg(LOG_ERROR, "couldn't find encrypted msg part");
		return (FALSE);
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
		return (FALSE);
	}

	// Allow deserialisation as the encryption may 	
	cmp_ctx_t cmp;
	cmp_init(&cmp, dec_part, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	if(np_tree_deserialize(target, &cmp) == FALSE) {
		log_debug_msg(LOG_ERROR, "couldn't deserialize msg part after decryption");
		return FALSE;
	}
	// TODO: check if the complete buffer was read (byte count match)

	
	return (TRUE);
}

np_bool _np_messagepart_encrypt(np_tree_t* msg_part,
							unsigned char* nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: np_bool _np_messagepart_encrypt(np_tree_t* msg_part,							unsigned char* nonce,							unsigned char* public_key,							NP_UNUSED unsigned char* secret_key){");
	cmp_ctx_t cmp;

	unsigned char msg_part_buffer[65536];
	void* msg_part_buf_ptr = msg_part_buffer;

	cmp_init(&cmp, msg_part_buf_ptr, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
	np_tree_serialize(msg_part, &cmp);

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
		return (FALSE);
	}

	_np_tree_replace_all_with_str(msg_part, NP_ENCRYPTED,
			np_treeval_new_bin(enc_msg_part, enc_msg_part_len));
	return (TRUE);
}


void _np_messagepart_t_del(void* nw)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_del(void* nw){");
	np_messagepart_t* part = (np_messagepart_t*) nw;

	if(part->msg_part != NULL) np_memory_free(part->msg_part);
}
void _np_messagepart_t_new(void* nw)
{
	log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_messagepart_t_new(void* nw){");
	np_messagepart_t* part = (np_messagepart_t *) nw;

	part->msg_part  = NULL;
}

char* np_messagepart_printcache(np_bool asOneLine)
{
	char* ret = NULL;
	char* new_line = "\n";
	if(asOneLine == TRUE){
		new_line = "    ";
	}

	ret = np_str_concatAndFree(ret, "--- Messagepart cache (%"PRIu16") ---%s", np_state()->msg_part_cache->size, new_line);
	_LOCK_MODULE(np_message_part_cache_t)
	{
		np_tree_elem_t* tmp = NULL;
		

		RB_FOREACH(tmp, np_tree_s, np_state()->msg_part_cache)
		{
			np_message_t* msg = tmp->val.value.v;

			ret = np_str_concatAndFree(ret,
					"%s   received %2"PRIu32" of %2"PRIu16" expected parts. msg subject:%s%s",
					msg->uuid,
					pll_size(msg->msg_chunks),
					msg->no_of_chunks,
					_np_message_get_subject(msg),
					new_line
					);
		}		
	}
	ret = np_str_concatAndFree(ret, "--- Messagepart cache end ---%s", new_line);

	return (ret);
}
