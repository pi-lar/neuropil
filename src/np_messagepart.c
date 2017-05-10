/*
 * np_messagepart.c
 *
 *  Created on: 10.05.2017
 *      Author: sklampt
 */
#include "msgpack/cmp.h"
#include "sodium.h"

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_log.h"
#include "np_message.h"
#include "np_tree.h"
#include "np_util.h"

#include "np_messagepart.h"

_NP_MODULE_LOCK_IMPL(np_messagesgpart_cache_t);
NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp (const np_messagepart_ptr value1, const np_messagepart_ptr value2)
{
	uint16_t part_1 = value1->part; // tree_find_str(value1->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];
	uint16_t part_2 = value2->part; // tree_find_str(value2->instructions, NP_MSG_INST_PARTS)->val.value.a2_ui[1];

	log_msg(LOG_MESSAGE | LOG_DEBUG, "message part compare %d / %d / %d", part_1, part_2, part_1 - part_2);

	if (part_2 > part_1) return ( 1);
	if (part_1 > part_2) return (-1);
	return (0);
}


np_bool _np_messagepart_decrypt(np_tree_t* msg_part,
							unsigned char* enc_nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key)
{
	log_msg(LOG_TRACE, ".start.np_message_decrypt_part");
	np_tree_elem_t* enc_msg_part = tree_find_str(msg_part, NP_ENCRYPTED);
	if (NULL == enc_msg_part)
	{
		log_msg(LOG_ERROR, "couldn't find encrypted msg part");
		log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
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
		log_msg(LOG_ERROR, "couldn't decrypt msg part with session key %s", public_key);
		log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
		return (FALSE);
	}

	cmp_ctx_t cmp;
	cmp_init(&cmp, dec_part, buffer_reader, buffer_writer);
	deserialize_jrb_node_t(msg_part, &cmp);
	// TODO: check if the complete buffer was read (byte count match)

	tree_del_str(msg_part, NP_ENCRYPTED);

	log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
	return (TRUE);
}

//		if (-1 == _np_messagepart_encrypt(args->msg->header,
//										  nonce,
//										  target_token->session_key,
//										  NULL))
//		{
//			log_msg(LOG_WARN,
//				"incorrect encryption of message header (not sending to %s:%hd)",
//				target_node->dns_name, target_node->port);
//			return;
//		}
//
np_bool _np_messagepart_encrypt(np_tree_t* msg_part,
							unsigned char* nonce,
							unsigned char* public_key,
							NP_UNUSED unsigned char* secret_key)
{
	log_msg(LOG_TRACE, ".start.np_message_encrypt_part");
	cmp_ctx_t cmp;

    unsigned char msg_part_buffer[65536];
    void* msg_part_buf_ptr = msg_part_buffer;

    cmp_init(&cmp, msg_part_buf_ptr, buffer_reader, buffer_writer);
    serialize_jrb_node_t(msg_part, &cmp);

    uint64_t msg_part_len = cmp.buf-msg_part_buf_ptr;

	uint64_t enc_msg_part_len = msg_part_len + crypto_box_MACBYTES;

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
		log_msg(LOG_TRACE, ".end  .np_message_encrypt_part");
		return (FALSE);
	}

	_tree_replace_all_with_str(msg_part, NP_ENCRYPTED,
			new_val_bin(enc_msg_part, enc_msg_part_len));

	log_msg(LOG_TRACE, ".end  .np_message_encrypt_part");
	return (TRUE);
}


