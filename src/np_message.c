/**
 *  np_message.c
 *  description:
 **/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>

#include "sodium.h"

#include "np_message.h"

#include "cmp.h"
#include "jval.h"
#include "dtime.h"
#include "log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_jtree.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_util.h"
#include "np_threads.h"


// default message type enumeration
enum {
	NEUROPIL_PING_REQUEST = 1,
	NEUROPIL_PING_REPLY,

	NEUROPIL_JOIN = 10,
	NEUROPIL_JOIN_ACK,
	NEUROPIL_JOIN_NACK,

	NEUROPIL_AVOID = 20,
	NEUROPIL_DIVORCE,

	NEUROPIL_UPDATE = 30,
	NEUROPIL_PIGGY,

	NEUROPIL_MSG_INTEREST = 50,
	NEUROPIL_MSG_AVAILABLE,

	NEUROPIL_REST_OPERATIONS = 100,
	NEUROPIL_POST,   /*create*/
	NEUROPIL_GET,    /*read*/
	NEUROPIL_PUT,    /*update*/
	NEUROPIL_DELETE, /*delete*/
	NEUROPIL_QUERY,

	NEUROPIL_INTERN_MAX = 1024,
	NEUROPIL_DATA = 1025,

} message_enumeration;


#define NR_OF_ELEMS(x)  (sizeof(x) / sizeof(x[0]))

np_msgproperty_t np_internal_messages[] =
{
	{ .msg_subject=ROUTE_LOOKUP, .msg_mode=TRANSFORM, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=np_route_lookup }, // default input handling func should be "route_get" ?

	{ .msg_subject=DEFAULT, .msg_mode=INBOUND, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_in_received },
	// TODO: add garbage collection output
	{ .msg_subject=DEFAULT, .msg_mode=OUTBOUND, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_send },

	{ .msg_subject=NP_MSG_HANDSHAKE, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_in_handshake },
	{ .msg_subject=NP_MSG_HANDSHAKE, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_handshake },

	// we don't need to ack the ack the ack the ack ...
	{ .msg_subject=NP_MSG_ACK, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=NULL }, // incoming ack handled in network layer, not required
	{ .msg_subject=NP_MSG_ACK, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=hnd_msg_out_ack },

	// ping is send directly to the destination host, no ack required
	{ .msg_subject=NP_MSG_PING_REQUEST, .msg_mode=INBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_in_ping },
	{ .msg_subject=NP_MSG_PING_REPLY, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_in_pingreply },
	{ .msg_subject=NP_MSG_PING_REQUEST, .msg_mode=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_out_send },
	{ .msg_subject=NP_MSG_PING_REPLY, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_NONE, .retry=5, .clb=hnd_msg_out_send },

	// join request: node unknown yet, therefore send without ack, explicit ack handling via extra messages
	{ .msg_subject=NP_MSG_JOIN_REQUEST, .msg_mode=INBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_DESTINATION, .retry=5, .clb=hnd_msg_in_join_req }, // just for controller ?
	{ .msg_subject=NP_MSG_JOIN_REQUEST, .msg_mode=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_DESTINATION, .retry=5, .clb=hnd_msg_out_send },
	{ .msg_subject=NP_MSG_JOIN_ACK, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_join_ack },
	{ .msg_subject=NP_MSG_JOIN_ACK, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send },
	{ .msg_subject=NP_MSG_JOIN_NACK, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_join_nack },
	{ .msg_subject=NP_MSG_JOIN_NACK, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send },

	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .msg_mode=TRANSFORM, .mep_type=DEFAULT_TYPE, .priority=5, .ack_mode=ACK_NONE, .retry=0, .clb=np_send_rowinfo }, // default input handling func should be "route_get" ?
	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_piggy },
	{ .msg_subject=NP_MSG_PIGGY_REQUEST, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send },

	{ .msg_subject=NP_MSG_UPDATE_REQUEST, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_update },
	{ .msg_subject=NP_MSG_UPDATE_REQUEST, .msg_mode=OUTBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send },

	{ .msg_subject=NP_MSG_INTEREST, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_interest },
	{ .msg_subject=NP_MSG_AVAILABLE, .msg_mode=INBOUND, .mep_type=ONE_WAY, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_in_available },
	{ .msg_subject=NP_MSG_INTEREST, .msg_mode=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send },
	{ .msg_subject=NP_MSG_AVAILABLE, .msg_mode=OUTBOUND, .mep_type=REQ_REP, .priority=5, .ack_mode=ACK_EACHHOP, .retry=5, .clb=hnd_msg_out_send }
};


void np_message_t_new(void* msg) {

	np_message_t* msg_tmp = (np_message_t*) msg;

	msg_tmp->header       = make_jtree();
	// log_msg(LOG_DEBUG, "header now (%p: %p->%p)", tmp, tmp->header, tmp->header->flink);
	msg_tmp->properties   = make_jtree();
	// log_msg(LOG_DEBUG, "properties now (%p: %p->%p)", tmp, tmp->properties, tmp->properties->flink);
	msg_tmp->instructions = make_jtree();
	// log_msg(LOG_DEBUG, "instructions now (%p: %p->%p)", tmp, tmp->instructions, tmp->instructions->flink);
	msg_tmp->body         = make_jtree();
	// log_msg(LOG_DEBUG, "body now (%p: %p->%p)", tmp, tmp->body, tmp->body->flink);
	msg_tmp->footer       = make_jtree();
}

// destructor of np_message_t
void np_message_t_del(void* data) {

	np_message_t* msg = (np_message_t*) data;

/*	np_jrb_t* subj = jrb_find_str(msg->header,       NP_MSG_HEADER_SUBJECT);
	np_jrb_t* seq  = jrb_find_str(msg->instructions, "_np.seq");

	if ( (subj != NULL) && (seq != NULL) ) {
		uint32_t seqnum = 0;
		seqnum = seq->val.value.ul;
		log_msg(LOG_DEBUG, "now deleting %s (%u)", subj->val.value.s, seqnum);

	} else if ( (subj != NULL) && (seq == NULL) ) {
		log_msg(LOG_DEBUG, "now deleting %s (0)", subj->val.value.s);

	} else {
		log_msg(LOG_DEBUG, "now deleting <unknown> (0)");
	}
*/
	// log_msg(LOG_DEBUG, "now deleting header %p", msg->header);
	np_free_tree(msg->header);
	// log_msg(LOG_DEBUG, "now deleting instructions %p", msg->instructions);
	np_free_tree(msg->instructions);
	// log_msg(LOG_DEBUG, "now deleting properties %p", msg->properties);
	np_free_tree(msg->properties);
	// log_msg(LOG_DEBUG, "now deleting body %p", msg->body);
	np_free_tree(msg->body);
	// log_msg(LOG_DEBUG, "now deleting footer %p", msg->footer);
	np_free_tree(msg->footer);
}

np_bool np_message_serialize(np_message_t* msg, void* target, uint64_t* out_size) {

    cmp_ctx_t cmp;
    cmp_init(&cmp, target, buffer_reader, buffer_writer);

	cmp_write_array(&cmp, 5);

	// log_msg(LOG_DEBUG, "serializing the header (size %hd)", msg->header->size);
	serialize_jrb_node_t(msg->header, &cmp);

	// log_msg(LOG_DEBUG, "serializing the instructions (size %hd)", msg->header->size);
	serialize_jrb_node_t(msg->instructions, &cmp);

	// log_msg(LOG_DEBUG, "serializing the properties (size %hd)", msg->properties->size);
	serialize_jrb_node_t(msg->properties, &cmp);

	// log_msg(LOG_DEBUG, "serializing the body (size %hd)", msg->body->size);
	serialize_jrb_node_t(msg->body, &cmp);

	// log_msg(LOG_DEBUG, "serializing the footer (size %hd)", msg->footer->size);
	serialize_jrb_node_t(msg->footer, &cmp);

	*out_size = cmp.buf-target;
	return TRUE;
}

np_bool np_message_deserialize(np_message_t* msg, void* buffer) {

	// np_message_t* msg_tmp;
	// np_bind(np_message_t, obj_msg, msg_tmp);

	cmp_ctx_t cmp;
	cmp_init(&cmp, buffer, buffer_reader, buffer_writer);

	uint32_t array_size;
	if (!cmp_read_array(&cmp, &array_size)) return 0;
	if (array_size != 5) {
		log_msg(LOG_WARN, "unrecognized message length while deserializing message");
		// np_unbind(np_message_t, obj_msg, msg_tmp);
		return FALSE;
	}

	// log_msg(LOG_DEBUG, "deserializing msg header");
	deserialize_jrb_node_t(msg->header, &cmp);

	// log_msg(LOG_DEBUG, "deserializing msg instructions");
	deserialize_jrb_node_t(msg->instructions, &cmp);

	// log_msg(LOG_DEBUG, "deserializing msg properties");
	deserialize_jrb_node_t(msg->properties, &cmp);

	// log_msg(LOG_DEBUG, "deserializing msg body");
	deserialize_jrb_node_t(msg->body, &cmp);

	// log_msg(LOG_DEBUG, "deserializing msg footer");
	deserialize_jrb_node_t(msg->footer, &cmp);

	// np_unbind(np_message_t, obj_msg, msg_tmp);
	return TRUE;
}

/** 
 ** message_create: 
 ** creates the message to the destination #dest# the message format would be like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message structure.
 */
void np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_jtree_t* the_data)
{
	// np_message_t* new_msg;
	// np_bind(np_message_t, msg, new_msg);
	// log_msg(LOG_DEBUG, "message ptr: %p %s", msg, subject);

	jrb_insert_str(msg->header, NP_MSG_HEADER_SUBJECT,  new_jval_s((char*) subject));
	jrb_insert_str(msg->header, NP_MSG_HEADER_TO,  new_jval_s((char*) key_get_as_string(to)));
	if (from != NULL) jrb_insert_str(msg->header, NP_MSG_HEADER_FROM, new_jval_s((char*) key_get_as_string(from)));
	if (from != NULL) jrb_insert_str(msg->header, NP_MSG_HEADER_REPLY_TO, new_jval_s((char*) key_get_as_string(from)));

	if (the_data != NULL) {
		np_message_setbody(msg, the_data);
	}
	// np_unbind(np_message_t, msg, new_msg);
}

inline void np_message_setproperties(np_message_t* msg, np_jtree_t* properties) {
	np_free_tree(msg->properties);
	msg->properties = properties;
};
inline void np_message_setinstruction(np_message_t* msg, np_jtree_t* instructions) {
	np_free_tree(msg->instructions);
	msg->instructions = instructions;
};
inline void np_message_setbody(np_message_t* msg, np_jtree_t* body) {
	// log_msg(LOG_DEBUG, "now setting body before %p", msg->body);
	np_free_tree(msg->body);
	msg->body = body;
	// log_msg(LOG_DEBUG, "now setting body after %p", msg->body);
};
inline void np_message_setfooter(np_message_t* msg, np_jtree_t* footer) {
	np_free_tree(msg->footer);
	msg->footer = footer;
};

//		if (-1 == np_message_decrypt_part(newmsg->instructions,
//										  enc_nonce->val.value.bin,
//										  session_token->session_key, NULL))
//		{
//			log_msg(LOG_ERROR,
//				"incorrect decryption of message instructions (send from %s:%hd)",
//				ipstr, port);
//			job_submit_event(state->jobq, np_network_read);
//			return;
//		}

np_bool np_message_decrypt_part(np_jtree_t* msg_part,
							unsigned char* enc_nonce,
							unsigned char* public_key,
							unsigned char* secret_key)
{
	log_msg(LOG_TRACE, ".start.np_message_decrypt_part");
	np_jtree_elem_t* enc_msg_part = jrb_find_str(msg_part, NP_ENCRYPTED);
	if (NULL == enc_msg_part) {
		log_msg(LOG_ERROR, "couldn't find encrypted msg part");
		log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
		return FALSE;
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
	if (ret < 0) {
		log_msg(LOG_ERROR, "couldn't decrypt msg part with session key %s", public_key);
		log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
		return FALSE;
	}

	cmp_ctx_t cmp;
	cmp_init(&cmp, dec_part, buffer_reader, buffer_writer);

//	uint32_t map_size = 0;
//	if (!cmp_read_map(&cmp, &map_size)) {
//		log_msg(LOG_ERROR, "couldn't read map size %s", public_key);
//		log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
//		return FALSE;
//	}

	deserialize_jrb_node_t(msg_part, &cmp);
	del_str_node(msg_part, NP_ENCRYPTED);

	log_msg(LOG_TRACE, ".end  .np_message_decrypt_part");
	return TRUE;
}

//		if (-1 == np_message_encrypt_part(args->msg->header,
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
np_bool np_message_encrypt_part(np_jtree_t* msg_part,
							unsigned char* nonce,
							unsigned char* public_key,
							unsigned char* secret_key)
{
	log_msg(LOG_TRACE, ".start.np_message_encrypt_part");
	cmp_ctx_t cmp;
    unsigned char msg_part_buffer[NP_MESSAGE_SIZE];
    void* msg_part_buf_ptr = msg_part_buffer;

    cmp_init(&cmp, msg_part_buf_ptr, buffer_reader, buffer_writer);
    serialize_jrb_node_t(msg_part, &cmp);

    uint64_t msg_part_len = cmp.buf-msg_part_buf_ptr;

	uint64_t enc_msg_part_len = msg_part_len + crypto_box_MACBYTES;

	unsigned char* enc_msg_part = (unsigned char*) malloc(enc_msg_part_len);
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
	if (ret < 0) {
		log_msg(LOG_TRACE, ".end  .np_message_encrypt_part");
		return FALSE;
	}
	// log_msg(LOG_ERROR, "encrypted msg part with session key %s", public_key);

	jrb_replace_all_with_str(msg_part, NP_ENCRYPTED,
			new_jval_bin(enc_msg_part, enc_msg_part_len));

	log_msg(LOG_TRACE, ".end  .np_message_encrypt_part");
	return TRUE;
}

void np_message_encrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token)
{
	log_msg(LOG_TRACE, ".start.np_message_encrypt_payload");
	// first encrypt the relevant message part itself
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char sym_key[crypto_secretbox_KEYBYTES];

	randombytes_buf((void*) nonce, crypto_box_NONCEBYTES);
	randombytes_buf((void*) sym_key, crypto_secretbox_KEYBYTES);

	np_message_encrypt_part(msg->body, nonce, sym_key, NULL);
	np_message_encrypt_part(msg->properties, nonce, sym_key, NULL);

	// now encrypt the encryption key using public key crypto stuff
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	unsigned char ciphertext[crypto_box_MACBYTES + crypto_secretbox_KEYBYTES];

	// convert our own sign key to an encryption key
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,
										 state->my_key->authentication->private_key);
	// finally encrypt
	int ret = crypto_box_easy(ciphertext, sym_key, crypto_secretbox_KEYBYTES, nonce,
					          tmp_token->public_key, curve25519_sk);
	if (0 > ret) {
		log_msg(LOG_ERROR, "encryption of message payload failed");
		return;
	}
/*
	log_msg(LOG_DEBUG, "ciphertext: %s", ciphertext);
	log_msg(LOG_DEBUG, "nonce:      %s", nonce);
	log_msg(LOG_DEBUG, "sym_key:    %s", sym_key);
*/

	// TODO: use sealed boxes instead ???
	// int crypto_box_seal(unsigned char *c, const unsigned char *m,
	// unsigned long long mlen, const unsigned char *pk);

	np_jtree_t* encryption_details = make_jtree();
	// insert the public-key encrypted encryption key for each receiver of the message
	jrb_insert_str(encryption_details, "_np.nonce",
				   new_jval_bin(nonce, crypto_box_NONCEBYTES));
	jrb_insert_str(encryption_details, tmp_token->issuer,
				   new_jval_bin(ciphertext,
						   	    crypto_box_MACBYTES + crypto_secretbox_KEYBYTES));

	// add encryption details to the message
	jrb_insert_str(msg->instructions, NP_ENCRYPTED,
			new_jval_tree(encryption_details));

	log_msg(LOG_TRACE, ".end  .np_message_encrypt_payload");
}

void np_message_decrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token) {

	log_msg(LOG_TRACE, ".start.np_message_decrypt_payload");

	np_jtree_t* encryption_details =
			jrb_find_str(msg->instructions, NP_ENCRYPTED)->val.value.tree;

	// insert the public-key encrypted encryption key for each receiver of the message
	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, jrb_find_str(encryption_details, "_np.nonce")->val.value.bin, crypto_box_NONCEBYTES);
	unsigned char enc_sym_key[crypto_secretbox_KEYBYTES + crypto_box_MACBYTES];
	memcpy(enc_sym_key, jrb_find_str(encryption_details, (char*) key_get_as_string(state->my_key))->val.value.bin, crypto_secretbox_KEYBYTES + crypto_box_MACBYTES);

	unsigned char sym_key[crypto_secretbox_KEYBYTES];
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,
										 state->my_key->authentication->private_key);

//	log_msg(LOG_DEBUG, "ciphertext: %s", enc_sym_key);
//	log_msg(LOG_DEBUG, "nonce:      %s", nonce);

	int ret = crypto_box_open_easy(sym_key, enc_sym_key, crypto_box_MACBYTES + crypto_secretbox_KEYBYTES,
								   nonce, tmp_token->public_key, curve25519_sk);
	if (0 > ret) {
		log_msg(LOG_ERROR, "decryption of message payload failed");
		return;
	}
// 	log_msg(LOG_DEBUG, "sym_key:    %s", sym_key);

	np_message_decrypt_part(msg->properties, nonce, sym_key, NULL);
	np_message_decrypt_part(msg->body, nonce, sym_key, NULL);

	log_msg(LOG_TRACE, ".end  .np_message_decrypt_payload");
}


/**
 ** message_init: chstate, port
 ** Initialize messaging subsystem on port and returns the MessageGlobal * which 
 ** contains global state of message subsystem.
 ** message_init also initiate the network subsystem
 **/
void message_init (np_state_t* state) {

    RB_INIT(&state->msg_properties);
    state->msg_tokens = make_jtree();

	/* NEUROPIL_INTERN_MESSAGES */
	for (uint8_t i = 0; i < NR_OF_ELEMS(np_internal_messages); i++) {
		if (strlen(np_internal_messages[i].msg_subject) > 0) {
			log_msg(LOG_DEBUG, "register handler (%hhd): %s", i, np_internal_messages[i].msg_subject);
			RB_INSERT(rbt_msgproperty, &state->msg_properties, &np_internal_messages[i]);
		}
	}
}

np_callback_t np_message_get_callback (np_msgproperty_t *handler)
{
	assert (handler != NULL);
	assert (handler->clb != NULL);

	return handler->clb;
}

/**
 ** registers the handler function #func# with the message type #type#,
 ** it also defines the acknowledgment requirement for this type 
 **/
np_msgproperty_t* np_message_get_handler(np_state_t *state, np_msg_mode_type msg_mode, const char* subject) {

	assert(subject != NULL);;

	np_msgproperty_t prop = { .msg_subject=(char*) subject, .msg_mode=msg_mode };
	return RB_FIND(rbt_msgproperty, &state->msg_properties, &prop);
}

int16_t property_comp(const np_msgproperty_t* const prop1, const np_msgproperty_t* const prop2)
{
	// TODO: check how to use bitmasks with red-black-tree efficiently
	int16_t i = strncmp(prop1->msg_subject, prop2->msg_subject, 64);

	if (0 == i)
		if (prop1->msg_mode == prop2->msg_mode) return  0;
		if (prop1->msg_mode > prop2->msg_mode)  return  1;
		if (prop1->msg_mode < prop2->msg_mode)  return -1;
	else
		return i;
}

void np_message_register_handler(np_state_t *state, np_msgproperty_t* msgprops) {
	RB_INSERT(rbt_msgproperty, &state->msg_properties, msgprops);
}

void np_msgproperty_t_new(void* property) {

	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	prop->partner_key = NULL;

	// prop->msg_subject = strndup(subject, 255);
	prop->msg_mode = INBOUND | OUTBOUND;
	prop->mep_type = ONE_WAY;
	prop->ack_mode = ACK_EACHHOP;
	prop->priority = 5;
	prop->retry    = 5;
	// prop->clb = callback;

	prop->max_threshold = 10;
	prop->msg_threshold =  0;

	prop->last_update = dtime();

	// cache which will hold up to max_threshold messages
	prop->cache_policy = FIFO | OVERFLOW_PURGE;
	sll_init(np_message_t, prop->msg_cache);

	pthread_mutex_init (&prop->lock, NULL);
    pthread_cond_init (&prop->msg_received, &prop->cond_attr);
    pthread_condattr_setpshared(&prop->cond_attr, PTHREAD_PROCESS_PRIVATE);
}

void np_msgproperty_t_del(void* property) {

	np_msgproperty_t* prop = (np_msgproperty_t*) property;

	if (prop->msg_subject) free(prop->msg_subject);

	pthread_condattr_destroy(&prop->cond_attr);
    pthread_cond_destroy (&prop->msg_received);
	pthread_mutex_destroy (&prop->lock);
}


//np_msgproperty_t* np_decode_msg_property(np_jtree_t* data) {
//
//	np_msgproperty_t* property = NULL;
//	np_new_obj(np_msgproperty_t, property);
//
//	np_jtree_elem_t* msg_subject = jrb_find_str(data, "_np.mp.msg_subject");
//	property->msg_subject = strndup(msg_subject->val.value.s, 255);
//	property->mep_type = jrb_find_str(data, "_np.mp.mep_type")->val.value.ush;
//	property->ack_mode = jrb_find_str(data, "_np.mp.ack_mode")->val.value.ush;
//	property->msg_threshold = jrb_find_str(data, "_np.mp.msg_threshold")->val.value.ui;
//	property->max_threshold = jrb_find_str(data, "_np.mp.max_threshold")->val.value.ui;
//
//	return property;
//}
//
//void np_encode_msg_property(np_jtree_t* data, np_msgproperty_t* property) {
//
//	jrb_insert_str(data, "_np.mp.msg_subject", new_jval_s(property->msg_subject));
//	jrb_insert_str(data, "_np.mp.mep_type", new_jval_ush(property->mep_type));
//	jrb_insert_str(data, "_np.mp.ack_mode", new_jval_ush(property->ack_mode));
//	jrb_insert_str(data, "_np.mp.max_threshold", new_jval_ui(property->max_threshold));
//	jrb_insert_str(data, "_np.mp.msg_threshold", new_jval_ui(property->msg_threshold));
//
//}
