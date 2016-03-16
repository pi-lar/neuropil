/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "include.h"

#include "jval.h"
#include "np_container.h"
#include "np_jtree.h"
#include "np_key.h"
#include "np_memory.h"
#include "np_util.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_messagepart_s
{
	np_jtree_t* header;
	np_jtree_t* instructions;
	int part;
	void* msg_part;
};

typedef np_messagepart_t* np_messagepart_ptr;
NP_PLL_GENERATE_PROTOTYPES(np_messagepart_ptr);

struct np_message_s
{
	np_obj_t* obj; // link to memory pool

	np_jtree_t* header;
	np_jtree_t* instructions;
	np_jtree_t* properties;
	np_jtree_t* body;
	np_jtree_t* footer;

	// only used if the message has to be split up into chunks
	np_bool is_single_part;
	uint16_t no_of_chunks;
	np_pll_t(np_messagepart_ptr, msg_chunks);
};

_NP_GENERATE_MEMORY_PROTOTYPES(np_message_t);


/** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **/
void np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_jtree_t* the_data);

void np_message_encrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token);
np_bool np_message_decrypt_payload(np_state_t* state, np_message_t* msg, np_aaatoken_t* tmp_token);

// encrypt / decrypt parts of a message
np_bool np_message_decrypt_part(np_jtree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);
np_bool np_message_encrypt_part(np_jtree_t* msg_part, unsigned char* enc_nonce, unsigned char* public_key, unsigned char* private_key);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
void np_message_calculate_chunking(np_message_t* msg);
np_message_t* np_message_check_chunks_complete(np_state_t* state, np_jobargs_t* args);
np_bool np_message_serialize(np_state_t* state, np_jobargs_t* args);
np_bool np_message_serialize_chunked(np_state_t* state, np_jobargs_t* args);
np_bool np_message_deserialize(np_message_t* msg, void* buffer);
np_bool np_message_deserialize_chunked(np_message_t* msg);

void np_message_setinstruction(np_message_t* msg, np_jtree_t* instructions);
void np_message_addinstructionentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delinstructionentry(np_message_t*, const char* key);

void np_message_setproperties(np_message_t* msg, np_jtree_t* properties);
void np_message_addpropertyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delpropertyentry(np_message_t*, const char* key);

void np_message_setbody(np_message_t* msg, np_jtree_t* body);
void np_message_addbodyentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delbodyentry(np_message_t*, const char* key);

inline void np_message_setfooter(np_message_t* msg, np_jtree_t* footer);
void np_message_addfooterentry(np_message_t*, const char* key, np_jval_t value);
void np_message_delfooterentry(np_message_t*, const char* key);

// msg header constants
static const char* NP_MSG_HEADER_SUBJECT   = "_np.subj";
static const char* NP_MSG_HEADER_TO        = "_np.to";
static const char* NP_MSG_HEADER_FROM      = "_np.from";
static const char* NP_MSG_HEADER_REPLY_TO  = "_np.r_to";

// msg instructions constants
static const char* NP_MSG_INST_SEND_COUNTER = "_np.sendnr";
static const char* NP_MSG_INST_PART         = "_np.part";
static const char* NP_MSG_INST_PARTS        = "_np.parts";
static const char* NP_MSG_INST_ACK          = "_np.ack";
static const char* NP_MSG_INST_ACK_TO       = "_np.ack_to";
static const char* NP_MSG_INST_SEQ          = "_np.seq";
static const char* NP_MSG_INST_UUID         = "_np.uuid";
static const char* NP_MSG_INST_ACKUUID      = "_np.ackuuid";
static const char* NP_MSG_INST_TTL          = "_np.ttl";
static const char* NP_MSG_INST_TSTAMP       = "_np.tstamp";

// msg handshake constants
static const char* NP_HS_PAYLOAD = "_np.payload";
static const char* NP_HS_SIGNATURE = "_np.signature";

// body constants
static const char* NP_MSG_BODY_JTREE = "_np.jtree";
static const char* NP_MSG_BODY_TEXT = "_np.text";
static const char* NP_MSG_BODY_XML = "_np.xml";

// encrypted message part
static const char* NP_NONCE = "_np.nonce";
static const char* NP_ENCRYPTED = "_np.encrypted";
static const char* NP_SYMKEY = "_np.symkey";

// msg footer constants
static const char* NP_MSG_FOOTER_ALIAS_KEY = "_np.alias_key";
static const char* NP_MSG_FOOTER_GARBAGE = "_np.garbage";

#ifdef __cplusplus
}
#endif

#endif /* _NP_MESSAGE_H_ */
