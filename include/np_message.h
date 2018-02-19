//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_types.h"
#include "np_messagepart.h"
#include "np_threads.h"
#include "np_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_message_s
{
	char* uuid;

	np_obj_t* obj; // link to memory pool

	np_tree_t* header;
	np_tree_t* instructions;
	np_tree_t* properties;
	np_tree_t* body;
	np_tree_t* footer;

	// only used if the message has to be split up into chunks
	np_bool is_single_part;
	uint32_t no_of_chunks;
	np_pll_t(np_messagepart_ptr, msg_chunks);
	np_mutex_t msg_chunks_lock;

	np_msgproperty_ptr msg_property;

	TSP(np_bool, is_acked);
	np_sll_t(np_responsecontainer_on_t, on_ack);
	TSP(np_bool, is_in_timeout);
	np_sll_t(np_responsecontainer_on_t, on_timeout);
	TSP(np_bool, has_reply);
	np_sll_t(np_message_on_reply_t, on_reply);

	void* bin_properties;
	void* bin_body;
	void* bin_footer;
	np_messagepart_t* bin_static;

} NP_API_INTERN;

#ifndef SWIG
_NP_GENERATE_MEMORY_PROTOTYPES(np_message_t);
#endif

/** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **
 **/
NP_API_INTERN
void _np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_tree_t* the_data);

NP_API_INTERN
void _np_message_encrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token);
NP_API_INTERN
np_bool _np_message_decrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
NP_API_INTERN
void _np_message_calculate_chunking(np_message_t* msg);
NP_API_INTERN
np_message_t* _np_message_check_chunks_complete(np_message_t* msg_to_check);
NP_API_INTERN
np_bool _np_message_serialize_header_and_instructions(np_jobargs_t* args);
NP_API_INTERN
np_bool _np_message_serialize_chunked(np_message_t * msg);

NP_API_INTERN
np_bool _np_message_deserialize_header_and_instructions(np_message_t* msg, void* buffer);
NP_API_INTERN
np_bool _np_message_deserialize_chunked(np_message_t* msg);

NP_API_INTERN
void _np_message_setinstructions(np_message_t* msg, np_tree_t* instructions);
NP_API_INTERN
void _np_message_add_instruction(np_message_t*, const char* key, np_treeval_t value);
NP_API_INTERN
void _np_message_del_instruction(np_message_t*, const char* key);

NP_API_INTERN
void _np_message_setproperties(np_message_t* msg, np_tree_t* properties);
NP_API_INTERN
void _np_message_add_property(np_message_t*, const char* key, np_treeval_t value);
NP_API_INTERN
void _np_message_del_property(np_message_t*, const char* key);

NP_API_INTERN
void _np_message_setbody(np_message_t* msg, np_tree_t* body);
NP_API_INTERN
void _np_message_add_bodyentry(np_message_t*, const char* key, np_treeval_t value);
NP_API_INTERN
void _np_message_del_bodyentry(np_message_t*, const char* key);

NP_API_INTERN
inline void _np_message_setfooter(np_message_t* msg, np_tree_t* footer);
NP_API_INTERN
void _np_message_add_footerentry(np_message_t*, const char* key, np_treeval_t value);
NP_API_INTERN
void _np_message_del_footerentry(np_message_t*, const char* key);

NP_API_INTERN
void _np_message_set_to(np_message_t* msg, np_key_t* target);
NP_API_INTERN
char* _np_message_get_subject(np_message_t* msg);
NP_API_INTERN
double _np_message_get_expiery(const np_message_t* const self);
NP_API_INTERN
np_bool _np_message_is_expired(const np_message_t* const msg_to_check);
NP_API_INTERN
void _np_message_mark_as_incomming(np_message_t* msg);
NP_API_INTERN
np_key_t* _np_message_get_sender(np_message_t* self);

NP_API_EXPORT
void np_message_add_on_reply(np_message_t* self, np_message_on_reply_t on_reply);
NP_API_EXPORT
void np_message_remove_on_reply(np_message_t* self, np_message_on_reply_t on_reply_to_remove);

// msg header constants
static const char* _NP_MSG_HEADER_TARGET		= "_np.target";
static const char* _NP_MSG_HEADER_SUBJECT		= "_np.subj";
static const char* _NP_MSG_HEADER_TO			= "_np.to";
static const char* _NP_MSG_HEADER_FROM			= "_np.from";

// msg instructions constants
static const char* _NP_MSG_INST_SEND_COUNTER	= "_np.sendnr";
static const char* _NP_MSG_INST_PART			= "_np.part";
static const char* _NP_MSG_INST_PARTS			= "_np.parts";
static const char* _NP_MSG_INST_ACK				= "_np.ack";
static const char* _NP_MSG_INST_ACK_TO			= "_np.ack_to";
static const char* _NP_MSG_INST_SEQ				= "_np.seq";
static const char* _NP_MSG_INST_UUID			= "_np.uuid";
static const char* _NP_MSG_INST_RESPONSE_UUID	= "_np.response_uuid";
static const char* _NP_MSG_INST_TTL				= "_np.ttl";
static const char* _NP_MSG_INST_TSTAMP			= "_np.tstamp";

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
