//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_MESSAGE_H_
#define _NP_MESSAGE_H_

#include <stdarg.h>

#include "np_memory.h"

#include "np_types.h"
#include "np_messagepart.h"
#include "np_threads.h"
#include "util/np_list.h"

#ifdef __cplusplus
extern "C" {
#endif


enum np_message_submit_type {
    np_message_submit_type_DIRECT,
    np_message_submit_type_ROUTE
};

struct np_message_s
{
    char* uuid;

    np_tree_t* header;
    np_tree_t* instructions;
    np_tree_t* body;
    np_tree_t* footer;

    // only used if the message has to be split up into chunks
    bool is_single_part;
    uint32_t no_of_chunks;
    uint32_t no_of_chunk;
    np_pll_t(np_messagepart_ptr, msg_chunks);
    np_mutex_t msg_chunks_lock;

    // np_msgproperty_conf_ptr msg_property;
    double send_at;
    double redelivery_at;

    void* bin_body;
    void* bin_footer;
    np_messagepart_t* bin_static;

    enum np_message_submit_type submit_type;
    np_aaatoken_t * decryption_token;
} NP_API_INTERN;


_NP_GENERATE_MEMORY_PROTOTYPES(np_message_t)


/** message_create / free:
 ** creates the message to the destination #dest# the message format would be like:
 ** deletes the message and corresponding structures
 **
 **/
NP_API_INTERN
void _np_message_create(np_message_t* msg, np_dhkey_t to, np_dhkey_t from, np_dhkey_t subject, np_tree_t* the_data);

NP_API_INTERN
bool np_message_clone(np_message_t* copy_of_message, np_message_t* message);

NP_API_INTERN
void _np_message_encrypt_payload(np_message_t* msg, np_sll_t(np_aaatoken_ptr,tmp_token) );
NP_API_INTERN
bool _np_message_decrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token);

// (de-) serialize a message to a binary stream using message pack (cmp.h)
NP_API_INTERN
void _np_message_calculate_chunking(np_message_t* msg);

NP_API_INTERN
bool _np_message_serialize_header_and_instructions(np_state_t* context, np_message_t* msg);
NP_API_INTERN
bool _np_message_serialize_chunked(np_state_t* context, np_message_t * msg);

NP_API_INTERN
bool _np_message_deserialize_header_and_instructions(np_message_t* msg, void* buffer);
NP_API_INTERN
bool _np_message_deserialize_chunked(np_message_t* msg);

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
np_dhkey_t* _np_message_get_subject(const np_message_t* const self);
NP_API_INTERN
double _np_message_get_expiery(const np_message_t* const self);
NP_API_INTERN
bool _np_message_is_expired(const np_message_t* const msg_to_check);
NP_API_INTERN
bool _np_message_is_internal(np_state_t * context, np_message_t * msg);
NP_API_INTERN
void _np_message_mark_as_incomming(np_message_t* msg);
NP_API_INTERN
np_dhkey_t* _np_message_get_sender(const np_message_t* const self);

NP_API_INTERN
void _np_message_add_response_handler(const np_message_t* self, const np_util_event_t event, bool use_destination_from_header_to_field);

NP_API_INTERN
void _np_message_trace_info(char* desc, np_message_t * msg_in);

// msg header constants
static const char* _NP_MSG_HEADER_TARGET		= "_np.target";
static const char* _NP_MSG_HEADER_SUBJECT		= "_np.subj";
static const char* _NP_MSG_HEADER_TO			= "_np.to";
static const char* _NP_MSG_HEADER_FROM			= "_np.from";

// msg instructions constants
static const char* _NP_MSG_INST_SEND_COUNTER	= "_np.sendnr";
static const char* _NP_MSG_INST_PARTS			= "_np.parts";
static const char* _NP_MSG_INST_ACK				= "_np.ack";
static const char* _NP_MSG_INST_ACK_TO			= "_np.ack_to";
static const char* _NP_MSG_INST_SEQ				= "_np.seq";
static const char* _NP_MSG_INST_UUID			= "_np.uuid";
static const char* _NP_MSG_INST_RESPONSE_UUID	= "_np.response_uuid";
static const char* _NP_MSG_INST_TTL				= "_np.ttl";
static const char* _NP_MSG_INST_TSTAMP			= "_np.tstamp";

// msg extension constants
static const char* _NP_MSG_EXTENSIONS_SESSION = "_np.session";

// msg handshake constants
static const char* NP_HS_PAYLOAD = "_np.payload";
static const char* NP_HS_SIGNATURE = "_np.signature";
static const char* NP_HS_PRIO = "_np.hs.priority";

// body constants
static const char* NP_MSG_BODY_TEXT = "_np.text";
static const char* NP_MSG_BODY_XML = "_np.xml";

// msg footer constants
static const char* NP_MSG_FOOTER_GARBAGE = "_np.garbage";

#ifdef __cplusplus
}
#endif

#endif /* _NP_MESSAGE_H_ */
