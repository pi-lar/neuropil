

#ifndef _NP_RESPONSECONTAINER_H_
#define _NP_RESPONSECONTAINER_H_


#include "np_list.h"
#include "np_memory.h"

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
	struct np_responsecontainer_s {
		double received_at;      // the time when the msg received a response (ack or reply)
		double send_at; // this is the time the packet is transmitted (or retransmitted)
		double expires_at;   // the time when the responsecontainer will expire and will be deleted
		np_key_t* dest_key; // the destination key / next/final hop of the message
		// uint16_t expected_ack;
		// uint16_t received_ack;
		np_message_t* msg;
	} NP_API_INTERN;

	_NP_GENERATE_MEMORY_PROTOTYPES(np_responsecontainer_t);

	NP_API_INTERN
		void _np_responsecontainer_received_ack(np_responsecontainer_t* entry);
	NP_API_INTERN
		np_bool _np_responsecontainer_is_fully_acked(np_responsecontainer_t* entry);
	NP_API_INTERN
		void _np_responsecontainer_set_timeout(np_responsecontainer_t* entry);
	NP_API_INTERN
		np_responsecontainer_t* _np_responsecontainers_get_by_uuid(np_state_t* context, char* uuid);
	NP_API_INTERN
		void _np_responsecontainer_received_response(np_responsecontainer_t* entry, np_message_t* response);

#ifdef __cplusplus
}
#endif

#endif // _NP_RESPONSECONTAINER_H_
