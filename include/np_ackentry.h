
#ifndef _NP_AACKENTRY_H_
#define _NP_AACKENTRY_H_


#include "np_list.h"
#include "np_memory.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
	struct np_ackentry_s {
		np_obj_t* obj;

		np_bool has_received_ack;        // signal when paket is acked
		double received_at;      // the time when the last packet is acked
		double send_at; // this is the time the packet is transmitted (or retransmitted)
		double expires_at;   // the time when the ackentry will expire and will be deleted
		np_key_t* dest_key; // the destination key / next/final hop of the message
		uint16_t expected_ack;
		uint16_t received_ack;
		np_message_t* msg;
	} NP_API_INTERN;

	_NP_GENERATE_MEMORY_PROTOTYPES(np_ackentry_t);

	NP_API_INTERN
		void _np_ackentry_set_acked(np_ackentry_t* entry);

	NP_API_INTERN
		np_bool _np_ackentry_is_fully_acked(np_ackentry_t* entry);

#ifdef __cplusplus
}
#endif

#endif // _NP_AACKENTRY_H_
