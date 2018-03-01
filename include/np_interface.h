//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but heavily modified
/**
neuropil.h is the entry point to use the neuropil messaging library.
It defines all user centric functions and hides the complexity of the double encryption layer.
It should contain all required functions to send or receive messages.

*/

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>

//#include <np_intern.h>

#ifdef __cplusplus
extern "C" {
#endif
	
	#define NP_EXTENSION_BYTES (10*1024)
	#define NP_SECRET_BYTES (4096)
	#define NP_PUBLIC_BYTES (999)
	#define NP_FINGERPRINT_BYTES (64)

	enum np_error_code {
		np_error_code_none = 0,
		np_error_code_invalid_input,
		np_error_code_invalid_input_size,
		np_error_code_wrong_process_order,
	};

	typedef void np_application_context;
	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];

	np_application_context* np_build_application_context(uint8_t prefered_no_of_threads);
	void np_get_id(np_id* out, unsigned char* data, uint32_t data_size);
	enum np_error_code np_get_address (np_application_context* ac, unsigned char* buffer, uint32_t buffer_size);
	
	enum np_ip_port_type {
		np_ip_port_type_udp,
		np_ip_port_type_tcp
	};
	enum np_connection_type {
		np_connection_type_ip4,
		np_connection_type_ip6
	};
	typedef struct np_connection {
		np_id hash;
		uint8_t ip_v4[4];
		uint8_t ip_v6[16];
		uint16_t ip_port;
		enum ip_port_type ip_port_type;
		enum np_connection_type connection_type;
	} np_connection;

	enum np_error_code  np_send_data(np_application_context* ac, void* data, uint32_t size, char* subject);

	enum np_error_code np_connect(np_application_context* ac, struct np_connection c);
	enum np_error_code np_connect_to(np_application_context* ac, char* connection_str);

	enum np_error_code np_listen(np_application_context* ac, struct np_connection on);
	enum np_error_code np_listen_on(np_application_context* ac, char* on);

	typedef struct np_token {
		np_id realm, issuer, subject, audience;		
		double issued_at, not_before, expires_at;
		uint8_t extension_bytes[NP_EXTENSION_BYTES], 			
			public_key[NP_PUBLIC_BYTES],
			secret_key[NP_SECRET_BYTES];
		uint32_t extension_length;
	} np_token;

	enum np_error_code  np_set_identity(np_application_context* ac, struct np_token ident);	
	
	// duration == 0 => run infinite
	enum np_error_code  np_run(np_application_context* ac, uint32_t duration);

	typedef bool(*np_receive_callback) (void* data, uint32_t data_size);
	enum np_error_code  np_add_on_receive(np_application_context* ac, np_receive_callback clb);
	uint32_t np_pull_data(np_application_context* ac, char * subject, void* buffer, uint32_t buffer_size);

	enum np_message_exchange_ackmode {
		np_message_exchange_ackmode_none = 0
	};

	typedef struct np_message_exchange {
		enum np_message_exchange_ackmode ackmode;
		uint16_t max_parallel; // ex threshold
		//...
	} np_message_exchange;

	enum np_error_code  np_register_subject(np_application_context* c, np_id subject, struct np_message_exchange exchange_config);

	typedef bool(*np_authenticate_callback) (struct np_token token);
	enum np_error_code  np_authenticate(np_application_context* ac, np_authenticate_callback clb);
	struct np_token np_pull_authenticate(np_application_context* ac);

	typedef bool(*np_authorize_callback) (struct np_token token);
	enum np_error_code  np_authorize(np_application_context* ac, np_id subject, np_authorize_callback clb);	
	struct np_token np_pull_authorize(np_application_context* ac, np_id subject);

#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
