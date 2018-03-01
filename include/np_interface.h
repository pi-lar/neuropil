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

	enum np_error {
		np_ok = 0,
		np_invalid_input,
		np_invalid_input_size,
		// ...
	};

	typedef void np_context;
	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];

	np_context* np_new_context (uint8_t n_threads);
	void np_get_id (np_id* out, char* in, uint32_t length);

	enum np_error np_send (np_context* ac, uint8_t* data, uint32_t length, np_id* subject);

	// Get “connect string”. Signals error if connect string is unavailable (i.e.,
	// no listening interface is configured.)
	enum np_error np_get_address (void *ac, char *out, uint32_t max);

	enum np_error np_join (np_context* ac, char* address);

	enum np_error np_listen (np_context* ac, char* protocol, char* address, uint16_t port);

	struct np_token {
		np_id realm, issuer, subject, audience;		
		double issued_at, not_before, expires_at;
		uint8_t extensions[NP_EXTENSION_BYTES];
		uint32_t extension_length;			
		uint8_t public_key[NP_PUBLIC_BYTES],
                        secret_key[NP_SECRET_BYTES];
	};

	// secret_key is nullable
	struct np_token *np_new_identity (void *ac, double expires_at, uint8_t *(secret_key[SECRET_KEY_BYTES]));

	enum np_error np_set_identity (np_context* ac, struct np_token identity);
	
	// duration == 0 => process pending events and exit
	enum np_error np_run (np_context* ac, double duration);

	typedef bool (*np_receive_callback) (uint8_t* data, uint32_t length);
	enum np_error np_receive (np_context* ac, np_receive_callback callback);

	enum np_mx_ackmode {
		np_mx_ackmode_none = 0
	};

	struct np_mx_properties {
		enum np_mx_ackmode ackmode;
		uint16_t max_parallel; // ex threshold
		//...
	};

	enum np_error  np_set_mx_properties (np_context* ac, np_id subject, struct np_mx_properties properties);

	typedef bool (*np_aaa_callback) (struct np_token *aaa_token);
	enum np_error np_authenticate (np_context* ac, np_aaa_callback callback);
	enum np_error np_authorize (np_context* ac, np_id subject, np_aaa_callback callback);
	
#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
