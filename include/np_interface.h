//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

/* Neuropil API v2 */

#ifndef _NP_INTERFACE_H_
#define _NP_INTERFACE_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Protocol constants
	enum {
		NP_SECRET_KEY_BYTES = 32,
		NP_PUBLIC_KEY_BYTES = 32,
		NP_FINGERPRINT_BYTES = 32
	};

	// Implementation defined limits
	#define NP_EXTENSION_BYTES (10*1024)
	#define NP_EXTENSION_MAX (NP_EXTENSION_BYTES-1)

	enum np_error {
		np_ok = 0,
		np_network_error,
		np_invalid_input,
		np_invalid_input_size,
		np_invalid_operation,
		np_insufficient_memory,
		np_startup
		// ...
	};

	typedef uint8_t np_id[NP_FINGERPRINT_BYTES];
	// If length is 0 then string is expected to be null-terminated.
	// char* is the appropriate type because it is the type of a string
	// and can also describe an array of bytes. (sizeof char == 1)
	void np_get_id(np_id* id, char* string, size_t length);

	struct np_token {
		np_id realm, issuer, subject, audience;		
		double issued_at, not_before, expires_at;
		uint8_t extensions[NP_EXTENSION_BYTES];
		size_t extension_length;			
		uint8_t public_key[NP_PUBLIC_KEY_BYTES],
                        secret_key[NP_SECRET_KEY_BYTES];
	};

	// New incarnation of np_settings.h
	struct np_settings {
		uint32_t n_threads;
		// ...
	};
	void np_default_settings (struct np_settings *settings);

	typedef void np_context;
	np_context* np_new_context(struct np_settings *settings);

	enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);

	// secret_key is nullable
	struct np_token *np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES]));

	enum np_error np_set_identity(np_context* ac, struct np_token identity);

	// Get “connect string”. Signals error if connect string is unavailable (i.e.,
	// no listening interface is configured.)
	enum np_error np_get_address(np_context* ac, char* address, uint32_t max);

	enum np_error np_join(np_context* ac, char* address);

	enum np_error np_send(np_context* ac, uint8_t* message, size_t length, np_id* subject);

	typedef bool (*np_receive_callback)(uint8_t* message, size_t length);
	// There can be more than one receive callback, hence "add".
	enum np_error np_add_receive_cb(np_context* ac, np_receive_callback callback);

	typedef bool (*np_aaa_callback)(struct np_token* aaa_token);
	enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);
	enum np_error np_set_authorize_cb(np_context* ac, np_id subject, np_aaa_callback callback);

	// duration: 0 => process pending events and return
	//           N => process events for up to N seconds and return
	enum np_error np_run(np_context* ac, double duration);

	enum np_mx_pattern      { NP_MX_ONEWAY, NP_MX_REQ_REP, /* ... */ };
	enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE };
	enum np_mx_ackmode      { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT };
	struct np_mx_properties {
		np_id reply_subject;
		enum np_mx_ackmode ackmode;
		enum np_mx_pattern pattern;
		enum np_mx_cache_policy cache_policy;
		uint32_t max_parallel, max_retry, max_ttl, min_ttl;
		bool unique_uuids_check;
	};

	enum np_error np_set_mx_properties(np_context* ac, np_id subject, struct np_mx_properties properties);
	
#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
