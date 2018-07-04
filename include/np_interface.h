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
#include <assert.h>
#ifdef NP_BENCHMARKING
#include <math.h>
#endif
#include <float.h>

#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

	// Protocol constants
	enum {
		NP_SECRET_KEY_BYTES = 32,
		NP_PUBLIC_KEY_BYTES = 32,
		NP_FINGERPRINT_BYTES = 32,
        NP_UUID_CHARS = 37
	};

	// Implementation defined limits
	#define NP_EXTENSION_BYTES (10*1024)
	#define NP_EXTENSION_MAX (NP_EXTENSION_BYTES-1)

	enum np_status {
		np_error = 0,
		np_uninitialized,
		np_running,
		np_stopped,
		np_shutdown,		
	};

	enum np_error {
		np_ok = 0,
		np_not_implemented,
		np_network_error,
		np_invalid_argument,
		np_invalid_operation,
		np_insufficient_memory,
		np_startup
		// ...
	};
	static const char* np_error_str[] = {
		"",
		"operation is not implemented",
		"could not init network",
		"argument is invalid",
		"operation is currently invalid",
		"insufficient memory",
		"startup error. See log for more details"
	};

	typedef void np_context;
	
	typedef struct np_dhkey_s
	{
		uint32_t t[8];
	} np_id;

	// If length is 0 then string is expected to be null-terminated.
	// char* is the appropriate type because it is the type of a string
	// and can also describe an array of bytes. (sizeof char == 1)
	void np_get_id(np_context * context, np_id* id, char* string, size_t length);

	typedef struct np_token {
		np_id realm, issuer, subject, audience;
		double issued_at, not_before, expires_at;
		uint8_t extensions[NP_EXTENSION_BYTES];
		size_t extension_length;
		uint8_t public_key[NP_PUBLIC_KEY_BYTES],
			secret_key[NP_SECRET_KEY_BYTES];
	}np_token;

	typedef struct np_message {
		char uuid[NP_UUID_CHARS];
		np_id from; 
		np_id subject;		
		double received_at, expires_at;
		uint8_t * data;
		size_t data_length;
	} np_message ;

	// New incarnation of np_settings.h
	struct np_settings {
		uint32_t n_threads;
		char log_file[256];
		uint32_t log_level;
		// ...
	};

	struct np_settings * np_new_settings(struct np_settings **settings);

	np_context* np_new_context(struct np_settings *settings);

	// secret_key is nullable
	struct np_token *np_new_identity(np_context* ac, double expires_at, uint8_t* (secret_key[NP_SECRET_KEY_BYTES]));

	enum np_error np_set_identity(np_context* ac, struct np_token identity);

	enum np_error np_listen(np_context* ac, char* protocol, char* host, uint16_t port);

	// Get “connect string”. Signals error if connect string is unavailable (i.e.,
	// no listening interface is configured.)
	enum np_error np_get_address(np_context* ac, char* address, uint32_t max);

	enum np_error np_join(np_context* ac, char* address);

	enum np_error np_send(np_context* ac, char* subject, uint8_t* message, size_t length);
	enum np_error np_send_to(np_context* ac, char* subject, uint8_t* message, size_t length, np_id * target);

	typedef bool (*np_receive_callback)(np_context* ac, np_message* message);
	// There can be more than one receive callback, hence "add".
	enum np_error np_add_receive_cb(np_context* ac, char* subject, np_receive_callback callback);

	typedef bool (*np_aaa_callback)(np_context* ac, struct np_token* aaa_token);
	enum np_error np_set_authenticate_cb(np_context* ac, np_aaa_callback callback);
	enum np_error np_set_authorize_cb(np_context* ac, np_aaa_callback callback);
	enum np_error np_set_accounting_cb(np_context* ac, np_aaa_callback callback);
	

	// duration: 0 => process pending events and return
	//           N => process events for up to N seconds and return
	enum np_error np_run(np_context* ac, double duration);

	enum np_mx_pattern      { NP_MX_ONEWAY, NP_MX_REQ_REP, /* ... */ };
	enum np_mx_cache_policy { NP_MX_FIFO_REJECT, NP_MX_FIFO_PURGE, NP_MX_LIFO_REJECT, NP_MX_LIFO_PURGE };
	enum np_mx_ackmode      { NP_MX_ACK_NONE, NP_MX_ACK_DESTINATION, NP_MX_ACK_CLIENT };

	struct np_mx_properties {
		char* reply_subject;
		enum np_mx_ackmode ackmode;
		enum np_mx_pattern pattern;
		enum np_mx_cache_policy cache_policy;
		uint32_t max_parallel, max_retry;
		double intent_ttl, intent_update_after;
		double message_ttl;
		bool once_only;
	};

	struct np_mx_properties np_get_mx_properties(np_context* ac, char* subject, bool* exisits);
	enum np_error np_set_mx_properties(np_context* ac, char* subject, struct np_mx_properties properties);

	bool np_has_joined(np_context * ac);
	void np_set_userdata(np_context * ac, void* userdata);
	void* np_get_userdata(np_context * ac);
	enum np_status np_get_status(np_context* ac);	
	bool np_has_receiver_for(np_context*ac, char * subject);



#ifdef __cplusplus
}
#endif

#endif /* _NP_INTERFACE_H_ */
