//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: sending messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <sodium.h>

#include "neuropil.h"

/* This is our intended recepient’s public key (encoded in hexadecimal.) */
char *trusted = "0a1b2c3d4e5f6a7b0a1b2c3d4e5f6a7b7b6a5f4e3d2c1b0a7b6a5f4e3d2c1b0a";

uint8_t trusted_pubkey[NP_PUBLIC_KEY_BYTES];

bool authorize (np_context *ac, struct token *id)
{
	return 0 == sodium_memcmp(id->public_key, trusted_pubkey,
				  NP_PUBLIC_KEY_BYTES);
}

int main (void)
{
	size_t key_len = 0;
	assert(0 == sodium_hex2bin(trusted_pubkey, sizeof(trusted_pubkey),
				   trusted, strlen(trusted),
				   NULL, &key_len, NULL));
	assert(key_len == NP_PUBLIC_KEY_BYTES);

	struct np_settings cfg;
	np_default_settings(&cfg);

	np_context *ac = np_new_context(&cfg);

	assert(np_ok == np_listen(ac, "udp4", "localhost", 1234));

	assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));

	assert(np_ok == np_set_authorize_cb(ac, authorize));

	np_error status;
	char *message = "Hello, World!";
	do {
		status = np_run(ac, 5.0)
			|| np_send(ac, "mysubject", message, strlen(message));
	} while (np_ok == status);

	return status;
}
