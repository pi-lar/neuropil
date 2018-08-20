//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: sending messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>

#include "neuropil.h"

bool authorize (np_context *ac, struct token *id)
{
	// TODO: Make sure that id->public_key is the intended receipient!
	return true;
}

int main (void)
{
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
