//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: receiving messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "neuropil.h"

bool authorize (np_context *ac, struct np_token *id)
{
	// TODO: Make sure that id->public_key is the intended sender!
	return true;
}

bool receive (np_context* ac, struct np_message* message)
{
	printf("Received: %.*s\n", message->data_length, message->data);
	return true;
}

int main (void)
{
	struct np_settings cfg;
	np_default_settings(&cfg);

	np_context *ac = np_new_context(&cfg);

	assert(np_ok == np_listen(ac, "udp4", "localhost", 3456));

	assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));

	assert(np_ok == np_set_authorize_cb(ac, authorize));

	assert(np_ok == np_add_receive_cb(ac, "mysubject", receive));

	enum np_error status;
	do status = np_run(ac, 5.0); while (np_ok == status);

	return status;
}
