//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: bootstrap node.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#include "neuropil.h"

bool authenticate (np_context *, struct np_token *);

int main (void)
{
	struct np_settings cfg;
	np_default_settings(&cfg);

	np_context *ac = np_new_context(&cfg);

	/**
	   In order to bootstrap a neuropil network we need an initial peer
	   that will invite our node into the mesh. We call Nodes whose only
	   function is providing transit services to the network
	   “infrastructure nodes.” A simple infrastructure node could look very
	   much like the simple receiver example above, and could serve as the
	   initial contact for other neuropil nodes (such as our sender and
	   receiver examples.)

	   This node will not receive any messages, and will not set an
	   authorization callback. More importantly, our bootstrap node will
	   not attempt to join a network via :c:func:`np_join`. Since it will
	   be the first node in the network there is no network it could join.
	   Still, it will just listen on a known network address/port tuple.

	   .. code-block:: c

	   \code
	*/
	assert(np_ok == np_listen(ac, "udp4", "localhost", 2345));
	/**
	   \endcode

	   Other nodes can now join the network by calling :c:func:`np_join`
	   with the bootstrap node’s address. Using the absolute address as
	   returned by c:func:`np_get_address` will guarantee that nodes will
	   connect to the intended node only, and not say an impersonator.

	   .. code-block:: c

	   \code
	*/
	char address[256];
	assert(np_ok == np_get_address(ac, address, sizeof(address)));
	printf("Bootstrap address: %s\n", address);
	/**
	   \endcode

	   Alternatively, you can attempt to join any node that listens on a
	   specific network address/port tuple by joining a wildcard address,
	   which in this case would be ``"*:udp4:localhost:2345"``.

	   In the neuropil messaging layer, nodes need no authorization to join
	   a network, but they do need to authenticate themselves. This node
	   sets an authentication callback via :c:func:`np_set_authenticate_cb`
	   that will be called each time a node attempts to join this node.
	*/
	assert(np_ok == np_set_authenticate_cb(ac, authenticate));

	enum np_return status;
	do status = np_run(ac, 5.0); while (np_ok == status);

	return status;
}

/**
   The authentication callback gets passed the identity of the node that
   requesting to join, and can reject the request by returning :c:data:`false`.
   For convenience, we merely log the first seven bytes of the public key of
   each node that joins the network via this node in its authentication
   callback.

   .. code-block:: c

   \code
*/
bool authenticate (np_context *ac, struct np_token *id)
{
	// TODO: Make sure that id->public_key is an authenticated peer!
	printf("Joined: %02X%02X%02X%02X%02X%02X%02X...\n",
	       id->public_key[0], id->public_key[1], id->public_key[2],
	       id->public_key[3], id->public_key[4], id->public_key[5],
	       id->public_key[6]);
	return true;
}
/**
   \endcode
*/
