//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

// Example: sending messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

/**
   First and foremost, we have to include header file which defines the API for
   the neuropil messaging layer.

   .. code-block:: c

   \code
*/
#include "neuropil.h"
/**
   \endcode
*/

bool authorize (np_context *, struct np_token *);

int main (void)
{
	/**
	   To initialize the neuropil messaging layer, we prepare a
	   :c:type:`np_settings` by populating it with the default settings
	   using :c:func:`np_default_settings`, and create a new
	   application context with :c:func:`np_new_context`.

	   .. code-block:: c

	   \code
	*/
	struct np_settings cfg;
	np_default_settings(&cfg);

	np_context *ac = np_new_context(&cfg);
        /**
	   \endcode
	*/

	/**
	   Next, we allocate a network address and port tuple to listen on for
	   incoming connections using :c:func:`np_listen`.

	   .. code-block:: c

	   \code
	 */
	assert(np_ok == np_listen(ac, "udp4", "localhost", 1234));
        /**
	   \endcode
	*/

	/**
	   To join a neuropil network, we have to connect with our initial
	   bootstrap node using :c:func:`np_join`. Other nodes in the network
	   will be discovered automatically, but we need explicitly specify the
	   network address and port tuple for our initial contact.

	   .. code-block:: c

	   \code
	 */
	assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
        /**
	   \endcode
	*/

	/**
	   We should also set an authorization callback via
	   :c:func:`np_set_authorize_cb` to control access to this node. More
	   on this later.

	   .. code-block:: c

	   \code
	 */
	assert(np_ok == np_set_authorize_cb(ac, authorize));
        /**
	   \endcode
	*/

    /**
       Now to our application logic. We will repeatedly run the neuropil
       event loop with :c:func:`np_run`, and then send our user defined
       message with the subject ``"mysubject"`` using :c:func:`np_send`. If
       anything goes wrong we return the error code (an
       :c:type:`np_return`.)

       Effectively, this means that our node will process protocol requests
       continuously (for as long as there is no error situation) and send a
       message every five seconds periodically.

       .. code-block:: c

       \code
     */
    enum np_return status;
    do {
        status = np_run(ac, 0);
        char message[100];
        printf("Enter message (max 100 chars): ");
        fgets(message, 200, stdin);
        // Remove trailing newline
        if ((strlen(message) > 0) && (message[strlen (message) - 1] == '\n'))
            message[strlen (message) - 1] = '\0';
        size_t message_len = strlen(message);
        np_send(ac, "mysubject", message, message_len);
        printf("Sent: %s\n", message);
    } while (np_ok == status);

	return status;
        /**
	   \endcode
	*/
}

/**
   All that is left is to implement our authorization callback, a function of
   type :c:type:`np_aaa_callback`. The one defined is eternally lenient, and
   authorizes every peer to receive our messages. To ensure that our message is
   not read by strangers, it should really return :c:data:`false` for
   :c:type:`np_token` of unknown identities.

   .. code-block:: c

   \code
*/
bool authorize (np_context *ac, struct np_token *id)
{
	// TODO: Make sure that id->public_key is the intended recipient!
	return true;
}
/**
   \endcode
*/
