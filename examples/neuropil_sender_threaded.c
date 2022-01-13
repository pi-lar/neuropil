//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: sending messages.

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>

/**
   First and foremost, we have to include header file which defines the API for
   the neuropil cybersecurity mesh.

   .. code-block:: c

   \code
*/
#include "neuropil.h"
/**
   \endcode
*/

struct input_thread_args {
    np_context *ac;
    bool isRunning;
    const char *subject;
};


bool authorize (np_context *, struct np_token *);
void handle_input(struct input_thread_args *args);

int main (void)
{
	/**
	   To initialize the neuropil cybersecurity mesh, we prepare a
	   :c:type:`np_settings` by populating it with the default settings
	   using :c:func:`np_default_settings`, and create a new
	   application context with :c:func:`np_new_context`.

	   .. code-block:: c

	   \code
	*/
	struct np_settings cfg;
	np_default_settings(&cfg);
	np_context *ac = np_new_context(&cfg);

    const char *subject = "mysubject";
	struct np_mx_properties msg_props = np_get_mx_properties(ac, subject);
	np_set_mx_properties(ac, subject, msg_props);
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

	np_run(ac, 0.0);

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
	   event loop for five seconds with :c:func:`np_run`, and then send our
	   message with the subject ``"mysubject"`` using :c:func:`np_send` inside a dedicated thread. If
	   anything goes wrong we return the error code (an
	   :c:type:`np_return`.)

	   Effectively, this means that our node will process protocol requests
	   continuously and in parallel it is able to send a user defined message.

	   .. code-block:: c

	   \code
	 */
	enum np_return status;

	// Create arguments for input thread
	bool isRunning = true;
	struct input_thread_args args;
	args.ac = ac;
	args.isRunning = isRunning;
    args.subject = subject;
    // Create & start user input thread
	pthread_t input_thread;
	pthread_create(&input_thread, NULL, handle_input, &args);

	// Run neuropil event loop
	do status = np_run(ac, 5.0);
	while (np_ok == status);

	// End thread loop and wait for it to end
    isRunning = false;
    pthread_join(input_thread, NULL);
	return status;
        /**
	   \endcode
	*/Extend sender/receiver example by user defined messages.
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

/**
 The user input will be dealt with in a separate thread. It will get the neuropil context and a running
 indicator as arguments and will continously ask the user for new messages to send.
 \code
 */
void handle_input(struct input_thread_args *thread_args) {
	do {
		char message[100];
		printf("Enter message (max 100 chars): ");
        fgets(message, 200, stdin);
        // Remove trailing newline
        if ((strlen(message) > 0) && (message[strlen (message) - 1] == '\n'))
            message[strlen (message) - 1] = '\0';
		size_t message_len = strlen(message);
		np_send(thread_args->ac, thread_args->subject, message, message_len);
		printf("Sent: %s\n", message);
	} while(thread_args->isRunning);
}
/**
 \endcode
 */
