//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_keycache.h"
#include "np_tree.h"

#include "neuropil.h"

#include "example_helper.c"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);


np_bool receive_echo_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body);

/**
  The purpose of this program is to start a server for our echo service.
  We will wait for incomming messages on the "echo" subject and will return them to the sender.
*/
int main(int argc, char **argv) {

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";

	int opt;
	if (parse_program_args(
		__FILE__,
		argc,
		argv,
		&no_threads,
		&j_key,
		&proto,
		&port,
		&publish_domain,
		&level,
		&logpath,
		NULL,
		NULL
	) == FALSE) {
		exit(EXIT_FAILURE);
	} 

	/**
		for the general initialisation of a node please look into the neuropil_node example
	*/

	char log_file[256];
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_echo_server", port);
	fprintf(stdout, "logpath: %s\n", log_file);

	np_log_init(log_file, level);
	np_init(proto, port, publish_domain);

	/**
	in your main program, initialize the message property for the echo service

	.. code-block:: c

	\code
	*/

	np_msgproperty_t* msg_props = NULL;
	np_add_receive_listener(receive_echo_message, "echo");
	msg_props = np_msgproperty_get(INBOUND, "echo");
	msg_props->msg_subject = strndup("echo", 255);
	msg_props->ack_mode = ACK_NONE;
	msg_props->msg_ttl = 20.0;
	/**
	 \endcode

	and add a listener to receive a callback everytime a "echo" message is received.
	finally start the job queue to start processing messages.

	.. code-block:: c

     \code
	*/
	np_start_job_queue(no_threads);
	/** \endcode */

	while (TRUE) {
		np_time_sleep(0.1);
	}
}

/**
Our callback function that will be called each time
a echo message is received by the nodes that you are going to start

.. code-block:: c

\code
*/
np_bool receive_echo_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {
/** \endcode */
	np_tree_t* header = msg->header;
	fprintf(stdout, "%f - RECEIVED", np_time_now());

	/**
	 we try to evaluate the source of the message

	 .. code-block:: c

	 \code
	 */
	np_dhkey_t reply_to = { 0 }; // All
	np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
	if (NULL != repl_to) {
		reply_to = repl_to->val.value.dhkey;

		/**
		 \endcode

		  we evaluate the content and check if we did receive a text message
		  to prevent malicious use of the demo service and then
		  send the message back to its sender

		 .. code-block:: c

		 \code
		 */
		char* text;
		np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
		if (NULL != txt) {
			text = np_treeval_to_str(txt->val, NULL);

		} else {
			text = "<NON TEXT MSG>";
		}
		fprintf(stdout, ": \"%s\"\n", text);
		// send the message back
		np_send_text("echo", text, 0, &reply_to);
		/** \endcode */
	}
	return TRUE;
}
