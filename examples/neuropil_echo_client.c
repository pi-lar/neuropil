//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 .. NOTE::
    If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
*/
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_route.h"

#include "neuropil.h"

#include "example_helper.c"


NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);


bool receive_message(np_context *context, const np_message_t* const msg, np_tree_t* body, void* localdata);

/**
The purpose of this program is to start a client for our echo service.
We will periodically call our echo server with a message
and if everything goes as expected we will receive the same message
from the server.
*/
int main(int argc, char **argv) {
	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";
	/**
	The default value for the message we like to send is "Hello World! {x}"
	{x} will be replaced by a increasing number.
	If you like to send your own message you can
	call the programm with the "-m <string>" parameter.
	*/

	char* message_to_send_org = "Hello World!";
	char* message_to_send = message_to_send_org;

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
		"[-m message_to_send]",
		"m:",
		&message_to_send

	) == false) {
		exit(EXIT_FAILURE);
	}
	bool j_key_provided = j_key != NULL;
	int retry_connection = 3;
	bool add_id_to_msg = strcmp(message_to_send, message_to_send_org ) == 0;

 
	/**
	We create our node,

	.. code-block:: c

	\code
	*/
	struct np_settings *settings = np_default_settings(NULL);
	settings->n_threads = no_threads;

	snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_controller", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	np_state_t * context = np_new_context(settings);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}

	/**
	\endcode
	*/

	/**
  	and join to our bootstrap node
 	(either the default localhost or a node provided by parameter)

	.. code-block: c

	\code
	*/
	char* bootstrap_node = NULL;
	while (true) {
		fprintf(stdout, "try to join bootstrap node\n");
		if (false == j_key_provided) {
			snprintf(j_key, 255, "%s:localhost:3333", proto);
		}
		np_join(context, j_key);

		int timeout = 100;
		while (timeout > 0
				&& false == context->my_node_key->node->joined_network) {
			// wait for join acceptance
			np_time_sleep(0.1);
			timeout--;
		}

		if (true == context->my_node_key->node->joined_network) {
			bootstrap_node = np_route_get_bootstrap_connection_string(context);
			fprintf(stdout, "%s joined network!\n", port);
			break;
		} else {
			fprintf(stdout, "%s could not join network!\n", port);
			if(retry_connection-- < 0){
				fprintf(stdout, "abort\n");
				break;
			}
		}
	}
	/**
	\endcode
	*/

	/**
	and initialize the message property for the echo service

	.. code-block:: c

	\code
	*/
	np_msgproperty_t* msg_props = NULL;
	np_add_receive_listener(context, receive_message, NULL, "echo");
	msg_props = np_msgproperty_get(context, INBOUND, "echo");
	msg_props->msg_subject = strndup("echo", 255);
	msg_props->ack_mode = ACK_NONE;
	msg_props->msg_ttl = 20.0;
	/**
	\endcode
	*/

	/**
	to add a listener to receive a callback every time a "echo" message is received.
	finally start the jobqueue to start processing messages.

	.. code-block:: c

	\code
	*/
	__np_example_helper_loop(context);
	if (np_ok != np_run(context, 0)) {
		printf("ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}	/**
	\endcode
	*/

	/**
	And now we can send, periodically, our message to our bootstrap node.

	.. code-block:: c

	\code
	*/
	uint32_t i = 0;
	while (true == context->my_node_key->node->joined_network) {
		__np_example_helper_loop(context);
		if (i++ % 50 == 0) {
			char * s_out;
			if(add_id_to_msg) {
				asprintf(&s_out, "%s %"PRIu32, message_to_send, i );
			} else {
				asprintf(&s_out,"%s", message_to_send);
			}

			fprintf(stdout, "%f - SENDING:  \"%s\" to    %s\n", np_time_now(), s_out, bootstrap_node);
			log_msg(LOG_INFO, "SENDING:  \"%s\" to    %s", s_out, bootstrap_node);

			// Send our message
			np_send_text(context, "echo", s_out, 0, NULL);
			free(s_out);
		}
		np_time_sleep(0.1);
	}
	/**
	\endcode
	*/
}

/**
If  we receive a message for the "echo" subject we now get a callback to this function

.. code-block:: c

   \code
*/
bool receive_message(np_context *context, const np_message_t* const msg, np_tree_t* body, void* localdata) {
/**
   \endcode
*/
	/**
	We can now handle the message an can access
	the payload via the body tree structure.

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
	fprintf(stdout, "%f - RECEIVED: \"%s\" \n", np_time_now(), text);
	/**
	   \endcode
	*/

	/**
	To signal the network a completely processed message
	(no resends necessary) we return a true value to our caller.

	.. code-block:: c

	   \code
	*/
	return true;
	/**
	   \endcode
	*/
}
