//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
 *.. NOTE::
 *
 *   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
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


np_bool receive_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body);

/**
  The purpose of this program is to start a client for our echo service.
  We will periodicly call our echo server with a message
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
		"[-m message_to_send]",
		"m:",
		&message_to_send

	) == FALSE) {
		exit(EXIT_FAILURE);
	}
	np_bool j_key_provided = j_key != NULL;
	int retry_connection = 3;
	np_bool add_id_to_msg = strcmp(message_to_send, message_to_send_org ) == 0;

	char log_file_host[256];
	sprintf(log_file_host, "%s%s_%s.log", logpath, "/neuropil_echo_client", port);	
	fprintf(stdout, "logpath: %s\n", log_file_host);

/**
  We create our node,

 .. code-block:: c
 \code
 */
	np_log_init(log_file_host, level);
	np_state_t* status = np_init(proto, port, publish_domain);
/**
 \endcode
 
  and join to our bootstrap node
 (either the default localhost or a node provided by parameter)

 .. code-block: c
 \code
 */
	char* bootstrap_node = NULL;
	while (TRUE) {
		fprintf(stdout, "try to join bootstrap node\n");
		if (TRUE == j_key_provided) {
			np_send_join(j_key);
		} else {
			sprintf(j_key, "%s:localhost:3333", proto);
			np_send_wildcard_join(j_key);
		}

		int timeout = 100;
		while (timeout > 0
				&& FALSE == status->my_node_key->node->joined_network) {
			// wait for join acceptance
			np_time_sleep(0.1);
			timeout--;
		}

		if (TRUE == status->my_node_key->node->joined_network) {
			bootstrap_node = np_route_get_bootstrap_connection_string();
			fprintf(stdout, "%s joined network!\n", port);
			break;
		} else {
			fprintf(stderr, "%s could not join network!\n", port);
			if(retry_connection-- < 0){
				fprintf(stderr, "abort\n");
				break;
			}
		}
	}
  /**
   \endcode

	and initialize the message property for the echo service

	.. code-block:: c
	\code
	*/

	np_msgproperty_t* msg_props = NULL;
	np_add_receive_listener(receive_message, "echo");
	msg_props = np_msgproperty_get(INBOUND, msg_props);
	msg_props->msg_subject = strndup("echo", 255);
	msg_props->ack_mode = ACK_NONE;
	msg_props->msg_ttl = 20.0;
	/**
	 \endcode

	to add a listener to receive a callback every time a "echo" message is received.
	finally start the jobqueue to start processing messages.

	.. code-block:: c
	\code
	*/
	np_start_job_queue(no_threads);
	/**
	 \endcode

	  And now we can send, periodically, our message to our bootstrap node.

	 .. code-block:: c
	 \code
	 */
	uint32_t i = 0;
	while (TRUE == status->my_node_key->node->joined_network) {
		__np_example_helper_loop();
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
			np_send_text("echo", s_out, 0, NULL);
			free(s_out);
		}
		np_time_sleep(0.1);
	}
	/** \endcode */
}

/**
  If  we receive a message for the "echo" subject we now get a callback to this function

 .. code-block:: c
 \code
 */
np_bool receive_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) {
	/**
	 \endcode

	  We can now handle the message an can access
	  the payload via the body and properties tree structures.

	 .. code-block:: c
	 \code
	 */
	 np_tree_t* header = msg->header;

	char* reply_to = NULL;
	np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
	if (NULL != repl_to) {
		reply_to = np_treeval_to_str(repl_to->val, NULL);
	}

	char* text;
	np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
	if (NULL != txt) {
		text = np_treeval_to_str(txt->val, NULL);

	} else {
		text = "<NON TEXT MSG>";
	}
	fprintf(stdout, "%f - RECEIVED: \"%s\" from: %s \n", np_time_now(), text, reply_to);
	/**
	 \endcode

	  To signal the network a completely processed message
	  (no resends necessary) we return a TRUE value to our caller.

	 .. code-block:: c
	 \code
	 */
	return TRUE;
	/** \endcode */
}
