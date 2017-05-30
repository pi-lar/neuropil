//
// neuropil is copyright 2016 by pi-lar GmbH
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

#define USAGE "neuropil_echo_client [-j key:proto:host:port] [ -p protocol] [-t worker_thread_count] [-l path_to_log_folder] [-u publish_domain] [-m message_to_send]"
#define OPTSTR "j:p:t:l:u:m:"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

#define DEBUG 0

extern char *optarg;
extern int optind;

np_bool receive_message(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body);

/**
  The purpose of this program is to start a client for our echo service.
  We will periodicly call our echo server with a message
  and if everything goes as expected we will receive the same message
  from the server.
 */
int main(int argc, char **argv) {
	int opt;

	char* proto = "udp4";
	char* logpath = ".";
 	char j_key[256];
	char* publish_domain = "localhost";
	char* message_to_send = "Hello World!";
	np_bool add_id_to_msg = TRUE;
	int no_threads = 8;
	int retry_connection = 3;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;
	np_bool j_key_provided = FALSE;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
		case 'j':
			j_key_provided = TRUE;
			sprintf(j_key, "%s", optarg);
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0)
				no_threads = 2;
			break;
		case 'm':
    /**
      The default value for the message we like to send is "Hello World! {x}"
      {x} will be replaced by a increasing number.
      If you like to send your own message you can
      call the programm with the "-m <string>" parameter.
     */
			message_to_send = optarg;
			add_id_to_msg = FALSE;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'u':
			publish_domain = optarg;
			break;
		case 'l':
			if (optarg != NULL) {
				logpath = optarg;
			} else {
				fprintf(stderr, "invalid option value\n");
				fprintf(stderr, "usage: %s\n", USAGE);
				exit(EXIT_FAILURE);
			}
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(EXIT_FAILURE);
		}
	}
  /**
	  To create unique names and to use a seperate port for every
	  node we will start the nodes in forks of this thread and use the pid as unique id.

	  As the pid may be greater then the port range we will shift it if necessary.

	 .. code-block:: c
	 \code
   */
	char port[7];
	// Get the current pid and shift it to be a viable port.
	// This way the application may be used for multiple instances on one system
	int current_pid = getpid();
	fprintf(stdout, "%d\n", current_pid);

	if (current_pid > 65535) {
		sprintf(port, "%d", (current_pid >> 1));
	} else {
		sprintf(port, "%d", current_pid);
	}
	/** \endcode */

	char log_file_host[256];
	sprintf(log_file_host, "%s%s_%s.log", logpath, "/neuropil_echo_client",
			port);
	fprintf(stdout, "logpath: %s\n", log_file_host);

/**
  We create our node,

 .. code-block:: c
 \code
 */
	np_log_init(log_file_host, level);
	np_state_t* status = np_init(proto, port, FALSE,
			strcmp(publish_domain, "localhost") == 0 ? publish_domain : NULL);
	np_start_job_queue(no_threads);
/**
 \endcode
 
  and join to our bootstrap node
 (either the default localhost or a node provided by parameter)

 .. code-block: c
 \code
 */
	np_key_t* bootstrap_node = NULL;
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
			ev_sleep(0.1);
			timeout--;
		}

		if (TRUE == status->my_node_key->node->joined_network) {
			bootstrap_node = np_route_get_bootstrap_key();
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
	np_new_obj(np_msgproperty_t, msg_props);
	msg_props->msg_subject = "echo";
	msg_props->ack_mode = ACK_NONE;
	msg_props->ttl = 20.0;
	np_msgproperty_register(msg_props);
	/**
	 \endcode

	and add a listener to receive a callback every time a "echo" message is received

	.. code-block:: c
	\code
	*/
	np_set_listener(receive_message, "echo");
	/**
	 \endcode

	  And now we can send, periodically, our message to our bootstrap node

	 .. code-block:: c
	 \code
	 */
	uint64_t i = 0;
	while (TRUE == status->my_node_key->node->joined_network) {
		if (i++ % 50 == 0) {
			char * s_out;
			if(add_id_to_msg) {
				asprintf(&s_out, "%s %"PRIu64, message_to_send, i );
			} else {
				asprintf(&s_out,"%s", message_to_send);
			}

			fprintf(stdout, "%f - SENDING:  \"%s\" to    %s\n", ev_time(), s_out, _np_key_as_str(bootstrap_node));
			log_msg(LOG_INFO, "SENDING:  \"%s\" to    %s", s_out, _np_key_as_str(bootstrap_node));

			// Send our message
			np_send_text("echo", s_out, 0, _np_key_as_str(bootstrap_node));
			free(s_out);
		}
		ev_sleep(0.1);
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
		reply_to = repl_to->val.value.s;
	}

	char* text;
	np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
	if (NULL != txt) {
		text = txt->val.value.s;

	} else {
		text = "<NON TEXT MSG>";
	}
	fprintf(stdout, "%f - RECEIVED: \"%s\" from: %s \n", ev_time(), text, reply_to);
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
