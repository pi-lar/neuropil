//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/**
.. highlight:: c
*/

#include "np_log.h"
#include "neuropil.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_message.h"

#define USAGE "neuropil_receiver_cb [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
extern int optind;

/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c
\code
*/

np_bool receive_this_is_a_test(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body)
{
/** \endcode */
	/**
	for this message exchange the message is send as a text element (if you used np_send_text)
	otherwise inspect the properties and payload np_tree_t structures ...

    .. code-block:: c
		\code
	*/
	char* text = np_tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	/** \endcode */
	log_msg(LOG_INFO, "RECEIVED: %s", text);

	/**
	return TRUE to indicate successfull handling of the message. if you return FALSE
	the message may get delivered a second time

	.. code-block:: c
	\code
	*/
	return TRUE;
	/** \endcode */
}


int main(int argc, char **argv)
{
	int opt;
	int no_threads = 2;
	char *j_key = NULL;
	char* proto = NULL;
	char* port = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			// for (i = 0; optarg[i] != ':' && i < strlen(optarg); i++);
			// optarg[i] = 0;
			j_key = optarg;
			// j_proto = optarg + (i+1);
			// j_hn = optarg + (i+2);
			// j_port = optarg + (i+3);
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 2;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'b':
			port = optarg;
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	/**
	in your main program, initialize the logging of neuopil, but this time use the port for the filename

	.. code-block:: c
	\code
	*/
	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_node", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_AAATOKEN;
	np_log_init(log_file, level);
	/** \endcode */

	/**
	initialize the neuropil subsystem with the np_init function

	.. code-block:: c
	\code
	*/
	np_init(proto, port, FALSE, NULL);
	/** \endcode */

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads (network io is non-blocking).

	.. code-block:: c
		\code
	*/
	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);
	/** \endcode */


	if (NULL != j_key)
	{
		np_send_join(j_key);
	}

		/**
		use the connect string that is printed to stdout and pass it to the np_controller to send a join message.
		wait until the node has received a join message before proceeding

		.. code-block:: c
		\code
		*/
	np_waitforjoin();
	/** \endcode */

	/**
	*.. note::
	*   Make sure that you have implemented and registered the appropiate aaa callback functions
	*   to control with which nodes you exchange messages. By default everybody is allowed to interact
	*   with your node
	 */

	/**
	register the listener function to receive data from the sender

	.. code-block:: c
		\code
	*/
	np_set_listener(receive_this_is_a_test, "this.is.a.test");
	/** \endcode */


	/**
	the loopback function will be triggered each time a message is received
	make sure that you've understood how to alter the message exchange to change
	receiving of message from the default values
 	*/

	/**
	loop (almost) forever, you're done :-)

	.. code-block:: c
	\code
	*/
	while (1)
	{
		ev_sleep(0.9);
	}
	/** \endcode */
}
