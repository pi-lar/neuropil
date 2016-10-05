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

#define USAGE "neuropil_receiver_cb [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
extern int optind;

/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c

   np_bool receive_this_is_a_test(np_tree_t* properties, np_tree_t* body)
   {
*/
static const char* NP_MSG_BODY_TEXT = "_np.text";

np_bool receive_this_is_a_test(np_tree_t* properties, np_tree_t* body)
{
	/**
	for this message exchange the message is send as a text element (if you used np_send_text)
	otherwise inspect the properties and payload np_tree_t structures ...

    .. code-block:: c

	      char* text = tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	*/
	char* text = tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	log_msg(LOG_INFO, "RECEIVED: %s", text);

	/**
	return TRUE to indicate successfull handling of the message. if you return FALSE
	the message may get delivered a second time

	.. code-block:: c

	      return TRUE;
	   }
	*/
	return TRUE;
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

	   char log_file[256];
	   sprintf(log_file, "%s_%d.log", "./neuropil_node", port);
	   int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	   log_init(log_file, level);
	*/
	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_node", port);
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_ROUTING | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_NETWORKDEBUG | LOG_KEYDEBUG;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_MESSAGE;
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_AAATOKEN;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	np_log_init(log_file, level);

	/**
	initialize the neuropil subsystem with the np_init function

	.. code-block:: c

	   np_init(proto, port, FALSE);
	*/
	np_init(proto, port, FALSE);

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads (network io is non-blocking).

	.. code-block:: c

	   np_start_job_queue(8);
	*/
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);

	/**
	wait until the node has received a join message before actually proceeding

	.. code-block:: c

	   np_waitforjoin();
	*/

	if (NULL != j_key)
	{
		np_send_join(j_key);
	}

	np_waitforjoin();

	/**
	.. note::
	   Make sure that you implement and register the appropiate aaa callback functions
	   to control with which nodes you exchange messages. By default everybody is allowed to interact
	   with your node
	 */

	/**
	register the listener function to receive data from the other side

	.. code-block:: c

	   np_set_listener(receive_this_is_a_test, "this.is.a.test");
	*/
	np_set_listener(receive_this_is_a_test, "this.is.a.test");

	/**
	loop (almost) forever, you're done :-)

	the loopback function will be triggered each time a message is received
	make sure that you've understood how to alter the message exchange to change
	receiving of message from the default values

	.. code-block:: c

	   while (1)
	   {
		   ev_sleep(0.9);
	   }
 	*/
	while (1)
	{
		ev_sleep(0.9);
	}
}
