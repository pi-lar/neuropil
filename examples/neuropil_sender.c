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

#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_tree.h"
#include "np_types.h"

#define USAGE "neuropil_sender [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count] [-r realmname] [-c code]"
#define OPTSTR "j:p:b:t:r:c:"

extern char *optarg;
extern int optind;

/**
first we have to define a global np_state_t variable

 .. code-block:: c
 \code
*/
np_state_t *state;
/** \endcode */

int main(int argc, char **argv)
{
	int opt;
	int no_threads = 2;
	char *j_key = NULL;
	char* proto = NULL;
	char* port = NULL;
	char* realm = NULL;
	char* code = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			j_key = optarg;
			break;
		case 't':
			no_threads = atoi(optarg);
			if (no_threads <= 0) no_threads = 8;
			break;
		case 'p':
			proto = optarg;
			break;
		case 'b':
			port = optarg;
			break;
		case 'r':
			realm = optarg;
			break;
		case 'c':
			code = optarg;
			break;
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	/**
	in your main program, initialize the logging of neuopil, use the port for the filename

	.. code-block:: c
	\code
	*/
	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_node", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG  | LOG_AAATOKEN;
	np_log_init(log_file, level);
	/** \endcode */

	/**
	initialize the global variable with the np_init function. the last argument
	defines if you would like to have simplistic http interface on port 31415

	.. code-block:: c
	\code
	*/
	state = np_init(proto, port, FALSE, NULL);
	/** \endcode */

	if (NULL != realm)
	{
		np_set_realm_name(realm);
		np_enable_realm_slave();
		if (NULL != code)
		{
			np_tree_insert_str(state->my_node_key->aaa_token->extensions,
							"passcode",
							np_treeval_new_hash(code));
		}
	}

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads, because network reading currently is blocking.

	.. code-block:: c
	\code
	*/
	np_start_job_queue(no_threads);
	/** \endcode */

	if (NULL != j_key)
	{
		np_send_join(j_key);
	}

	/**
	use the connect string that is printed to stdout and pass it to the np_controller to send a join message.
	wait until the node has received a join message before actually proceeding

	.. code-block:: c
	\code
	*/
	np_waitforjoin();
	/** \endcode */

	/**
	 *.. note::
	 *  Make sure that you implement and register the appropiate aaa callback functions
	 *  to control with which nodes you exchange messages. By default everybody is allowed to interact
	 *  with your node
	 */

	/**
	create the message that you would like to send across (now or in the loop later)

	.. code-block:: c
	\code
	*/
	char* msg_subject = "this.is.a.test";
	char* msg_data = "testdata";
	unsigned long k = 1;
	/** \endcode */

	/**
	loop (almost) forever and send your messages to the receiver :-)

	.. code-block:: c
	\code
 	*/
	while (1) {

		ev_sleep(1.0);

		np_send_text(msg_subject, msg_data, k, NULL);
		log_debug_msg(LOG_DEBUG, "send message %lu", k);

		k++;
	}
	/** \endcode */
}
