//
// neuropil is copyright 2016-2018 by pi-lar GmbH
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

#include "example_helper.c"

/**
first we have to define a global np_state_t variable

.. code-block:: c

   \code
*/
np_state_t *state;
/**
   \endcode
*/

int main(int argc, char **argv)
{
	char* realm = NULL;
	char* code = NULL;

	int no_threads = 8;
	char *j_key = NULL;
	char* proto = "udp4";
	char* port = NULL;
	char* publish_domain = NULL;
	int level = -2;
	char* logpath = ".";
	
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
		"[-r realmname] [-c code]",
		"r:c:"
	) == FALSE) {
		exit(EXIT_FAILURE);
	}	

	/**
	in your main program, initialize the logging of neuopil, use the port for the filename

	.. code-block:: c

	   \code
	*/
	struct np_settings *settings = np_new_settings(NULL);
	settings->n_threads = no_threads;

	sprintf(settings->log_file, "%s%s_%s.log", logpath, "/neuropil_controller", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	np_context * context = np_new_context(settings);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}
	/**
	   \endcode
	*/

	if (NULL != realm)
	{
		np_set_realm_name(context, realm);
		//np_enable_realm_client();
		if (NULL != code)
		{
			np_tree_insert_str(state->my_node_key->aaa_token->extensions,
							"passcode",
							np_treeval_new_hash(code));
		}
	}

	__np_example_helper_loop(context); // for the fancy ncurse display

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads, because network reading currently is blocking.

	.. code-block:: c

	   \code
	*/
	if (np_ok != np_run(context, 0)) {
		printf("ERROR: Node could not start");
		exit(EXIT_FAILURE);
	}
	/**
	   \endcode
	*/

	if (NULL != j_key)
	{
		np_join(context, j_key);
	}

	/**
	use the connect string that is printed to stdout and pass it to the np_controller to send a join message.
	wait until the node has received a join message before actually proceeding

	.. code-block:: c

	   \code
	*/
	np_waitforjoin(context);
	/**
	   \endcode
	*/

	/**
	 .. NOTE::
	    Make sure that you implement and register the appropiate aaa callback functions
	    to control with which nodes you exchange messages. By default everybody is allowed to interact
	    with your node
	*/

	/**
	create the message that you would like to send across (now or in the loop later)

	.. code-block:: c

	   \code
	*/
	char* msg_subject = "this.is.a.test";
	char* msg_data = "testdata";
	unsigned long k = 1;
	/**
	   \endcode
	*/

	/**
	loop (almost) forever and send your messages to the receiver :-)
	 
	.. code-block:: c

	   \code
	*/
	while (1) {
		__np_example_helper_loop(context); // for the fancy ncurse display
		np_time_sleep(1.0);

		np_send_text(context, msg_subject, msg_data, k, NULL);
		log_debug_msg(LOG_DEBUG, "send message %lu", k);

		k++;
	}
	/**
	   \endcode
    */
}
