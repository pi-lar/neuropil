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
#include <assert.h>

#include "neuropil.h"
#include "np_log.h"
#include "np_types.h"

#include "example_helper.c"

/**
first we have to define some global variables

.. code-block:: c

   \code
*/
int seq = -1;
int joinComplete = 0;
/**
   \endcode
*/

int main(int argc, char **argv)
{
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
		NULL,
		NULL
	) == false) {
		exit(EXIT_FAILURE);
	}

	/**
	in your main program, initialize the settings for neuropil 
	(if you want to use the defaults you may skip this and provide NULL instead)

	.. code-block:: c

	   \code
	*/

	struct np_settings *settings = np_default_settings(NULL);
	settings->n_threads = no_threads;

	snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_controller", port);
	fprintf(stdout, "logpath: %s\n", settings->log_file);
	settings->log_level = level;

	/**
	   \endcode
	*/


	/**
	initialize the context with the np_new_context function 
	and start the network to listen on

	.. code-block:: c

	   \code
	*/
	np_context * context = np_new_context(settings);

	if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}

	/**
	   \endcode
	*/


	/**
	start up the job processing

	.. code-block:: c

	   \code
	*/
	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_run(context, 0);
	/**
	   \endcode
	*/

	/**
	  check stdout and the log file because it will contain this nodes hashvalue / connect string, e.g.

    .. code-block:: c

       2f96848a8c490e0f0f71c74caa900423bcf2d32882a9a0b3510c50085f7ec0e5:udp6:localhost:3333
	*/

	/**
	and finally loop (almost) forever

	.. code-block:: c

	   while (1) {
	       np_time_sleep(1.0);
	   }
	*/

	/**
	your're done ... if you plan to connect your nodes to this controller as a bootstrap node.

	The created process can be contacted by other nodes and will forward messages as required.
	By default the authentication / authorization / accounting handler accept nodes/message request
	from everybody.

    .. NOTE::
	   Make sure that you implement and register your own aaa callback functions to control with which
	   nodes you exchange messages. By default everybody is allowed to interact with your node !
	*/

	if(j_key != NULL){
		np_join(context, j_key);
	}
	while (1)
	{
		size_t nbytes = 255;
		// msg_out = NULL;
		char* node_string = (char *) malloc (nbytes);
		printf("enter a node to start (key:host:port)\n");
		fgets(node_string, nbytes, stdin);
		if (strlen(node_string) > 255 || strlen(node_string) < 64)
		{
			printf("given identifier too long or to small, skipping invitation ...\n");
			continue;
		}
		node_string[strcspn(node_string, "\r\n")] = '\0';
		log_debug_msg(LOG_DEBUG, "creating internal structure");

		/**
		do you remember the connect string that is printed to stdout and to the log file ?
		you can use it to send join request to other nodes.
		In the example below the 'node_string' must contain exactly this string:

	    .. code-block:: c

		   _LOCK_ACCESS(state)
		   {
		       node_key = np_node_decode_from_str(state, node_string);
		   }

		   log_msg(LOG_DEBUG, "sending join message");
	       np_sendjoin(state, node_key);
		*/
		log_debug_msg(LOG_DEBUG, "creating welcome message");
		np_join(context, node_string);

//		np_new_obj(np_message_t, msg_out);
//		np_tree_t* jrb_me = np_tree_create();
//		np_node_encode_to_jrb(jrb_me, state->my_node_key, false);
//		np_message_create(msg_out, node_key, state->my_node_key, NP_MSG_JOIN_REQUEST, jrb_me);
//
//		log_msg(LOG_DEBUG, "submitting welcome message");
//		np_msgproperty_t* prop = np_msgproperty_get(state, OUTBOUND, NP_MSG_JOIN_REQUEST);
//		_np_job_submit_msg_event(0.0, prop, node_key, msg_out);

		np_time_sleep(1.0);
	}
}
