//
// neuropil is copyright 2016-2017 by pi-lar GmbH
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
first we have to define a global np_state_t variable

 .. code-block:: c
 \code
*/
np_state_t *state;
/** \endcode */

int seq = -1;
int joinComplete = 0;

int main(int argc, char **argv)
{
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
	in your main program, initialize the logging of neuropil

	.. code-block:: c

	\code
	*/
	char log_file[256];	
	sprintf(log_file, "%s%s_%s.log", logpath, "/neuropil_controller", port);
	np_log_init(log_file, level);
	/** \endcode */


	/**
	initialize the global variable with the np_init function

	.. code-block:: c

	\code
	*/
	state = np_init(proto, port, publish_domain);

	/** \endcode */
	// state->my_node_key->node->joined_network = 1;

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads, because network reading currently is blocking.

	.. code-block:: c

	\code
	*/
	log_debug_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(no_threads);
	/** \endcode */

	/**
	  check stdout and the log file because it will contain this nodes hashvalue / connect string, e.g.

   *.. code-block:: c
   *
   *    2f96848a8c490e0f0f71c74caa900423bcf2d32882a9a0b3510c50085f7ec0e5:udp6:localhost:3333

	*/

	/**
	and finally loop (almost) forever

	*.. code-block:: c
	*
	*   while (1) {
	*       ev_sleep(1.0);
	*   }
	*/

	/**
	your're done ... if you plan to connect your nodes to this controller as a bootstrap node.

	The created process can be contacted by other nodes and will forward messages as required.
	By default the authentication / authorization / accounting handler accept nodes/message request
	from everybody.

   *.. note::
	 *
	 *  Make sure that you implement and register the appropiate aaa callback functions
	 *  to control with which nodes you exchange messages. By default everybody is allowed to interact
	 *  with your node
	*/

	if(j_key != NULL){
		np_send_join(j_key);
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

	  *.. code-block:: c
		*
		*   _LOCK_ACCESS(state)
		*  {
		*       node_key = np_node_decode_from_str(state, node_string);
		*  }
		*
		*  log_msg(LOG_DEBUG, "sending join message");
	*      np_sendjoin(state, node_key);
		*/
		log_debug_msg(LOG_DEBUG, "creating welcome message");
		np_send_join(node_string);

//		np_new_obj(np_message_t, msg_out);
//		np_tree_t* jrb_me = np_tree_create();
//		np_node_encode_to_jrb(jrb_me, state->my_node_key, FALSE);
//		np_message_create(msg_out, node_key, state->my_node_key, NP_MSG_JOIN_REQUEST, jrb_me);
//
//		log_msg(LOG_DEBUG, "submitting welcome message");
//		np_msgproperty_t* prop = np_msgproperty_get(state, OUTBOUND, NP_MSG_JOIN_REQUEST);
//		_np_job_submit_msg_event(0.0, prop, node_key, msg_out);

		ev_sleep(1.0);
	}
}
