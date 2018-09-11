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

/**
.. highlight:: c
*/

#include "np_log.h"
#include "np_legacy.h"
#include "np_tree.h"
#include "np_types.h"
#include "np_message.h"

#include "example_helper.c"

  
/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c

   \code
*/
bool receive_this_is_a_test(np_context* context, const np_message_t* const msg, np_tree_t* body, void* localdata)
{
/**
\endcode
*/

/**
for this message exchange the message is send as a text element (if you used np_send_text)
otherwise inspect the properties and payload np_tree_t structures ...

.. code-block:: c

\code
*/
    char* text = np_treeval_to_str(np_tree_find_str(body, NP_MSG_BODY_TEXT)->val, NULL);
/**
\endcode
*/
    log_msg(LOG_INFO, "RECEIVED: %s", text);

/**
return true to indicate successfull handling of the message. if you return false
the message may get delivered a second time

.. code-block:: c

\code
*/
    return true;
}
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

	example_user_context* user_context;
	if ((user_context = parse_program_args(
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
		NULL)) == NULL) {
		exit(EXIT_FAILURE);
	}
	
	/**
	in your main program, initialize the logging of neuopil, but this time use the port for the filename

	.. code-block:: c

	   \code
	*/
	struct np_settings *settings = np_default_settings(NULL);
	settings->n_threads = no_threads;
	/**
	   \endcode
	*/

	snprintf(settings->log_file, 255, "%s%s_%s.log", logpath, "/neuropil_controller", port);
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
	   

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads (network io is non-blocking).

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
	wait until the node has received a join message before proceeding

	.. code-block:: c

	   \code
	*/
	np_waitforjoin(context);
	/**
	   \endcode
	*/

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
	np_add_receive_listener(context, receive_this_is_a_test,NULL,  "this.is.a.test");
	/**
	   \endcode
	*/


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
		np_time_sleep(0.9);
	}
	/**
	   \endcode
	*/
}
