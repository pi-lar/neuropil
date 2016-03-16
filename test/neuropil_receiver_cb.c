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

#include "event/ev.h"
#include "include.h"

#include "log.h"
#include "dtime.h"
#include "neuropil.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_msgproperty.h"

#define USAGE "neuropil_receiver_cb [ -j bootstrap:port ] [ -p protocol] [-b port]"
#define OPTSTR "j:p:b:"

#define DEBUG 0
#define NUM_HOST 120

extern char *optarg;
extern int optind;

/**
first we have to define a global np_state_t variable

.. code-block:: c

   np_state_t *state;
*/
np_state_t *state;

/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c

   np_bool receive_this_is_a_test(np_jtree_t* properties, np_jtree_t* body)
   {
*/
np_bool receive_this_is_a_test(np_jtree_t* properties, np_jtree_t* body)
{
	/**
	for this message exchange the message is send as a text element (if you used np_send_text)
	otherwise inspect the properties and payload np_jtree_t structures ...

    .. code-block:: c

	      char* subject = jrb_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	*/
	char* text = jrb_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	log_msg(LOG_DEBUG, "RECEIVED: %s", text);

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
	char *b_hn = NULL;
	char* b_port = NULL;
	char* proto = NULL;
	char* port = NULL;
	int i;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
	{
		switch ((char) opt)
		{
		case 'j':
			for (i = 0; optarg[i] != ':' && i < strlen(optarg); i++);
			optarg[i] = 0;
			b_hn = optarg;
			b_port = optarg + (i+1);
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
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_MESSAGE;
	// int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	log_init(log_file, level);

	/**
	initialize the global variable with the np_init function

	.. code-block:: c

	   state = np_init(proto, port);
	*/
	state = np_init(proto, port, FALSE);

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads, because network reading currently is blocking.

	.. code-block:: c

	   np_start_job_queue(state, 8);
	*/
	log_msg(LOG_DEBUG, "starting job queue");
	np_start_job_queue(state, 8);

	/**
	wait until the node has received a join message before actually proceeding

	.. code-block:: c

	   np_waitforjoin(state);
	*/
	np_waitforjoin(state);

	/**
	.. note::
	   Make sure that you implement and register the appropiate aaa callback functions
	   to control with which nodes you exchange messages. By default everybody is allowed to interact
	   with your node
	 */

	/**
	register the listener function to receive data from the other side

	.. code-block:: c

	   np_set_listener(state, receive_this_is_a_test, "this.is.a.test");
	*/
	np_set_listener(state, receive_this_is_a_test, "this.is.a.test");

	/**
	loop (almost) forever, you're done :-)

	the loopback function will be triggered each time a message is received
	make sure that you've understood how to alter the message exchange to change
	receiving of message from the default values

	.. code-block:: c

	   while (1)
	   {
		   dsleep(0.9);
	   }
 	*/
	while (1)
	{
		ev_sleep(0.9);
		// dsleep(0.9);
	}
}
