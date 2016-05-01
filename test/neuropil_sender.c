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
#include "np_types.h"

#define USAGE "neuropil_sender [ -j bootstrap:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
extern int optind;

/**
first we have to define a global np_state_t variable

.. code-block:: c

   np_state_t *state;
*/
np_state_t *state;


int main(int argc, char **argv)
{
	int opt;
	int no_threads = 2;
	char *j_key = NULL;
	char* proto = NULL;
	char* port = NULL;

	while ((opt = getopt(argc, argv, OPTSTR)) != EOF) {
		switch ((char) opt) {
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
		default:
			fprintf(stderr, "invalid option %c\n", (char) opt);
			fprintf(stderr, "usage: %s\n", USAGE);
			exit(1);
		}
	}

	/**
	in your main program, initialize the logging of neuopil, use the port for the filename

	.. code-block:: c

	   char log_file[256];
	   sprintf(log_file, "%s_%d.log", "./neuropil_node", port);
	   int level = LOG_ERROR | LOG_WARN | LOG_INFO;
	   log_init(log_file, level);
	*/
	char log_file[256];
	sprintf(log_file, "%s_%s.log", "./neuropil_node", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG;
	np_log_init(log_file, level);

	/**
	initialize the global variable with the np_init function. the last argument
	defines if you would like to have simplistic http interface on port 31415

	.. code-block:: c

	   state = np_init(proto, port, FALSE);
	*/
	state = np_init(proto, port, FALSE);

	/**
	start up the job queue with 8 concurrent threads competing for job execution.
	you should start at least 2 threads, because network reading currently is blocking.

	.. code-block:: c

	   np_start_job_queue(8);
	*/
	np_start_job_queue(no_threads);

	if (NULL != j_key)
	{
		np_sendjoin(j_key);
	}

	/**
	wait until the node has received a join message before actually proceeding

	.. code-block:: c

	   np_waitforjoin();
	*/
	np_waitforjoin();

	/**
	.. note::
	   Make sure that you implement and register the appropiate aaa callback functions
	   to control with which nodes you exchange messages. By default everybody is allowed to interact
	   with your node
	 */

	/**
	create the message that you would like to send across (now or in the loop later)

	.. code-block:: c

	   char* msg_subject = "this.is.a.test";
	   char* msg_data = "testdata";
	   unsigned long k = 1; // send across a sequence number
	*/
	char* msg_subject = "this.is.a.test";
	char* msg_data = "testdata";
	unsigned long k = 1;

	/**
	loop (almost) forever and send your messages to your receiver :-)

	.. code-block:: c

	   while (1)
	   {
	      ev_sleep(1.0);
		  np_send_text(state, msg_subject, msg_data, k);
		  k++;
	   }
 	*/
	while (1) {

		ev_sleep(1.0);

		np_send_text(msg_subject, msg_data, k);
		log_msg(LOG_DEBUG, "send message %lu", k);

		k++;
	}
}
