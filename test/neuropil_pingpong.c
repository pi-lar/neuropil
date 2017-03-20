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
#include "np_msgproperty.h"
#include "np_tree.h"
#include "np_types.h"


#define USAGE "neuropil_receiver_cb [ -j key:proto:host:port ] [ -p protocol] [-b port] [-t worker_thread_count]"
#define OPTSTR "j:p:b:t:"

extern char *optarg;
extern int optind;

/**
right, let's define two callback functions that will be called each time
a ping or pong message is received by the nodes that you are going to start

.. code-block:: c

   np_bool receive_ping(np_tree_t* properties, np_tree_t* body)
   {
*/
static const char* NP_MSG_BODY_TEXT = "_np.text";
static const char* NP_MSG_INST_SEQ  = "_np.seq";

uint32_t _ping_count = 0;
uint32_t _pong_count = 0;

np_bool receive_ping(np_tree_t* properties, np_tree_t* body)
{
	char* text = tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = tree_find_str(properties, NP_MSG_INST_SEQ)->val.value.ul;

	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);

	np_send_text("pong", "pong", _pong_count++);

	return TRUE;
}

np_bool receive_pong(np_tree_t* properties, np_tree_t* body)
{
	char* text = tree_find_str(body, NP_MSG_BODY_TEXT)->val.value.s;
	uint32_t seq = tree_find_str(properties, NP_MSG_INST_SEQ)->val.value.ul;

	log_msg(LOG_INFO, "RECEIVED: %d -> %s", seq, text);

	np_send_text("ping", "ping", _ping_count++);

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
	sprintf(log_file, "%s_%s.log", "./neuropil_pingpong", port);
	int level = LOG_ERROR | LOG_WARN | LOG_INFO;
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
	use the connect string that is printed to stdout and pass it to the np_controller to send a join message.
	wait until the node has received a join message before proceeding

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
	   Make sure that you have implemented and registered the appropiate aaa callback functions
	   to control with which nodes you exchange messages. By default everybody is allowed to interact
	   with your node
	 */
	np_msgproperty_t* ping_props = NULL;
	np_new_obj(np_msgproperty_t, ping_props);
	// ping_props->mode_type = INBOUND | OUTBOUND;
	ping_props->msg_subject = "ping";
	ping_props->ack_mode = ACK_NONE;
	ping_props->ttl = 20.0;
	np_msgproperty_register(ping_props);
	np_set_listener(receive_ping, "ping");

	np_msgproperty_t* pong_props = NULL;
	np_new_obj(np_msgproperty_t, pong_props);
	// pong_props->mode_type = INBOUND | OUTBOUND; // this is already the default
	pong_props->msg_subject = "pong";
	pong_props->ack_mode = ACK_NONE;
	pong_props->ttl = 20.0;
	np_msgproperty_register(pong_props);
	np_set_listener(receive_pong, "pong");


	/**
	register the listener function to receive data from the sender

	.. code-block:: c

	   np_set_listener(receive_this_is_a_test, "this.is.a.test");
	*/

	/**
	loop (almost) forever, you're done :-)

	.. code-block:: c

	   while (1)
	   {
		   ev_sleep(0.9);
	   }
	*/

	// send an initial ping
	np_send_text("ping", "ping", _ping_count++);

	/**
	the loopback function will be triggered each time a message is received
	make sure that you've understood how to alter the message exchange to change
	receiving of message from the default values

 	*/
	while (1)
	{
		ev_sleep(0.9);
	}
}
