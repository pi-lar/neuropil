//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
.. NOTE::
   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "neuropil.h"

#include "np_list.h"
#include "example_helper.c"


NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);


bool receive_echo_message(np_context * context, struct np_message*  msg);

/**
The purpose of this program is to start a server for our echo service.
We will wait for incomming messages on the "echo" subject and will return them to the sender.
*/
int main(int argc, char **argv) {

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
        NULL
    )) == NULL) {
        exit(EXIT_FAILURE);
    } 

    /**
    for the general initialization of a node please look into the neuropil_node example
    */

    struct np_settings *settings = np_default_settings(NULL);
    settings->n_threads = no_threads;

	snprintf(settings->log_file, 256, "%s%s_%s.log", logpath, "/neuropil_echo_s", port);
    fprintf(stdout, "logpath: %s\n", settings->log_file);
    settings->log_level = level;

	np_context * context = np_new_context(settings);
	np_set_userdata(context, user_context);
    if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
        np_example_print(context, stderr, "ERROR: Node could not listen to %s:%s:%s",proto, publish_domain, port);
        exit(EXIT_FAILURE);
    }

    /**
    in your main program, initialize the message property for the echo service

    .. code-block:: c

       \code
    */

    np_add_receive_cb(context,  "echo", receive_echo_message);
    struct np_mx_properties msg_props = np_get_mx_properties(context, "echo");
    msg_props.ackmode = NP_MX_ACK_NONE;
    msg_props.message_ttl = 20.0;
    np_set_mx_properties(context,  "echo", msg_props);

    /**
       \endcode

    and add a listener to receive a callback everytime a "echo" message is received.
    finally start the job queue to start processing messages.

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

    while (true) {
        np_run(context, 1.0);
    }
}

/**
Our callback function that will be called each time
a echo message is received by the nodes that you are going to start

.. code-block:: c

   \code
*/
bool receive_echo_message(np_context * context, struct np_message* msg) {
/**
   \endcode
*/

    fprintf(stdout, "%f - RECEIVED", np_time_now());

    /**
    we try to evaluate the source of the message

    .. code-block:: c

       \code
    */
    // np_id reply_to = msg->from;


    /**
       \endcode
    */

	/**
	we evaluate the content and check if we did receive a text message
	to prevent malicious use of the demo service and then
	send the message back to its sender

	.. code-block:: c

	   \code
	*/
	fprintf(stdout, ": \"%.*s\"\n", (int) msg->data_length, msg->data);

	// send the message back
	np_send_to(context, "echo", msg->data, msg->data_length,  &msg->from);
	/**
	   \endcode
	*/
    return true;
}
