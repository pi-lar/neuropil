//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
/**
.. NOTE::
   If you are not yet familiar with the neuropil initialization procedure please refer to the :ref:`tutorial`
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"

#include "np_log.h"
#include "np_types.h"
#include "np_list.h"
#include "np_util.h"
#include "np_memory.h"

#include "np_message.h"
#include "np_msgproperty.h"
#include "np_keycache.h"
#include "np_tree.h"

#include "neuropil.h"

#include "example_helper.c"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);


bool receive_echo_message(np_context * context, const np_message_t* const msg, np_tree_t* body, void* localdata);

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
    for the general initialization of a node please look into the neuropil_node example
    */

    struct np_settings *settings = np_default_settings(NULL);
    settings->n_threads = no_threads;

	snprintf(settings->log_file, 256, "%s%s_%s.log", logpath, "/neuropil_controller", port);
    fprintf(stdout, "logpath: %s\n", settings->log_file);
    settings->log_level = level;

    np_context * context = np_new_context(settings);

    if (np_ok != np_listen(context, proto, publish_domain, atoi(port))) {
        printf("ERROR: Node could not listen");
        exit(EXIT_FAILURE);
    }

    /**
    in your main program, initialize the message property for the echo service

    .. code-block:: c

       \code
    */

    np_msgproperty_t* msg_props = NULL;
    np_add_receive_listener(context, receive_echo_message, NULL, "echo");
    msg_props = np_msgproperty_get(context, INBOUND, "echo");
    msg_props->msg_subject = strndup("echo", 255);
    msg_props->ack_mode = ACK_NONE;
    msg_props->msg_ttl = 20.0;
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
        np_time_sleep(0.1);
    }
}

/**
Our callback function that will be called each time
a echo message is received by the nodes that you are going to start

.. code-block:: c

   \code
*/
bool receive_echo_message(np_context * context, const np_message_t* const msg, np_tree_t* body, void* localdata) {
/**
   \endcode
*/

    np_tree_t* header = msg->header;
    fprintf(stdout, "%f - RECEIVED", np_time_now());

    /**
    we try to evaluate the source of the message

    .. code-block:: c

       \code
    */
    np_id reply_to = { 0 }; // All
    np_tree_elem_t* repl_to = np_tree_find_str(header, _NP_MSG_HEADER_FROM);
    if (NULL != repl_to) {
        memcpy(&reply_to, &repl_to->val.value.dhkey, NP_FINGERPRINT_BYTES);
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
        char* text;
        np_tree_elem_t* txt = np_tree_find_str(body, NP_MSG_BODY_TEXT);
        if (NULL != txt) {
            text = np_treeval_to_str(txt->val, NULL);

        } else {
            text = "<NON TEXT MSG>";
        }
        fprintf(stdout, ": \"%s\"\n", text);
        // send the message back
        np_send_text(context, "echo", text, 0,  &reply_to);
        /**
           \endcode
        */
    }
    return true;
}
