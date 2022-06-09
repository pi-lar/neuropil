//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
/**
.. highlight:: c
*/

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "example_helper.c"

#include "neuropil.h"
#include "neuropil_log.h"

#include "np_log.h"

uint32_t _ping_count = 0;
uint32_t _pong_count = 0;

/**
right, let's define two callback functions that will be called each time
a ping or pong message is received by the nodes that you are going to start

The first one is

.. code-block:: c

   \code
*/

bool receive_ping(np_context *context, struct np_message *msg) {
  /**
     \endcode
  */
  char     in_text[5];
  int      text_items = 0;
  uint32_t i          = 0;

  sscanf((char *)msg->data, "%s %" PRIu32, in_text, &i);
  fprintf(stdout, "RECEIVED: %d -> %s\n", i, in_text);

  np_time_sleep(0.01);

  fprintf(stdout, "SENDING: %d -> %s\n", _pong_count++, "pong");

  char *out_text;
  asprintf(&out_text, "%s %" PRIu32, "pong", _pong_count);
  np_send(context, "pong", (uint8_t *)out_text, strlen(out_text) + 1);
  free(out_text);

  fflush(stdout);

  return true;
}
/**
and the second one:

.. code-block:: c

   \code
*/
bool receive_pong(np_context *context, struct np_message *msg) {
  /**
     \endcode
  */
  char     in_text[5];
  int      text_items = 0;
  uint32_t i          = 0;

  sscanf((char *)msg->data, "%s %" PRIu32, in_text, &i);
  fprintf(stdout, "RECEIVED: %d -> %s\n", i, in_text);

  np_time_sleep(0.01);

  fprintf(stdout, "SENDING: %d -> %s\n", _ping_count++, "ping");

  char *out_text;
  asprintf(&out_text, "%s %" PRIu32, "ping", _ping_count);
  np_send(context, "ping", (uint8_t *)out_text, strlen(out_text) + 1);
  free(out_text);

  fflush(stdout);

  return true;
}

int main(int argc, char **argv) {
  int   no_threads = 8;
  char *j_key      = NULL;
  char *proto      = "udp4";
  char *port       = NULL;
  char *hostname   = NULL;
  char *dns_name   = NULL;
  int   level      = -2;
  char *logpath    = ".";

  example_user_context *user_context;
  if ((user_context = parse_program_args(__FILE__,
                                         argc,
                                         argv,
                                         &no_threads,
                                         &j_key,
                                         &proto,
                                         &port,
                                         &hostname,
                                         &dns_name,
                                         &level,
                                         &logpath,
                                         NULL,
                                         NULL)) == NULL) {
    exit(EXIT_FAILURE);
  }

  /**
  in your main program, initialize the logging of neuopil, but this time use the
  port for the filename

  .. code-block:: c

     \code
  */
  struct np_settings *settings = np_default_settings(NULL);
  settings->n_threads          = no_threads;
  /**
     \endcode
  */

  snprintf(settings->log_file,
           255,
           "%s%s_%s.log",
           logpath,
           "/neuropil_pingpong",
           port);
  fprintf(stdout, "logpath: %s\n", settings->log_file);
  settings->log_level = level;

  np_context *context = np_new_context(settings);
  np_set_userdata(context, user_context);

  if (np_ok != np_listen(context, proto, hostname, atoi(port), dns_name)) {
    np_example_print(context,
                     stderr,
                     "ERROR: Node could not listen to %s:%s:%s",
                     proto,
                     hostname,
                     port);
    exit(EXIT_FAILURE);
  }

  /**
     \endcode
  */

  /**
  The port may change due to default setting for NULL,
  so we need to reevaluate the port to print it out later on

  .. code-block:: c

     \code
  */
  // port =  ((np_state_t*)context)->my_node_key->node->port;
  /**
     \endcode
  */

  /**
  Now we need to register this node as interested in "ping" and "pong" messages.
  For this we will configure two message properties with the appropiate
  callbacks to our handlers.

  .. code-block:: c

     \code
  */
  np_add_receive_cb(context, "ping", receive_ping);
  struct np_mx_properties ping_props = np_get_mx_properties(context, "ping");
  ping_props.ackmode                 = NP_MX_ACK_NONE;
  ping_props.message_ttl             = 20.0;
  np_set_mx_properties(context, "ping", ping_props);

  // register the listener function to receive data from the sender
  np_add_receive_cb(context, "pong", receive_pong);
  struct np_mx_properties pong_props = np_get_mx_properties(context, "pong");
  pong_props.ackmode                 = NP_MX_ACK_NONE;
  pong_props.message_ttl             = 20.0;
  np_set_mx_properties(context, "pong", pong_props);
  /**
     \endcode
  */

  // __np_example_helper_loop(context);

  /**
  start up the job queue with 8 concurrent threads competing for job execution.
  you should start at least 2 threads (network io is non-blocking).

  .. code-block:: c

     \code
  */
  if (np_ok != np_run(context, 0)) {
    fprintf(stdout, "ERROR: Node could not start");
    exit(EXIT_FAILURE);
  }
  /**
     \endcode
  */

  /**
  If this is your first start of the program copy the connections string from
  stdout and start a second instance of the program. provide the connection
  string via the -j parameter.

  the next step in the  program is to check if the j_key was provided. if so we
  will try to join the node. If not we will print out the connection string of
  this node and wait for a node to join this network.

  .. code-block:: c

     \code
  */
  if (NULL != j_key) {
    np_join(context, j_key);
  } else {
    fprintf(stdout, "Node waits for connections.\n");
    fprintf(stdout,
            "Please start another node with the following arguments:\n");
    fprintf(stdout, "\n\t-j %s\n", np_get_connection_string(context));
  }

  fprintf(stdout, "Wait for node to connect.\n");
  while (np_has_joined(context) == false) {
    np_run(context, 1.0);
  }
  fprintf(stdout, "Connection established.\n");
  /**
     \endcode
  */

  fprintf(stdout, "Search for pingable nodes.\n");
  while (np_has_receiver_for(context, "ping") == false) {
    np_run(context, 1.0);
  }
  fprintf(stdout, "Pingable node found.\n");

  /**
  .. NOTE::
     Make sure that you have implemented and registered your own aaa callback
  functions to control with which nodes you exchange messages. By default
  everybody is allowed to interact with your node
  */

  log_msg(LOG_INFO, "Sending initial ping");
  // send an initial ping
  char *out_text;
  asprintf(&out_text, "%s %" PRIu32, "ping", 0);
  np_send(context, "ping", (uint8_t *)out_text, strlen(out_text) + 1);
  free(out_text);

  /**
  loop (almost) forever, you're done :-)

  .. code-block:: c

     \code
  */
  while (1) {
    // __np_example_helper_loop(context); // for the fancy ncurse display
    np_run(context, 1.0);
    np_time_sleep(0.01);
  }
  /**
     \endcode
  */
}
