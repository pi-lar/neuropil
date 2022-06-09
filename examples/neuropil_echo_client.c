//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
/**
 .. NOTE::
    If you are not yet familiar with the neuropil initialization procedure
 please refer to the :ref:`tutorial`
*/
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "example_helper.c"

#include "neuropil.h"
#include "neuropil_log.h"

#include "util/np_list.h"

#include "np_log.h"

NP_SLL_GENERATE_PROTOTYPES(int);
NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(int);
NP_SLL_GENERATE_IMPLEMENTATION(int);

bool receive_message(np_context *context, struct np_message *msg);

/**
The purpose of this program is to start a client for our echo service.
We will periodically call our echo server with a message
and if everything goes as expected we will receive the same message
from the server.
*/
int main(int argc, char **argv) {
  int   no_threads = 8;
  char *j_key      = NULL;
  char *proto      = "udp4";
  char *port       = NULL;
  char *hostname   = NULL;
  char *dns_name   = NULL;
  int   level      = -2;
  char *logpath    = ".";
  /**
  The default value for the message we like to send is "Hello World! {x}"
  {x} will be replaced by a increasing number.
  If you like to send your own message you can
  call the programm with the "-m <string>" parameter.
  */

  char *message_to_send_org = "Hello World!";
  char *message_to_send     = message_to_send_org;

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
                                         "[-m message_to_send]",
                                         "m:",
                                         &message_to_send

                                         )) == NULL) {
    exit(EXIT_FAILURE);
  }
  bool j_key_provided   = j_key != NULL;
  int  retry_connection = 3;
  bool add_id_to_msg    = strcmp(message_to_send, message_to_send_org) == 0;

  /**
  We create our node,

  .. code-block:: c

  \code
  */
  struct np_settings *settings = np_default_settings(NULL);
  settings->n_threads          = no_threads;

  snprintf(settings->log_file,
           255,
           "%s%s_%s.log",
           logpath,
           "/neuropil_echo_c",
           port);
  fprintf(stdout, "logpath: %s\n", settings->log_file);
  settings->log_level = level;

  np_context *ac = np_new_context(settings);
  np_set_userdata(ac, user_context);
  np_ctx_cast(ac);

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
  and join to our bootstrap node
  (either the default localhost or a node provided by parameter)

  .. code-block: c

  \code
  */
  while (np_ok == np_run(context, 0.1)) {
    fprintf(stdout, "try to join bootstrap node\n");
    if (false == j_key_provided) {
      j_key = calloc(1, 255 * sizeof(char));
      snprintf(j_key, 255, "*:%s:localhost:3333", proto);
    }

    np_join(context, j_key);
    if (true == np_has_joined(context)) {
      fprintf(stdout, "%s joined network!\n", port);
      break;
    } else {
      fprintf(stdout, "%s could not join network!\n", port);
    }
  }
  /**
  \endcode
  */

  /**
  and initialize the message property for the echo service

  .. code-block:: c

  \code
  */
  struct np_mx_properties msg_props = np_get_mx_properties(context, "echo");
  msg_props.ackmode                 = NP_MX_ACK_NONE;
  msg_props.message_ttl             = 20.0;
  np_set_mx_properties(ac, "echo", msg_props);
  np_add_receive_cb(context, "echo", receive_message);
  /**
  \endcode
  */

  /**
  to add a listener to receive a callback every time a "echo" message is
  received. finally start the jobqueue to start processing messages.

  .. code-block:: c

  \code
  */
  __np_example_helper_loop(context);
  if (np_ok != np_run(context, 0)) {
    printf("ERROR: Node could not start");
    exit(EXIT_FAILURE);
  } /**
\endcode
*/

  /**
  And now we can send, periodically, our message to our bootstrap node.

  .. code-block:: c

  \code
  */
  uint32_t i = 0;
  while (true == np_has_joined(context)) {

    __np_example_helper_loop(context);

    if (i++ % 50 == 0) {
      char *s_out;
      if (add_id_to_msg) {
        asprintf(&s_out, "%s %" PRIu32, message_to_send, i / 50);
      } else {
        asprintf(&s_out, "%s", message_to_send);
      }

      fprintf(stdout, "%f - SENDING:  \"%s\"\n", np_time_now(), s_out);
      log_msg(LOG_INFO, "SENDING:  \"%s\"", s_out);

      // Send our message
      np_send(context, "echo", s_out, strlen(s_out));
      free(s_out);
    }
    np_run(context, 0.12);
  }
  /**
  \endcode
  */
}

/**
If  we receive a message for the "echo" subject we now get a callback to this
function

.. code-block:: c

   \code
*/
bool receive_message(np_context *context, struct np_message *msg) {
  /**
     \endcode
  */
  /**
  We can now handle the message an can access
  the payload via the body tree structure.

  .. code-block:: c

     \code
  */

  fprintf(stdout,
          "%f - RECEIVED: \"%.*s\" \n",
          np_time_now(),
          (int)msg->data_length,
          (char *)msg->data);
  /**
     \endcode
  */

  /**
  To signal the network a completely processed message
  (no resends necessary) we return a true value to our caller.

  .. code-block:: c

     \code
  */
  return true;
  /**
     \endcode
  */
}
