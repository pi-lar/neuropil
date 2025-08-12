//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
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

#include "example_helper.c"

#include "neuropil_log.h"

#include "util/np_tree.h"

#include "np_legacy.h"
#include "np_log.h"
#include "np_message.h"
#include "np_types.h"

/**
first, let's define a callback function that will be called each time
a message is received by the node that you are currently starting

.. code-block:: c

   \code
*/
bool receive_mysubject(np_context *context, struct np_message *msg) {
  /**
  \endcode
  */

  /**
  for this message exchange the message is send as a text element (if you used
  neuropil_sender) otherwise de-serialize and inspect your payload properly into
  structures ...

  .. code-block:: c

  \code
  */
  log_msg(LOG_INFO, msg->uuid, "RECEIVED: %.*s", msg->data_length, msg->data);
  /**
  \endcode
  */

  /**
  return true to indicate successfull handling of the message. if you return
  false the message may get delivered a second time

  .. code-block:: c

  \code
  */
  return true;
}
/**
   \endcode
*/

int main(int argc, char **argv) {
  int   no_threads = 8;
  char *j_key      = NULL;
  char *proto      = "udp4";
  char *port       = NULL;
  char *hostname   = NULL;
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
           "/neuropil_controller",
           port);
  fprintf(stdout, "logpath: %s\n", settings->log_file);
  settings->log_level = level;

  np_context *context = np_new_context(settings);

  if (np_ok != np_listen(context, proto, hostname, atoi(port))) {
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

  if (NULL != j_key) {
    np_join(context, j_key);
  }

  /**
  use the connect string that is printed to stdout and pass it to the
  np_controller to send a join message. wait until the node has received a join
  message before proceeding

  .. code-block:: c

     \code
  */
  while (false == np_has_joined(context))
    assert(np_ok == np_run(context, 0.5));

  /**
     \endcode
  */

  /**
   *.. note::
   *   Make sure that you have implemented and registered the appropiate aaa
   *callback functions to control with which nodes you exchange messages. By
   *default everybody is allowed to interact with your node
   */

  /**
  register the listener function to receive data from the sender

  .. code-block:: c

     \code
  */
  np_add_receive_cb(context, "mysubject", receive_mysubject);
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
  while (1) {
    assert(np_ok == np_run(context, 0.9));
  }
  /**
     \endcode
  */
}
