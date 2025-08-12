//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: sending messages.

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/**
   First and foremost, we have to include header file which defines the API for
   the neuropil cybersecurity mesh.

   .. code-block:: c

   \code
*/
#include "neuropil.h"
/**
   \endcode
*/

bool authorize(np_context *, struct np_token *);

int main(void) {
  /**
     To initialize the neuropil cybersecurity mesh, we prepare a
     :c:type:`np_settings` by populating it with the default settings
     using :c:func:`np_default_settings`, and create a new
     application context with :c:func:`np_new_context`.

     .. code-block:: c

     \code
  */
  struct np_settings cfg;
  np_default_settings(&cfg);
  strncpy(cfg.log_file, "sender.log", 255);

  np_context *ac = np_new_context(&cfg);
  /**
     \endcode
  */

  /**
     Next, we allocate a network address and port tuple to listen on for
     incoming connections using :c:func:`np_listen`.

     .. code-block:: c

     \code
   */
  assert(np_ok == np_listen(ac, "udp4", "localhost", 1234));
  /**
     \endcode
  */

  assert(np_ok == np_run(ac, 0.0));

  /**
     To join a neuropil network, we have to connect with our initial
     bootstrap node using :c:func:`np_join`. Other nodes in the network
     will be discovered automatically, but we need explicitly specify the
     network address and port tuple for our initial contact.

     .. code-block:: c

     \code
   */
  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));
  /**
     \endcode
  */

  /**
     We should also set an authorization callback via
     :c:func:`np_set_authorize_cb` to control access to this node. More
     on this later.

     .. code-block:: c

     \code
   */
  assert(np_ok == np_set_authorize_cb(ac, authorize));
  /**
     \endcode
  */

  /**
     We also need to convert our human readable subject string
     into an :c:type:np_subject instance.
     This can be done via :c:func:`np_generate_subject`.

     .. code-block:: c

     \code
   */
  np_subject subject_id = {0};
  assert(np_ok == np_generate_subject(&subject_id, "mysubject", 9));
  /**
     \endcode
  */

  /**
     Now to our application logic. We will repeatedly run the neuropil
     event loop with :c:func:`np_run`, and then send our user defined
     message with the ``subject_id`` using :c:func:`np_send`. If
     anything goes wrong we return the error code (an
     :c:type:`np_return`.)

     Effectively, this means that our node will process protocol requests
     continuously (for as long as there is no error situation) and send a
     message every five seconds periodically.

     .. code-block:: c

     \code
   */
  enum np_return status;
  uint64_t       _i = 0;
  do {
    status = np_run(ac, 1.0);
    char message[100];
    // printf("Enter message (max 100 chars): ");
    // fgets(message, 200, stdin);
    snprintf(message, 100, "msg %" PRIu64, _i++);
    sleep(0.01);
    // Remove trailing newline
    if ((strlen(message) > 0) && (message[strlen(message) - 1] == '\n'))
      message[strlen(message) - 1] = '\0';
    size_t message_len = strlen(message);
    np_send(ac, subject_id, message, message_len);
    printf("Sent: %s\n", message);
  } while (np_ok == status);

  return status;
  /**
     \endcode
  */
}

/**
   All that is left is to implement our authorization callback, a function of
   type :c:type:`np_aaa_callback`. The one defined is eternally lenient, and
   authorizes every peer to receive our messages. To ensure that our message is
   not read by strangers, it should really return :c:data:`false` for
   :c:type:`np_token` of unknown identities.

   .. code-block:: c

   \code
*/
bool authorize(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is the intended recipient!
  return true;
}
/**
   \endcode
*/
