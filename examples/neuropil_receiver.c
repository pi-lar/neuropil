//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: receiving messages.

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "neuropil.h"

bool authorize(np_context *, struct np_token *);

bool receive(np_context *, struct np_message *);

int main(void) {
  struct np_settings cfg;
  np_default_settings(&cfg);
  strncpy(cfg.log_file, "receiver.log", 255);

  np_context *ac = np_new_context(&cfg);

  assert(np_ok == np_listen(ac, "udp4", "localhost", 3456));

  assert(np_ok == np_run(ac, 0.0));

  assert(np_ok == np_join(ac, "*:udp4:localhost:2345"));

  assert(np_ok == np_set_authorize_cb(ac, authorize));

  np_subject subject_id = {0};
  assert(np_ok == np_generate_subject(&subject_id, "mysubject", 9));

  /**
     The simple receiver example looks very much like the sender we just
     discussed. Instead of sending messages it registers a receive
     callback for messages on the subject ``subject_id`` with
     :c:func:`np_add_receive_cb`.

     .. code-block:: c

     \code
  */
  assert(np_ok == np_add_receive_cb(ac, subject_id, receive));
  /**
     \endcode
  */

  /**
     In its in main loop it simply runs the neurpil event loop
     repeatedly, and handles any error situations by halting.

     .. code-block:: c

     \code
  */
  enum np_return status;
  do
    status = np_run(ac, 5.0);
  while (np_ok == status);

  return status;
  /**
     \endcode
  */
}

bool authorize(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}

/**
   The receive callback interprets the message payload as a string, and prints
   it to standard output.

   .. code-block:: c

   \code
*/
bool receive(np_context *ac, struct np_message *message) {
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  return true;
}
/**
   \endcode
*/
