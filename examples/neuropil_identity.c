//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: loading and saving identies and key material

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "neuropil.h"

#include "identity/np_identity.h"
#include "identity/np_keystore.h"

#include "np_legacy.h"

/**
   let's create one keystore, for authorizations and for authentication token

   .. code-block:: c

   \code
*/
static np_id authnz_keystore_id = {0};
/**
   \endcode
*/

bool authenticate(np_context *, struct np_token *);

bool authorize(np_context *, struct np_token *);

bool receive(np_context *, struct np_message *);

int main(void) {
  struct np_settings cfg;
  np_default_settings(&cfg);
  cfg.log_level = LOG_INFO | LOG_ERROR | LOG_WARNING | LOG_DEBUG | LOG_MISC;
  strncpy(cfg.log_file, "neuropil_identity.log", 255);

  np_context *context = np_new_context(&cfg);

  struct np_token my_identity =
      np_new_identity(context, np_time_now() + 86400, NULL);
  /**
     create the hash value for a very looong password
     a better way: use KDF functions or shared secrets as passphrases to encrypt
     keys and token !

     .. code-block:: c

     \code
  */
  np_id       passphrase_id = {0};
  const char *passphrase    = "ellenlangepassphrase";
  np_get_id(&passphrase_id, passphrase, strnlen(passphrase, 32));
  /**
     \endcode
  */

  /**
     create a secret key file in the current directory, filename is ".npid"

     ..code-block::c

     \code
  */
  np_identity_create_secretkey(context, "./", passphrase_id);
  /**
     \endcode
  */

  /**
     load the secret key from the file into our identity

     ..code-block::c

     \code
  */
  np_id my_id = {0};
  np_identity_load_secretkey(context,
                             "./",
                             &my_id,
                             passphrase_id,
                             &my_identity);
  /**
      \endcode
  */

  /**
     Next modify your identity as desired

     ..code-block::c

     \code
  */
  // e.g. push in a mail address
  memset(my_identity.subject, 0, 255);
  strncpy(my_identity.subject, "me@example.com", 15);
  // e.g. set a realm (any kind of grouping you would like to use)
  np_get_id(&my_identity.realm, "example.com", 11);
  // e.g. set expiry time to a higher value
  my_identity.expires_at = np_time_now() + 86400 * 2;
  // e.g. set the first-usage time to one hour in the future
  my_identity.not_before = np_time_now() + 3600;
  /**
     \endcode
  */

  /**
     make sure that the signature and thus the fingerprint is up-to-date

     ..code-block::c

     \code
  */
  np_id identity_fp = {0};
  np_sign_identity(context, &my_identity, true);
  np_token_fingerprint(context, my_identity, false, &identity_fp);
  /**
     \endcode
  */

  /**
     store the secret key again with the correct identifier, our fingerprint

    ..code-block::c

    \code
  */
  np_identity_save_secretkey(context, "./", passphrase_id, &my_identity);
  /**
     \endcode
  */

  /**
     save our identity to a file in a specific directory, filename is
     generated based on the fingerprint of teh token

     ..code-block::c

     \code
  */
  np_identity_save_token(context, "./", passphrase_id, &my_identity);
  /**
     \endcode
  */

  /**
     from now on we can load the secret key and we know which token file is ours

     ..code-block::c

     \code
  */
  np_id check_identity_fp = {0};
  np_identity_load_secretkey(context,
                             "./",
                             &check_identity_fp,
                             passphrase_id,
                             &my_identity);
  /**
     \endcode
  */

  /**
  re-create the token filename, unless you know the filename that you would
  like to load create the filename

  ..code-block::c

     \code
  */
  char filename[79];
  char identity_fp_str[65] = {0};
  np_id_str(identity_fp_str, check_identity_fp);
  snprintf(filename, 75, "np:npt:%s", identity_fp_str);
  /**
     \endcode
  */

  /**
     load the identity token from the file into the context

     ..code-block::c

     \code
  */
  np_identity_load_token(context,
                         "./",
                         check_identity_fp,
                         passphrase_id,
                         &my_identity);
  /**
     \endcode
  */

  /**
     \endcode
  */

  /**
     and now continue with the usual things to send / receive data

     The simple receiver example looks very much like the sender we just ...

     ..code-block::c

     \code
  */
  assert(np_ok == np_listen(context, "udp4", "localhost", 3456));

  /**
   We need to give the keystore m a unique identifier, so we only use hash
   value of a random string. With this initializer we init the keystore and
   protect it with the same passphrase.
   afterwards, we can load all identities stored in the keystore, so that they
   are available in memory
   make sure to handle the return code of np_keystore_load_identites, it will
   return np_invalid_operation on an empty file.

   .. code-block:: c

   \code
*/
  np_get_id(&authnz_keystore_id, "np:authnz:keystore", 18);
  assert(np_ok ==
         np_keystore_init(context, authnz_keystore_id, "./", passphrase_id));
  np_keystore_load_identities(context, authnz_keystore_id);

  assert(np_ok == np_set_authenticate_cb(context, authenticate));
  assert(np_ok == np_set_authorize_cb(context, authorize));
  assert(np_ok == np_run(context, 0.0));
  assert(np_ok == np_join(context, "*:udp4:localhost:2345"));

  np_subject subject_id = {0};
  assert(np_ok == np_generate_subject(&subject_id, "mysubject", 9));
  /**
     \endcode
  */

  assert(np_ok == np_add_receive_cb(context, subject_id, receive));
  enum np_return status;
  do
    status = np_run(context, 5.0);
  while (np_ok == status);

  return status;
}

bool authenticate(np_context *ac, struct np_token *id) {
  /**
     The authentication callback uses a token and stores it in it's keystore

     .. code-block:: c

     \code
  */
  if (np_ok == np_keystore_check_identity(ac, authnz_keystore_id, id)) {
    return true;
  } else {
    np_keystore_store_identity(ac, authnz_keystore_id, id);
  }

  /**
     \endcode
  */
  return false;
}

bool authorize(np_context *ac, struct np_token *id) {
  /**
     The authorize callback uses a token and stores it in it's keystore

     .. code-block:: c

     \code
  */
  if (np_ok == np_keystore_check_identity(ac, authnz_keystore_id, id)) {
    return true;
  } else {
    np_keystore_store_identity(ac, authnz_keystore_id, id);
  }
  return false;
  /**
     \endcode
  */
}

bool receive(np_context *ac, struct np_message *message) {
  printf("Received: %.*s\n", (int)message->data_length, message->data);
  return true;
}
