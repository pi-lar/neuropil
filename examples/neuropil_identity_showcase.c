//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// Example: loading and saving identies and key material

#include <assert.h>
#include <glob.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "neuropil.h"

#include "identity/np_identity.h"
#include "identity/np_keystore.h"

#include "np_legacy.h"

/**
   let's create one keystore, for authorizations and for authentication token

   .. code-block:: c

   \code
*/
static np_id controller_authnz_keystore_id = {0};
static np_id robot_authnz_keystore_id      = {0};
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
  strncpy(cfg.log_file,
          "/home/remotes/selmanoeztuerk/Repository/Neuropil/Robot-Showcase/"
          "neuropil_identity_showcase.log",
          255);

  np_context *context = np_new_context(&cfg);

  struct np_settings controller_cfg;
  np_default_settings(&controller_cfg);
  controller_cfg.log_level =
      LOG_INFO | LOG_ERROR | LOG_WARNING | LOG_DEBUG | LOG_MISC;
  strncpy(controller_cfg.log_file,
          "/home/remotes/selmanoeztuerk/Repository/Neuropil/Robot-Showcase/"
          "Controller/"
          "controller.log",
          255);

  np_context *controller_context = np_new_context(&controller_cfg);

  struct np_settings robot_cfg;
  np_default_settings(&robot_cfg);
  robot_cfg.log_level =
      LOG_INFO | LOG_ERROR | LOG_WARNING | LOG_DEBUG | LOG_MISC;
  strncpy(
      robot_cfg.log_file,
      "/home/remotes/selmanoeztuerk/Repository/Neuropil/Robot-Showcase/Robot/"
      "robot.log",
      255);

  np_context *robot_context = np_new_context(&robot_cfg);

  struct np_token controller_identity   = {0};
  struct np_token robot_identity        = {0};
  struct np_token manufacturer_identity = {0};
  /**
     create the hash value for a very looong password
     a better way: use KDF functions or shared secrets as passphrases to encrypt
     keys and token !

     .. code-block:: c

     \code

  */

  np_id controller_passphrase_id         = {0};
  char  controller_passwort[]            = {0};
  char  controller_passphrase_id_str[65] = {0};
  printf("Geben Sie ein Passwort für den Controller an\n");
  gets_s(controller_passwort, 64);
  printf("%s\n", controller_passwort);
  const char *controller_passphrase = controller_passwort;
  np_get_id(&controller_passphrase_id,
            controller_passphrase,
            strnlen(controller_passphrase, 32));
  np_id_str(controller_passphrase_id_str, controller_passphrase_id);
  printf("Passphrase id str: %s\n", controller_passphrase_id_str);

  np_id robot_passphrase_id         = {0};
  char  robot_passwort[]            = {0};
  char  robot_passphrase_id_str[65] = {0};
  printf("Geben Sie ein Passwort für den Robot an\n");
  gets_s(robot_passwort, 64);
  printf("%s\n", robot_passwort);
  const char *robot_passphrase = robot_passwort;
  np_get_id(&robot_passphrase_id,
            robot_passphrase,
            strnlen(robot_passphrase, 32));
  np_id_str(robot_passphrase_id_str, robot_passphrase_id);
  printf("Robot Passphrase id str: %s\n", robot_passphrase_id_str);

  /**
     \endcode
  */
  np_id check_identity_fp      = {0};
  np_id identity_fp            = {0};
  np_id controller_identity_fp = {0};

  char filename[79];
  char identity_fp_str[65] = {0};
  np_id_str(identity_fp_str, check_identity_fp);
  snprintf(filename, 75, "np:npt:%s", identity_fp_str);

  int controller_secretkey_return_value =
      np_identity_load_secretkey(controller_context,
                                 "/home/remotes/selmanoeztuerk/Repository/"
                                 "Neuropil/Robot-Showcase/Controller",
                                 &check_identity_fp,
                                 controller_passphrase_id,
                                 &controller_identity);

  /**
     load the identity token from the file into the context

     ..code-block::c

     \code
  */
  int controller_token_return_value =
      np_identity_load_token(controller_context,
                             "/home/remotes/selmanoeztuerk/Repository/Neuropil/"
                             "Robot-Showcase/Controller",
                             check_identity_fp,
                             controller_passphrase_id,
                             &controller_identity);

  int robot_secretkey_return_value = np_identity_load_secretkey(
      robot_context,
      "/home/remotes/selmanoeztuerk/Repository/Neuropil/Robot-Showcase/Robot",
      &check_identity_fp,
      robot_passphrase_id,
      &robot_identity);

  int robot_token_return_value = np_identity_load_token(
      robot_context,
      "/home/remotes/selmanoeztuerk/Repository/Neuropil/Robot-Showcase/Robot",
      check_identity_fp,
      robot_passphrase_id,
      &robot_identity);

  printf(
      "Controller Tokenload return value: %d\nController Secretkey return "
      "value: %d\nRobot Tokenload return value: %d\nRobot Secretkey return "
      "value: %d\n",
      controller_token_return_value,
      controller_secretkey_return_value,
      robot_token_return_value,
      robot_secretkey_return_value);

  /**
     \endcode


     \code
  */
  // e.g. push in a mail address
  struct stat buffer;
  bool        file_stat = stat(
                       "/home/remotes/selmanoeztuerk/Repository/Neuropil/"
                              "Robot-Showcase/Controller/.npid",
                       &buffer) == 0
                              ? true
                              : false;
  if (file_stat == true) {
    printf("Datei existiert.\n");
    if (controller_secretkey_return_value == 1) {
      printf("Secretkey konnte nicht geladen werden.\n");
    }
    if (controller_token_return_value == 1) {
      printf("Identity Token konnte nicht geladen werden.\n");
    }
  } else {

    // creation of controller identity

    controller_identity =
        np_new_identity(controller_context, np_time_now() + 86400, NULL);
    memset(controller_identity.subject, 0, 255);
    strncpy(controller_identity.subject, "Roboter-Inhaber", 16);
    // e.g. set a realm (any kind of grouping you would like to use)
    np_get_id(&controller_identity.realm, "neuropil.io", 11);
    // e.g. set expiry time to a higher value
    controller_identity.expires_at = np_time_now() + 86400 * 120;
    // e.g. set the first-usage time to one hour in the future
    controller_identity.not_before = np_time_now();

    np_sign_identity(controller_context, &controller_identity, true);
    np_token_fingerprint(controller_context,
                         controller_identity,
                         false,
                         &identity_fp);
    np_token_fingerprint(controller_context,
                         controller_identity,
                         false,
                         &controller_identity_fp);
    char controller_identity_fp_str[65] = {0};
    np_id_str(controller_identity_fp_str, controller_identity_fp);
    printf("Controller FP: \t%s\n", controller_identity_fp_str);

    np_identity_save_token(controller_context,
                           "/home/remotes/selmanoeztuerk/Repository/"
                           "Neuropil/Robot-Showcase/Controller",
                           controller_passphrase_id,
                           &controller_identity);
    np_identity_save_secretkey(controller_context,
                               "/home/remotes/selmanoeztuerk/Repository/"
                               "Neuropil/Robot-Showcase/Controller",
                               controller_passphrase_id,
                               &controller_identity);

    // creation of robot identity

    int controller_identity_fp_str_len = strlen(controller_identity_fp_str);
    robot_identity =
        np_new_identity(robot_context, np_time_now() + 86400, NULL);
    memset(robot_identity.subject, 0, 255);
    strncpy(robot_identity.subject, "Roboter", 8);
    // e.g. set a realm (any kind of grouping you would like to use)

    memcpy(robot_identity.realm,
           &controller_identity_fp,
           (NP_FINGERPRINT_BYTES));
    char robot_realm_str[] = {0};
    np_id_str(robot_realm_str, robot_identity.realm);
    printf("Robot realm: \t%s\n", robot_realm_str);

    // e.g. set expiry time to a higher value
    robot_identity.expires_at = np_time_now() + 86400 * 120;
    // e.g. set the first-usage time to one hour in the future
    robot_identity.not_before = np_time_now();

    np_sign_identity(robot_context, &robot_identity, true);
    np_token_fingerprint(robot_context, robot_identity, false, &identity_fp);

    np_identity_save_token(robot_context,
                           "/home/remotes/selmanoeztuerk/Repository/"
                           "Neuropil/Robot-Showcase/Robot",
                           robot_passphrase_id,
                           &robot_identity);
    np_identity_save_secretkey(robot_context,
                               "/home/remotes/selmanoeztuerk/Repository/"
                               "Neuropil/Robot-Showcase/Robot",
                               robot_passphrase_id,
                               &robot_identity);

    assert(np_ok ==
           np_listen(controller_context, "udp4", "localhost", 3456, NULL));

    np_get_id(&controller_authnz_keystore_id, "np:authnz:keystore", 18);
    np_keystore_init(controller_context,
                     controller_authnz_keystore_id,
                     "/home/remotes/selmanoeztuerk/Repository/"
                     "Neuropil/Robot-Showcase/Controller/",
                     controller_passphrase_id);

    np_keystore_load_identities(controller_context,
                                controller_authnz_keystore_id);

    int keystore_destroy =
        np_keystore_destroy(controller_context, controller_authnz_keystore_id);
    printf("Keystore destroy: %d\n", keystore_destroy);

    assert(np_ok == np_listen(robot_context, "udp4", "localhost", 3456, NULL));
    np_get_id(&robot_authnz_keystore_id, "np:authnz:keystore", 18);
    np_keystore_init(robot_context,
                     robot_authnz_keystore_id,
                     "/home/remotes/selmanoeztuerk/Repository/"
                     "Neuropil/Robot-Showcase/Robot/",
                     robot_passphrase_id);
    np_keystore_load_identities(robot_context, robot_authnz_keystore_id);
  }

  return 0;
}

bool authenticate(np_context *ac, struct np_token *id) {

  /**
     The authentication callback uses a token and stores it in it's keystore

     .. code-block:: c

     \code
  */
  if (np_ok ==
      np_keystore_check_identity(ac, controller_authnz_keystore_id, id)) {
    return true;
  } else {
    np_keystore_store_identity(ac, controller_authnz_keystore_id, id);
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
  if (np_ok ==
      np_keystore_check_identity(ac, controller_authnz_keystore_id, id)) {
    return true;
  } else {
    np_keystore_store_identity(ac, controller_authnz_keystore_id, id);
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
