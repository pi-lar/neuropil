//
// neuropil is copyright 2016-2024 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file
// for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "example_helper.c"
#include "files/file.h"

#include "util/np_tree.h"

#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_types.h"

bool authorize(np_context *ac, struct np_token *id);
bool authenticate(np_context *ac, struct np_token *id);

int main(int argc, char **argv) {
  int ret = 0;

  char *realm = NULL;
  char *code  = NULL;

  int   no_threads = 9;
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
                                         "[-r realmname]",
                                         "r:",
                                         &realm,
                                         &code)) == NULL) {
    exit(EXIT_FAILURE);
  }

  struct np_settings settings;
  np_default_settings(&settings);
  settings.n_threads = 5;

  snprintf(settings.log_file,
           255,
           "%s%s_%s.log",
           logpath,
           "/neuropil_http_node",
           port);
  settings.log_level = -3;

  np_context *ac = np_new_context(&settings);
  np_set_userdata(ac, user_context);
  np_ctx_cast(ac);

  np_example_print(context, stdout, "logpath: %s\n", settings.log_file);

  np_example_save_and_load_identity(context);

  if (NULL != realm) {
    np_set_realm_name(context, realm);
    np_enable_realm_client(context);
  }

  np_set_authorize_cb(context, authorize);
  np_set_authenticate_cb(context, authenticate);

  if (np_ok != np_listen(context, proto, "localhost", atoi(port), dns_name)) {
    np_example_print(context,
                     stderr,
                     "ERROR: Node could not listen to %s:%s:%s",
                     proto,
                     hostname,
                     port);
  } else {
    // __np_example_helper_loop(context); // for the fancy ncurse display
    fprintf(stdout,
            "INFO : node is listening on %s\n",
            np_get_connection_string(context));

    log_debug(LOG_DEBUG, NULL, "starting http module");
    _np_http_init(context, "localhost", "31415");

    np_id file_seed;
    memset(file_seed, 0, NP_FINGERPRINT_BYTES);

    log_debug(LOG_DEBUG, NULL, "starting file server");
    np_files_open(context, file_seed, "examples", false);
    np_sysinfo_enable_server(context);

    log_debug(LOG_DEBUG, NULL, "starting job queue");
    if (np_ok != np_run(context, 0.001)) {
      np_example_print(context, stderr, "ERROR: Node could not run");
    } else {

      if (NULL != j_key) {
        np_example_print(context, stdout, "try to join %s\n", j_key);
        // join previous node
        if (np_ok != np_join(context, j_key)) {
          np_example_print(context, stderr, "ERROR: Node could not join");
        }
      }

      while (np_get_status(context) == np_running) {
        np_files_open(context, file_seed, "examples", false);
        np_run(context, 0.5);
        // __np_example_helper_loop(context);
      }
    }
    np_example_print(context, stderr, "Closing Node");
  }

  return ret;
}

bool authorize(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  fprintf(stdout,
          "authz %s from %02X%02X%02X%02X%02X%02X%02X: "
          "%02X%02X%02X%02X%02X%02X%02X...\n",
          id->subject,
          id->issuer[0],
          id->issuer[1],
          id->issuer[2],
          id->issuer[3],
          id->issuer[4],
          id->issuer[5],
          id->issuer[6],
          id->public_key[0],
          id->public_key[1],
          id->public_key[2],
          id->public_key[3],
          id->public_key[4],
          id->public_key[5],
          id->public_key[6]);

  if (strncmp(id->subject, "files/", 6) == 0) {
    np_files_send_authorized(ac, id);
  }
  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}

bool authenticate(np_context *ac, struct np_token *id) {
  // TODO: Make sure that id->public_key is an authenticated peer!
  fprintf(stdout,
          "authn %s from %02X%02X%02X%02X%02X%02X%02X: "
          "%02X%02X%02X%02X%02X%02X%02X...\n",
          id->subject,
          id->issuer[0],
          id->issuer[1],
          id->issuer[2],
          id->issuer[3],
          id->issuer[4],
          id->issuer[5],
          id->issuer[6],
          id->public_key[0],
          id->public_key[1],
          id->public_key[2],
          id->public_key[3],
          id->public_key[4],
          id->public_key[5],
          id->public_key[6]);

  // TODO: Make sure that id->public_key is the intended sender!
  return true;
}
