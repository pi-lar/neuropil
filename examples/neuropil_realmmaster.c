//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <assert.h>
#include <errno.h>
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

#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_aaatoken.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_node.h"
#include "np_types.h"
#include "np_util.h"

np_state_t *state                = NULL;
np_tree_t  *authorized_tokens    = NULL;
np_tree_t  *authenticated_tokens = NULL;

pthread_mutex_t _aaa_mutex = PTHREAD_MUTEX_INITIALIZER;

int seq          = -1;
int joinComplete = 0;

bool check_authorize_token(np_context *context, struct np_token *token) {
  pthread_mutex_lock(&_aaa_mutex);
  if (NULL == authorized_tokens) authorized_tokens = np_tree_create();

  // if a token reaches this point, is has already been check for technical
  // validity
  bool ret_val = false;

  char pub_key[2 * crypto_sign_PUBLICKEYBYTES + 1];
  sodium_bin2hex(pub_key,
                 2 * crypto_sign_PUBLICKEYBYTES + 1,
                 token->public_key,
                 crypto_sign_PUBLICKEYBYTES);

  if (NULL != np_tree_find_str(authorized_tokens, token->issuer)) {
    pthread_mutex_unlock(&_aaa_mutex);
    return (true);
  }
  char uuid_hex[2 * NP_UUID_BYTES + 1];
  sodium_bin2hex(uuid_hex, 2 * NP_UUID_BYTES + 1, msg->uuid, NP_UUID_BYTES);

  fprintf(stdout, "----------------------------------------------\n");
  fprintf(stdout, "authorization request for : \n");
  fprintf(stdout, "\tuuid              : %s\n", uuid_hex);
  fprintf(stdout, "\trealm             : %s\n", token->realm);
  fprintf(stdout, "\tissuer            : %s\n", token->issuer);
  fprintf(stdout, "\tsubject           : %s\n", token->subject);
  fprintf(stdout, "\taudience          : %s\n", token->audience);

  struct timeval token_time;
  struct tm      token_ts;
  char           time_entry[27];
  token_time.tv_sec = (long)token->issued_at;
  token_time.tv_usec =
      (long)((token->issued_at - (double)token_time.tv_sec) * 1000000.0);
  localtime_r(&token_time.tv_sec, &token_ts);
  strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
  snprintf(time_entry + 19, 6, ".%6d", token_time.tv_usec);
  fprintf(stdout, "\tissued date       : %s\n", time_entry);

  token_time.tv_sec = (long)token->expires_at;
  token_time.tv_usec =
      (long)((token->expires_at - (double)token_time.tv_sec) * 1000000.0);
  localtime_r(&token_time.tv_sec, &token_ts);
  strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
  snprintf(time_entry + 19, 6, ".%6d", token_time.tv_usec);
  fprintf(stdout, "\texpiration        : %s\n", time_entry);

  fprintf(stdout, "\tpublic_key        : %s\n", pub_key);
  //	if (np_tree_find_str(token->extensions, "passcode"))
  //	{
  //		fprintf(stdout,
  //"----------------------------------------------\n");
  // fprintf(stdout,
  //"\tpasscode          : %s\n",
  // np_tree_find_str(token->extensions, "passcode")->val.value.s);
  //	}
  fprintf(stdout, "----------------------------------------------\n");
  fflush(stdout);
  // fprintf(stdout, "authorize ? [ (a)lways / (o)nce / (n)ever ]: ");

  /*
   * char result = fgetc(stdin);
          switch (result)
          {
          case 'a':
                  ret_val = true;
                  */
  np_ref_obj(np_aaatoken_t, token);
  np_tree_insert_str(authorized_tokens, token->issuer, np_treeval_new_v(token));
  /*
                  break;
          case 'o':
                  ret_val = true;
                  break;
          case 'n':
          default:
                  break;
          }
  */
  //	fprintf(stdout, "----------------------------------------------\n");
  //	fflush(stdout);

  pthread_mutex_unlock(&_aaa_mutex);
  return (true); // ret_val;
}

bool check_authenticate_token(np_context *context, struct np_token *token) {
  pthread_mutex_lock(&_aaa_mutex);

  if (NULL == authenticated_tokens) authenticated_tokens = np_tree_create();
  // if a token reaches this point, is has already been check for technical
  // validity
  bool ret_val = false;

  char pub_key[2 * crypto_sign_PUBLICKEYBYTES + 1];
  sodium_bin2hex(pub_key,
                 2 * crypto_sign_PUBLICKEYBYTES + 1,
                 token->public_key,
                 crypto_sign_PUBLICKEYBYTES);

  if (NULL != tree_find_str(authenticated_tokens, token->issuer)) {
    pthread_mutex_unlock(&_aaa_mutex);
    return (true);
  }

  fprintf(stdout, "----------------------------------------------\n");
  fprintf(stdout, "authentication request for:\n");
  fprintf(stdout, "\trealm             : %s\n", token->realm);
  fprintf(stdout, "\tissuer            : %s\n", token->issuer);
  fprintf(stdout, "\tsubject           : %s\n", token->subject);
  fprintf(stdout, "\taudience          : %s\n", token->audience);
  struct timeval token_time;
  struct tm      token_ts;
  char           time_entry[27];
  token_time.tv_sec = (long)token->issued_at;
  token_time.tv_usec =
      (long)((token->issued_at - (double)token_time.tv_sec) * 1000000.0);
  localtime_r(&token_time.tv_sec, &token_ts);
  strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
  snprintf(time_entry + 19, 6, ".%6d", token_time.tv_usec);
  fprintf(stdout, "\tissued date       : %s\n", time_entry);

  token_time.tv_sec = (long)token->expires_at;
  token_time.tv_usec =
      (long)((token->expires_at - (double)token_time.tv_sec) * 1000000.0);
  localtime_r(&token_time.tv_sec, &token_ts);
  strftime(time_entry, 19, "%Y-%m-%d %H:%M:%S", &token_ts);
  snprintf(time_entry + 19, 6, ".%6d", token_time.tv_usec);
  fprintf(stdout, "\texpiration        : %s\n", time_entry);

  fprintf(stdout, "\tpublic_key        : %s\n", pub_key);
  //	fprintf(stdout, "----------------------------------------------\n");
  //	if (tree_find_str(token->extensions, "passcode"))
  //	{
  //		fprintf(stdout, "\tpasscode          : %s\n",
  //				tree_find_str(token->extensions,
  //"passcode")->val.value.s);
  //	}
  fprintf(stdout, "----------------------------------------------\n");
  fflush(stdout);
  /*	fprintf(stdout, "authenticate ? (a)lways / (o)nce / (n)ever: ");

          char result = fgetc(stdin);
          switch (result)
          {
          case 'y':
                  ret_val = true;
                  */
  np_ref_obj(np_aaatoken_t, token);
  tree_insert_str(authenticated_tokens, token->issuer, np_treeval_new_v(token));
  /*		break;
          case 'N':
          default:
                  break;
          }
          fprintf(stdout, "----------------------------------------------\n");
          fflush(stdout);
          */
  pthread_mutex_unlock(&_aaa_mutex);
  return (true); // ret_val;
}

bool check_account_token(np_context *ac, struct np_token *token) {
  return (true);
}

struct np_token create_realm_identity(np_context *ac) {
  struct np_token realm_identity =
      np_new_identity(ac, np_time_now() + 7200.0, NULL);

  strncpy(realm_identity.realm,
          "pi-lar test realm",
          sizeof realm_identity.realm);
  strncpy(realm_identity.subject,
          "pi-lar realmserver",
          sizeof realm_identity.subject);
  // strncpy(realm_identity.issuer,  "pi-lar realmserver", 65);

  // add some unique identification parameters
  // a far better approach is to follow the "zero-knowledge" paradigm (use the
  // source, luke) also check libsodium password hahsing functionality
  // TODO: Mak possible to use  extensions as tree:
  // tree_insert_str(realm_identity.extensions, "passcode",
  // np_treeval_new_hash("test"));

  return (realm_identity);
}

int main(int argc, char **argv) {

  int   no_threads = 8;
  char *j_key      = NULL;
  char *proto      = "udp4";
  char *port       = NULL;
  char *hostname   = NULL;
  int   level      = -2;
  char *logpath    = ".";

  int                   opt;
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
  for the general initialisation of a node please look into the neuropil_node
  example
  */

  struct np_settings *settings = np_default_settings(NULL);
  settings->n_threads          = no_threads;

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

  struct np_token realm_identity = create_realm_identity(context);
  np_use_identity(context, realm_identity);
  np_set_realm_name(context, "pi-lar test realm");
  np_enable_realm_server(context);

  np_set_authenticate_cb(context, check_authenticate_token);
  np_set_authorize_cb(context, check_authorize_token);
  np_set_accounting_cb(context, check_account_token);

  /**
  check stdout and the log file because it will contain the hashvalue / connect
  string for your node, e.g.

  .. code-block:: c

     2f96848a8c490e0f0f71c74caa900423bcf2d32882a9a0b3510c50085f7ec0e5:udp6:localhost:3333
  */

  /**
  start up the job queue with 8 concurrent threads competing for job execution.

  .. code-block:: c

     np_threads_start_workers(8);
  */

  // dsleep(50);
  if (np_ok != np_run(context, 0)) {
    printf("ERROR: Node could not start");
    exit(EXIT_FAILURE);
  }

  if (NULL != j_key) {
    np_join(context, j_key);
  }

  /**
  and finally loop (almost) forever

  .. code-block:: c

     while (1) {
             dsleep(1.0);
     }
  */

  /**
  your're done ...

  if you plan to connect your nodes to this controller as a bootstrap node.
  The created process can be contacted by other nodes and will forward messages
  as required. By default the authentication / authorization / accounting
  handler accept nodes/message request from everybody.

  .. note::
     Make sure that you implement and register the appropiate aaa callback
  functions to control with which nodes you exchange messages. By default
  everybody is allowed to interact with your node
  */

  while (1) {
    np_time_sleep(1.0);
  }
}
