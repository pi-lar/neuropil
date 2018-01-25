//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <unistd.h>

#include "neuropil.h"
#include "np_log.h"
#include "np_types.h"
#include "np_aaatoken.h"

int seq = -1;
int joinComplete = 0;

np_bool auth_callback(np_aaatoken_t *token)
{
  char key[65] = {0};
  sodium_bin2hex(key, sizeof key, token->public_key, sizeof token->public_key);
  printf("welcome %s\n", key);
  return TRUE;
}

int main(int argc, char **argv)
{
  char *usage = "netnode [port] [jkey]\n";
  char *jkey = NULL;
  char *port = NULL;
  if (argc > 3) { fprintf(stderr, usage); exit(1); }
  if (argc >= 2) port = argv[1];
  if (argc >= 3) jkey = argv[2];

  char logpath[255];
  snprintf(logpath, sizeof logpath, "pilarnet-%d.log", getpid());
  np_log_init(logpath, LOG_ERROR|LOG_WARN|LOG_INFO|LOG_DEBUG);

  // inform us of joining nodes (XXX segfaults)
  //np_setauthenticate_cb(auth_callback);

  np_state_t *np = np_init("udp4", port, NULL);
  np_start_job_queue(4);

  // print connect string
  printf("%s\n", np_get_connection_string());


  if (jkey) {
    printf("join %s\n", jkey);
    np_send_join(jkey);
  }

  while (1) np_time_sleep(1.0);
}
