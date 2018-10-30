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
#include "np_legacy.h"
#include "np_log.h"
#include "np_types.h"
#include "np_aaatoken.h"

bool auth_callback(np_context*ac, struct np_token *token)
{
  char key[65] = {0};
  sodium_bin2hex(key, sizeof key, token->public_key, sizeof token->public_key);
  printf("welcome %s\n", key);
  return true;
}

int main(int argc, char **argv)
{
  char *usage = "pilarnet [port] [jkey]\n";
  char *jkey = NULL;
  char *port = NULL;
  if (argc > 3) { fprintf(stderr, usage); exit(1); }
  if (argc >= 2) port = argv[1];
  if (argc >= 3) jkey = argv[2];
  
  
	struct np_settings *settings = np_default_settings(NULL);
  snprintf(settings->log_file, sizeof settings->log_file, "pilarnet-%d.log", getpid());

	np_context * ac = np_new_context(settings);

	if (np_ok != np_listen(ac, "udp4", NULL, atoi(port))) {
		printf("ERROR: Node could not listen");
		exit(EXIT_FAILURE);
	}


  // inform us of joining nodes 
  np_set_authenticate_cb(ac, auth_callback);

  np_run(ac, 0);

  // print connect string
  printf("start a new node with: ./pilarnet %d %s\n", atoi(port)+1, np_get_connection_string(ac));


  if (jkey != NULL) {
    printf("join %s\n", jkey);
    np_join(ac, jkey);
  }

  while (1) np_time_sleep(np_run(ac, 0));
}
