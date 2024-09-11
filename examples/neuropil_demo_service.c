//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
/*
 * neuropil_demo_service.c
 *
 * This service is also available via *:udp4:demo.neuropil.io:31415
 *
 * It is composed out of the examples for
 *  - pingpong
 *  - echo server
 */

/**
 *.. NOTE::
 *   If you are not yet familiar with the neuropil initialization procedure
 *please refer to the :ref:`tutorial`
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "event/ev.h"
#include "example_helper.c"

#include "neuropil.h"
#include "neuropil_log.h"

#include "np_log.h"

bool receive_echo_message(np_context *context, struct np_message *message) {
  char uuid_hex[2 * NP_UUID_BYTES + 1];
  sodium_bin2hex(uuid_hex, 2 * NP_UUID_BYTES + 1, msg->uuid, NP_UUID_BYTES);
  np_example_print(context, stdout, "Echoing msg %s", uuid_hex);
  np_send_to(context,
             "echo",
             message->data,
             message->data_length,
             message->from);
  return true;
}

int main(int argc, char **argv) {
  int   no_threads = 8;
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
                                         "",
                                         "")) == NULL) {
    exit(EXIT_FAILURE);
  }

  struct np_settings *settings = np_default_settings(NULL);
  settings->n_threads          = no_threads;

  snprintf(settings->log_file,
           255,
           "%s/%s_%s.log",
           logpath,
           "neuropil_demo_service",
           port);
  fprintf(stdout, "logpath: %s\n", settings->log_file);
  settings->log_level = level;

  np_context *context = np_new_context(settings);
  np_set_userdata(context, user_context);

  if (np_ok != np_listen(context, proto, hostname, atoi(port), dns_name)) {
    np_example_print(context,
                     stderr,
                     "ERROR: Node could not listen to %s:%s:%s",
                     proto,
                     hostname,
                     port);
    exit(EXIT_FAILURE);
  }

  np_add_receive_cb(context, "echo", receive_echo_message);
  struct np_mx_properties echo_props = np_get_mx_properties(context, "echo");
  echo_props.ackmode                 = NP_MX_ACK_NONE;
  echo_props.message_ttl             = 20.0;
  np_set_mx_properties(context, "echo", echo_props);

  if (np_ok != np_run(context, 0)) {
    np_example_print(context, stderr, "ERROR: Node could not start");
    exit(EXIT_FAILURE);
  }

  __np_example_helper_run_info_loop(context);
}
