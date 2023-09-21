//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// WiringPi-Api einbinden
#include <arpa/inet.h>
#include <neuropil.h>
#include <neuropil_attributes.h>
#include <np_util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <wiringPi.h>

static np_id owner = {0};

static const char *HEARTBEAT = "urn:org:neuropil:iot-car:heartbeat";
static const char *COMMAND   = "urn:org:neuropil:iot-car:command";
static const char *SHUTDOWN  = "urn:org:neuropil:iot-car:shutdown";

static const char *OWNER = "urn:org:neuropil:iot-car:owner";

static const char *SET_OWNER = "urn:org:neuropil:iot-car:setowner";
static const char *REM_OWNER = "urn:org:neuropil:iot-car:remowner";

bool receive_set_owner(np_context *context, struct np_message *msg) {
  np_id _null = {0};
  if (memcmp(_null, owner, NP_FINGERPRINT_BYTES) == 0) {
    // the first person sending a ownership message wins
    struct np_data_conf  _data_conf         = {0};
    struct np_data_conf *_data_conf_ptr     = &_data_conf;
    unsigned char       *_owner_fingerprint = NULL;

    np_get_msg_attr_bin(msg, OWNER, &_data_conf_ptr, &_owner_fingerprint);
    if (_data_conf.data_size != NP_FINGERPRINT_BYTES) return false;

    memcpy(owner, _owner_fingerprint, NP_FINGERPRINT_BYTES);
    fprintf(stdout,
            "ownership request granted  in message [%s] from node: %32s \n",
            msg->uuid,
            msg->from);
    return true;
  }

  fprintf(stdout,
          "ownership request rejected in message [%s] from node: %32s \n",
          msg->uuid,
          msg->from);
  return true;
}

bool receive_rem_owner(np_context *context, struct np_message *msg) {
  memset(owner, 0, NP_FINGERPRINT_BYTES);
  fprintf(stdout,
          "ownership removed with message [%s] from node: %32s \n",
          msg->uuid,
          msg->from);
}

bool receive_command(np_context *context, struct np_message *msg) {
  digitalWrite(0, 0);
  digitalWrite(1, 0);
  digitalWrite(2, 0);
  digitalWrite(4, 0);

  np_tree_t *command = np_tree_create();
  np_buffer2tree(context, msg->data, msg->data_length, command);

  if (np_tree_find_str(command, "LEFT") != NULL) {
    digitalWrite(0, 1);
    digitalWrite(3, 1);
  } else if (np_tree_find_str(command, "RIGHT") != NULL) {
    digitalWrite(1, 1);
    digitalWrite(2, 1);
  } else if (np_tree_find_str(command, "FORWARD") != NULL) {
    digitalWrite(1, 1);
    digitalWrite(3, 1);
  } else if (np_tree_find_str(command, "BACKWARD") != NULL) {
    digitalWrite(0, 1);
    digitalWrite(2, 1);
  } else {
    fprintf(stdout,
            "owner     send unknown command [%s] with message [%s]\n",
            msg->data,
            msg->uuid);
  }
  // fprintf(stdout, "owner     moved car [%s] with message [%s]\n", msg->data,
  // msg->uuid);
  return true;
}

bool receive_shutdown(np_context *context, struct np_message *msg) {
  memset(owner, 0, NP_FINGERPRINT_BYTES);
  np_destroy(context, true);
  fprintf(stdout,
          "owner     send shutdown command with message [%s] \n",
          msg->uuid);
}

bool receive_and_send_heartbeat(np_context *context, struct np_message *msg) {

  /*    np_tree_t* command = np_tree_create();
      np_buffer2tree(context, msg->data, command);
  */

  np_send(context, HEARTBEAT, msg->data, msg->data_length);

  fprintf(stdout,
          "owner     send heartbeat command with message [%s] \n",
          msg->uuid);
}

bool authorize_cb(np_context *context, struct np_token *token) {
  np_id _null = {0};
  if (memcmp(_null, owner, NP_FINGERPRINT_BYTES) == 0) {
    if (strncmp(token->subject, SET_OWNER, strnlen(SET_OWNER, 33))) return true;
    return false;
  } else {
    np_id _null     = {0};
    np_id _to_check = {0};

    np_token_fingerprint(context, *token, false, &_to_check);

    if (memcmp(_null, owner, NP_FINGERPRINT_BYTES) != 0 &&
        memcmp(_to_check, owner, NP_FINGERPRINT_BYTES) == 0)
      return true;
    return false;
  }
}

// ----------------------------------------------
int main(int argc, char *argv[]) {
  char *logpath = ".";

  fprintf(stdout, "NEUROPIL IoT-Car example: Version 1.0.0 - 2021.01.01\n");

  // starting wiring API
  if (wiringPiSetup() == -1) return 1;

  // set pins
  pinMode(0, OUTPUT);
  pinMode(1, OUTPUT);
  pinMode(2, OUTPUT);
  pinMode(3, OUTPUT);

  struct np_settings settings;
  np_default_settings(&settings);
  settings.n_threads = 1;
  snprintf(settings.log_file, 255, "%s%s.log", logpath, "/neuropil_iot_car");

  np_context *app = np_new_context(&settings);
  np_set_authorize_cb(app, authorize_cb);

  struct np_mx_properties set_ownership_mx =
      np_get_mx_properties(app, SET_OWNER);
  np_add_receive_cb(app, SET_OWNER, receive_set_owner);

  np_run(app, 0.0);
  np_join(app, "*:udp4:demo.neuropil.io:3400");

  np_id _null = {0};
  while (np_ok != np_has_joined(app) &&
         0 == memcmp(_null, owner, NP_FINGERPRINT_BYTES)) {
    np_run(app, 0.0);
  }

  struct np_mx_properties rem_ownership_mx =
      np_get_mx_properties(app, REM_OWNER);
  np_add_receive_cb(app, REM_OWNER, receive_rem_owner);

  struct np_mx_properties shutdown_mx = np_get_mx_properties(app, SHUTDOWN);
  np_add_receive_cb(app, SHUTDOWN, receive_shutdown);

  struct np_mx_properties heartbeat_mx = np_get_mx_properties(app, HEARTBEAT);
  np_add_receive_cb(app, HEARTBEAT, receive_and_send_heartbeat);

  struct np_mx_properties command_mx = np_get_mx_properties(app, COMMAND);
  np_add_receive_cb(app, COMMAND, receive_command);

  while (1) {
    np_run(app, 0.0);
  }
  return 0;
}
