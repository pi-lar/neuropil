//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "sodium.h"

#include "neuropil_log.h"

#include "np_log.h"
#include "np_util.h"

int main(int argc, char **argv) {

  int log_level = LOG_ERROR | LOG_WARNING | LOG_INFO | LOG_DEBUG | LOG_TRACE;
  log_init("test_dh.log", log_level);

  char subject[] = "this.is.a.test";

  for (int i = 0; i < 100; i++) {
    char *uuid = np_create_uuid(subject, i);
    log_msg(LOG_DEBUG, NULL, "uuid size is %u", strlen(uuid));
  }
}
