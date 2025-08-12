//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

// test_fuzzing.c
#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "neuropil.h"

#include "np_legacy.h"

char *input_string = malloc(sizeof(char) * Size + 1);
memcpy(input_string, Data, Size);
input_string[Size] = '\0';

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  np_state_t *ctx;

  struct np_settings *settings = np_default_settings(NULL);
  snprintf(settings->log_file, 256, "./logs/neuropil_fuzzing.log");
  settings->log_level = LOG_DEBUG | LOG_INFO | LOG_WARNING | LOG_ERROR;
  settings->n_threads = 1;

  ctx = np_new_context(settings);
  np_listen(ctx, "udp4", "localhost", 5555, NULL);

  char *input_string = malloc(sizeof(char) * Size + 1);
  memcpy(input_string, Data, Size);
  input_string[Size] = '\0';

  np_join(ctx, input_string);

  np_destroy(ctx, false);
  return 0; // Non-zero return values are reserved for future use.
}
#ifdef __cplusplus
}
