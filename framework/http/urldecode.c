//
// SPDX-FileCopyrightText: 2016 Abe Fehr
// SPDX-License-Identifier: MIT
//

#include "http/urldecode.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

/* Function: urlDecode */
char *urlDecode(const char *str, size_t len) {
  int d = 0; /* whether or not the string is decoded */

  char *dStr   = malloc(len + 1);
  char  eStr[] = "00"; /* for a hex code */

  strncpy(dStr, str, len);

  while (!d) {
    d = 1;
    int i; /* the counter for the string */

    for (i = 0; i < len; ++i) {

      if (dStr[i] == '%') {
        if (dStr[i + 1] == 0) return dStr;

        if (isxdigit(dStr[i + 1]) && isxdigit(dStr[i + 2])) {

          d = 0;

          /* combine the next to numbers into one */
          eStr[0] = dStr[i + 1];
          eStr[1] = dStr[i + 2];

          /* convert it to decimal */
          long int x = strtol(eStr, NULL, 16);

          /* remove the hex */
          memmove(&dStr[i + 1], &dStr[i + 3], strnlen(&dStr[i + 3], len) + 1);

          dStr[i] = x;
        }
      }
    }
  }

  return dStr;
}
