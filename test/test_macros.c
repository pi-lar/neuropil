//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <inttypes.h>
#include <math.h>
#include <neuropil.h>
#include <np_legacy.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#ifndef _NP_TEST_MACROS_H_
#define _NP_TEST_MACROS_H_

#define MEASURE_TIME(array, pos, func)                                         \
  {                                                                            \
    struct timespec ts_start;                                                  \
    struct timespec ts_end;                                                    \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_start);                        \
    func;                                                                      \
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts_end);                          \
    double duration = 1000.0 * ts_end.tv_sec + 1e-6 * ts_end.tv_nsec -         \
                      (1000.0 * ts_start.tv_sec + 1e-6 * ts_start.tv_nsec);    \
    array[pos] = duration;                                                     \
  }

#define CALC_AND_PRINT_STATISTICS(name, array, max_size)                       \
  {                                                                            \
    double min = 2.0, max = 0.0, avg = 0.0, stddev = 0.0;                      \
    for (uint32_t j = 0; j < max_size; j++) {                                  \
      min = (min < array[j]) ? min : array[j];                                 \
      max = (max > array[j]) ? max : array[j];                                 \
      avg += array[j];                                                         \
    }                                                                          \
    avg = avg / max_size;                                                      \
    for (uint16_t j = 0; j < max_size; j++) {                                  \
      stddev += pow(array[j] - avg, 2);                                        \
    }                                                                          \
    stddev = sqrt(stddev / (max_size));                                        \
    fprintf(stdout,                                                            \
            "%-40s --> %.9f / %.9f / %.9f / %.9f \n",                          \
            name,                                                              \
            min,                                                               \
            avg,                                                               \
            max,                                                               \
            stddev);                                                           \
  }

np_state_t *_np_test_ctx(char *name, char *desc, char *porttype, int port);

#define TCTX(...) VFUNC(TCTX, __VA_ARGS__)

#define TCTX5(ID, NAME, DESC, PORTTYPE, PORT)                                  \
  np_state_t *ID;                                                              \
  for (uint8_t _CTX_i##__LINE__ = 0;                                           \
       (_CTX_i##__LINE__ < 1) &&                                               \
       NULL != (ID = _np_test_ctx(NAME,                                        \
                                  DESC,                                        \
                                  PORTTYPE,                                    \
                                  PORT)); /*fprintf(stdout, "running test case \
                                             %s\n", FUNC), fflush(stdout), */  \
       np_destroy(ID, false), _CTX_i##__LINE__++)

#define TCTX4(ID, DESC, PORTTYPE, PORT) TCTX5(ID, FUNC, DESC, PORTTYPE, PORT)
#define TCTX2(ID, DESC)                 TCTX4(ID, DESC, "udp4", (3000 + __COUNTER__))
#define TCTX1(DESC)                     TCTX2(context, DESC)
#define CTX()                           TCTX1("")

#endif // _NP_TEST_MACROS_H_
#ifndef _NP_TEST_MACROS_C_
#define _NP_TEST_MACROS_C_
np_state_t *_np_test_ctx(char *name, char *desc, char *porttype, int port) {
  np_state_t         *ret;
  struct np_settings *settings = np_default_settings(NULL);

  if (desc != NULL && strlen(desc) > 0)
    snprintf(settings->log_file,
             256,
             "logs/neuropil_test_%s_%s.log",
             name,
             desc);
  else snprintf(settings->log_file, 256, "logs/neuropil_test_%s.log", name);

  settings->log_level |= LOG_GLOBAL;
  settings->n_threads = 1;
  ret                 = np_new_context(settings);
  cr_assert(ret != NULL);
  cr_expect(np_stopped == np_get_status(ret),
            "np_get_status returned %" PRIu8,
            np_get_status(ret));
  cr_expect(np_ok == np_listen(ret, porttype, "localhost", port));
  cr_expect(np_stopped == np_get_status(ret),
            "np_get_status returned %" PRIi8,
            np_get_status(ret));
  cr_expect(np_ok == np_run(ret, 0));
  cr_expect(np_running == np_get_status(ret),
            "np_get_status returned %" PRIi8,
            np_get_status(ret));

  return ret;
}
#endif // _NP_TEST_MACROS_C_
