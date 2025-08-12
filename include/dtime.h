//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef NP_DTIME_H_
#define NP_DTIME_H_

#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 ** dtime:
 **  returns the time of day in double format with microsecond precision
 */
extern double dtime();

/**
 ** dalarm:
 **  generates a SIGALRM signal in #time# seconds
 */
extern void dalarm(double time);

/**
 ** dalarm:
 **  sleeps for #time# seconds
 */
extern void dsleep(double time);

/**
 ** dtotv:
 **  returns the struct timeval representation of double #d#
 */
extern struct timeval dtotv(double d);

/**
 ** tvtod:
 **  returns the double representation of timeval #tv#
 */
extern double tvtod(struct timeval tv);

#ifdef __cplusplus
}
#endif

#endif /* NP_DTIME_H_ */
