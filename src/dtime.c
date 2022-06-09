//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
// original version is based on the chimera project
#include "dtime.h" /* function headers */

#include <signal.h> /* siginterrupt, SIGALRM */
#include <stdio.h>
#include <string.h>   /* memset */
#include <sys/time.h> /* struct timeval, gettimeofday */

/**
 ** dtime:
 ** returns the time of day in double format with microsecond precision
 **/
double dtime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  // log_msg(LOG_DEBUG, "time now: %d:%d (%f)", tv.tv_sec, tv.tv_usec,
  // tvtod(tv));
  double retVal = (double)tv.tv_sec;
  retVal += ((double)tv.tv_usec / 1000000.0);
  return retVal;
}

/**
 ** dalarm:
 **  generates a SIGALRM signal in #time# seconds
 **/
void dalarm(double time) {
  struct itimerval it;
  memset(&it, 0, sizeof(struct itimerval));
  it.it_value = dtotv(time);
  siginterrupt(SIGALRM, 1);
  setitimer(ITIMER_REAL, &it, NULL);
}

/**
 ** dsleep:
 **  sleeps for #time# seconds
 **/
void dsleep(double time) {
  struct timeval tv;
  tv = dtotv(time);
  select(0, NULL, NULL, NULL, &tv);
}

/**
 ** dtotv:
 **  returns the struct timeval representation of double #d#
 **/
struct timeval dtotv(double d) {
  struct timeval tv;
  tv.tv_sec  = (long)d;
  tv.tv_usec = (long)((d - (double)tv.tv_sec) * 1000000.0);
  return (tv);
}

/**
 ** tvtod:
 **  returns the double representation of timeval #tv#
 **/
double tvtod(struct timeval tv) {
  double retVal = tv.tv_sec + ((double)tv.tv_usec / 1000000.0);
  return retVal;
}
