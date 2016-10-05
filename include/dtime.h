//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but heavily modified

#ifndef NP_DTIME_H_
#define NP_DTIME_H_

#include <sys/time.h>

#ifdef __cplusplus
extern "C"
{
#endif

  /**
   ** dtime:
   **  returns the time of day in double format with microsecond precision
   */
   extern double dtime ();

  /**
   ** dalarm: 
   **  generates a SIGALRM signal in #time# seconds
   */
   extern void dalarm (double time);

  /**
   ** dalarm:
   **  sleeps for #time# seconds
   */
    extern void dsleep (double time);

  /**
   ** dtotv: 
   **  returns the struct timeval representation of double #d#
   */
    extern struct timeval dtotv (double d);

  /**
   ** tvtod:
   **  returns the double representation of timeval #tv#
   */
    extern double tvtod (struct timeval tv);

#ifdef __cplusplus
}
#endif

#endif				/* NP_DTIME_H_ */
