//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0); please see LICENSE file for details
//
#include "event/ev.h"
#include <time.h>

#include "neuropil.h"
#include "np_util.h"

double np_time_now() {
	return  ev_time();
}

double np_time_sleep(double sleeptime) {

	sleeptime = max(sleeptime, NP_SLEEP_MIN);
	ev_sleep(sleeptime);

/*
	struct timespec ts;
	ts.tv_sec = (int)sleeptime;
	ts.tv_nsec = (sleeptime - ((int)sleeptime)) * 1000000; // to nanoseconds

	int status = -1;
	while (status == -1)
		status = nanosleep(&ts, &ts);
*/
	return sleeptime;
}
