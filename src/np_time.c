//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0); please see LICENSE file for details
//
#include "event/ev.h"
#include <time.h>

#include "neuropil.h"

double np_time_now() {
	return ev_time();
}

void np_time_sleep(double sleeptime) {

	ev_sleep(sleeptime);
	return;

/*
	struct timespec ts;
	ts.tv_sec = (int)sleeptime;
	ts.tv_nsec = (sleeptime - ((int)sleeptime)) * 1000000; // to nanoseconds

	int status = -1;
	while (status == -1)
		status = nanosleep(&ts, &ts);
*/
}
