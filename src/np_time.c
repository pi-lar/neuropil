//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0); please see LICENSE file for details
//
#include "event/ev.h"
#include "neuropil.h"

double np_time_now() {
	return ev_time();
}