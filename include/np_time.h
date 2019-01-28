//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
// original version was taken from chimera project, but modified
#ifndef _NP_TIME_H_
#define _NP_TIME_H_

#include "neuropil.h"
#include "np_legacy.h"

NP_API_INTERN
bool _np_time_init(np_state_t* context);
NP_API_INTERN
void _np_time_destroy(np_state_t* context);

NP_API_INTERN
double _np_time_update_cache(np_state_t* context);

#endif // _NP_TIME_H_