//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_TIME_H_
#define _NP_TIME_H_

#include "neuropil.h"
#include "np_legacy.h"

NP_API_INTERN
bool _np_time_init(np_state_t* context);
NP_API_INTERN
void _np_time_destroy(np_state_t* context);
NP_API_INTERN
double _np_time_force_now_nsec();

NP_API_INTERN
double _np_time_update_cache(np_state_t* context);

#endif // _NP_TIME_H_
