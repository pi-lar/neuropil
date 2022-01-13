//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_BOOTSTRAP_FILE_H_
#define _NP_BOOTSTRAP_FILE_H_

#include <stdbool.h>
#include <stdint.h>
#include "np_constants.h"
#include "np_legacy.h"
#include "np_settings.h"

NP_API_INTERN
bool _np_bootstrap_init(np_state_t* context);
NP_API_INTERN
void _np_bootstrap_destroy(np_state_t* context);

NP_API_INTERN
void np_bootstrap_add(np_state_t* context, const char* connectionstr);
NP_API_INTERN
void np_bootstrap_remove(np_state_t* context, const char* connectionstr);
NP_API_INTERN
void _np_bootstrap_confirm(np_state_t* context, np_key_t* confirmed);


#endif // _NP_BOOTSTRAP_FILE_H_
