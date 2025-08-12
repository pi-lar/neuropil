//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <stdlib.h>

#include "neuropil.h"
#include "neuropil_attributes.h"
#include "neuropil_data.h"
#pragma once

#define __CGOGEN 1

// Callback type definitions
extern bool np_go_authn_callback_internal(void *ac, struct np_token *aaa_token);
extern bool np_go_authz_callback_internal(void *ac, struct np_token *aaa_token);
extern bool np_go_receive_callback_internal(void              *ac,
                                            struct np_message *message);
