//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_serialization.h"

#include "neuropil_log.h"

#include "util/np_tree.h"
#include "util/np_treeval.h"

#include "np_log.h"
#include "np_settings.h"
#include "np_types.h"
#include "np_util.h"

#ifdef NP_USE_QCBOR
#include "s11n_impl/np_serialize_qcbor.c"
#elif NP_USE_CMP
#include "s11n_impl/np_serialize_cmp.c"
#else
#error "need a serialization framwork, please select NP_USE_QCBOR or NP_USE_CMP"
#endif
