//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "util/np_serialization.h"

#ifdef NP_USE_CMP

#include "s11n_impl/np_serialize_cmp.c"
// dummy implementation for msgpack serialization
inline bool np_serializer_write_nptoken(void                  *data_buffer,
                                        const struct np_token *token) {}
inline bool np_serializer_read_nptoken(const void      *data_buffer,
                                       struct np_token *token) {}

#endif

#ifdef NP_USE_QCBOR

#include "s11n_impl/np_serialize_qcbor.c"

#endif
