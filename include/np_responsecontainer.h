//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#ifndef _NP_RESPONSECONTAINER_H_
#define _NP_RESPONSECONTAINER_H_

#include "util/np_list.h"

#include "np_dhkey.h"
#include "np_memory.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

struct np_responsecontainer_s {
  char       uuid[NP_UUID_BYTES];
  np_dhkey_t dest_dhkey; // the destination key / next/final hop of the message
  np_dhkey_t msg_dhkey;  // the message (OUT) dhkey for this response handler

  double
      received_at; // the time when the msg received a response (ack or reply)
  double
      send_at; // this is the time the packet is transmitted (or retransmitted)
  double expires_at; // the time when the responsecontainer will expire and will
                     // be deleted
} NP_API_INTERN;

_NP_GENERATE_MEMORY_PROTOTYPES(np_responsecontainer_t);

// NP_API_INTERN
// void _np_responsecontainer_set(np_key_t* key, np_responsecontainer_t* entry);

NP_API_INTERN
np_responsecontainer_t *_np_responsecontainers_get_by_uuid(np_key_t *key,
                                                           char     *uuid);

#ifdef __cplusplus
}
#endif

#endif // _NP_RESPONSECONTAINER_H_
