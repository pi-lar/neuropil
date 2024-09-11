//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef _NP_MESSAGEPART_H_
#define _NP_MESSAGEPART_H_

#include "np_memory.h"
#include "np_threads.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct np_messagepart_s np_messagepart_t;
typedef np_messagepart_t       *np_messagepart_ptr;

struct np_e2e_messagepart_s {
  // pointers to header values
  unsigned char *mac_e;
  np_dhkey_t    *subject;
  np_dhkey_t    *audience;
  double        *tstamp;
  uint32_t      *ttl;
  unsigned char *uuid;
  uint16_t      *parts;
  uint16_t      *msg_flags;
  unsigned char *nonce;

  // for outgoing messages: pointer to the specific part in the message
  void *msg_header;
  void *msg_body;
};

struct np_n2n_messagepart_s {
  // internal management fields
  uint16_t chunk_offset;
  bool     is_forwarded_part;

  // message fields;
  char     mac_n[16];
  uint32_t seq;
  uint16_t hop_count;
  // char rlnc_n[32];
  struct np_e2e_messagepart_s e2e_msg_part;

  // for incoming messages: pointer to the complete allocated memory area
  void *msg_chunk;
};

struct np_messagepart_s {
  np_tree_t *header;
  np_tree_t *instructions;
  char       uuid[NP_UUID_BYTES];
  uint32_t   part;
  void      *msg_part;
  np_mutex_t work_lock;
} NP_API_INTERN;

NP_PLL_GENERATE_PROTOTYPES(np_messagepart_ptr);
_NP_GENERATE_MEMORY_PROTOTYPES(np_messagepart_t);

NP_API_INTERN
int8_t _np_messagepart_cmp(const np_messagepart_ptr value1,
                           const np_messagepart_ptr value2);

NP_API_PROTEC
char *np_messagepart_printcache(np_state_t *context, bool asOneLine);
#ifdef __cplusplus
}
#endif

#endif /* NP_MESSAGEPART_H_ */
