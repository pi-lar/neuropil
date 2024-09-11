//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "np_messagepart.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "inttypes.h"
#include "sodium.h"
#include "tree/tree.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_serialization.h"
#include "util/np_tree.h"

#include "np_crypto.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_message.h"
#include "np_types.h"
#include "np_util.h"

// NP_PLL_GENERATE_IMPLEMENTATION(np_messagepart_ptr);

int8_t _np_messagepart_cmp(const np_messagepart_ptr value1,
                           const np_messagepart_ptr value2) {
  uint16_t part_1 = value1->part; // np_tree_find_str(value1->instructions,
                                  // NP_MSG_INST_PARTS)->val.value.a2_ui[1];
  uint16_t part_2 = value2->part; // np_tree_find_str(value2->instructions,
                                  // NP_MSG_INST_PARTS)->val.value.a2_ui[1];

  np_ctx_memory(value1);
  log_debug(LOG_MESSAGE | LOG_VERBOSE,
            NULL,
            "message part compare %d / %d / %d",
            part_1,
            part_2,
            part_1 - part_2);

  if (part_2 > part_1) return (1);
  if (part_1 > part_2) return (-1);
  return (0);
}

void _np_messagepart_t_del(np_state_t       *context,
                           NP_UNUSED uint8_t type,
                           NP_UNUSED size_t  size,
                           void             *obj) {

  struct np_n2n_messagepart_s *part = (struct np_n2n_messagepart_s *)obj;

  if (part->msg_chunk != NULL) {
    np_unref_obj(BLOB_1024, part->msg_chunk, ref_obj_usage);
  }
}

void _np_messagepart_t_new(np_state_t       *context,
                           NP_UNUSED uint8_t type,
                           NP_UNUSED size_t  size,
                           void             *obj) {
  struct np_n2n_messagepart_s *part = (struct np_n2n_messagepart_s *)obj;

  // memset(part->uuid, 0, NP_UUID_BYTES);
  // part->msg_part = NULL;
  part->chunk_offset      = 0;
  part->is_forwarded_part = false;
}

char *np_messagepart_printcache(np_state_t *context, bool asOneLine) {
  char *ret      = NULL;
  char *new_line = "\n";
  if (asOneLine == true) {
    new_line = "    ";
  }

  ret = np_str_concatAndFree(ret,
                             "--- Messagepart cache (%" PRIu16 ") ---%s",
                             context->msg_part_cache->size,
                             new_line);
  _LOCK_MODULE(np_message_part_cache_t) {
    np_tree_elem_t *tmp = NULL;

    RB_FOREACH (tmp, np_tree_s, context->msg_part_cache) {
      struct np_e2e_message_s *msg = tmp->val.value.v;
      char                     msg_uuid[33];
      sodium_bin2hex(msg_uuid, 33, msg->uuid, 16);
      ret = np_str_concatAndFree(ret,
                                 "%s   received x of %2" PRIu16
                                 " expected parts. msg subject:%16s%s",
                                 msg_uuid,
                                 msg->parts,
                                 msg->subject,
                                 new_line);
    }
  }
  ret = np_str_concatAndFree(ret, "--- Messagepart cache end ---%s", new_line);

  return (ret);
}
