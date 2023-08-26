//
// SPDX-FileCopyrightText: 2016-2022 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include "core/np_comp_msgproperty.h"
#include "util/np_list.h"

#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_legacy.h"
#include "np_memory.h"
#include "np_types.h"

#ifndef SEARCH_MSGPROPERTY_SET
#define SEARCH_MSGPROPERTY_SET

#define NP_SEARCH_NODE_TTL 86400

#define NP_SEARCH_INTENT_TTL         6000
#define NP_SEARCH_INTENT_REFRESH_TTL 60

#define NP_SEARCH_RESULT_TTL         6000
#define NP_SEARCH_RESULT_REFRESH_TTL 60

static const char *SEARCH_NODE_SUBJECT   = "urn:np:search:node:v1";
static const char *SEARCH_ENTRY_SUBJECT  = "urn:np:search:entry:v1";
static const char *SEARCH_QUERY_SUBJECT  = "urn:np:search:query:v1";
static const char *SEARCH_RESULT_SUBJECT = "urn:np:search:result:v1";

enum np_required_search_subjects {
  SEARCH_NODE = 0x1000,

  SEARCH_SUBJECT_ENTRY  = 0x0100,
  SEARCH_SUBJECT_QUERY  = 0x0010,
  SEARCH_SUBJECT_RESULT = 0x0001,

  HYBRID_NODE_PROSUMER = 0x0111, // send/receive entries / queries / results
  SERVER_NODE_PROVIDER =
      0x0111, //     /receive entries / queries / results (proxy for results!)
  CLIENT_NODE_PROVIDER = 0x0001, //     /receive         /         / results

  SERVER_NODE_CONSUMER =
      0x0111, // send/        entries / queries / results (proxy for queries!)
  CLIENT_NODE_CONSUMER = 0x0010, // send/                / queries /
};

sll_return(np_msgproperty_conf_ptr)
    search_msgproperties(np_state_t                      *context,
                         enum np_required_search_subjects kind) {

  np_sll_t(np_msgproperty_conf_ptr, ret);
  sll_init(np_msgproperty_conf_ptr, ret);

  if (FLAG_CMP(kind, SEARCH_NODE)) {
    np_msgproperty_conf_t *__search_node_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_node_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_node_properties);

    __search_node_properties->msg_subject        = SEARCH_NODE_SUBJECT;
    __search_node_properties->msg_ttl            = 5.0;
    __search_node_properties->rep_subject        = NULL;
    __search_node_properties->mode_type          = INBOUND | OUTBOUND;
    __search_node_properties->mep_type           = ANY_TO_ANY;
    __search_node_properties->ack_mode           = ACK_NONE;
    __search_node_properties->priority           = 0;
    __search_node_properties->retry              = 0;
    __search_node_properties->unique_uuids_check = false;
    __search_node_properties->cache_size         = 13;
    __search_node_properties->max_threshold      = 13;
    __search_node_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_node_properties->token_min_ttl      = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_node_properties->audience_type      = NP_MX_AUD_VIRTUAL;
  }

  if (FLAG_CMP(kind, SEARCH_SUBJECT_ENTRY)) {
    np_msgproperty_conf_t *__search_entry_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_entry_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_entry_properties);

    __search_entry_properties->msg_subject        = SEARCH_ENTRY_SUBJECT;
    __search_entry_properties->msg_ttl            = 5.0;
    __search_entry_properties->rep_subject        = NULL;
    __search_entry_properties->mode_type          = INBOUND;
    __search_entry_properties->mep_type           = ANY_TO_ANY;
    __search_entry_properties->ack_mode           = ACK_NONE;
    __search_entry_properties->priority           = 0;
    __search_entry_properties->retry              = 0;
    __search_entry_properties->unique_uuids_check = true;
    __search_entry_properties->cache_size         = 13;
    __search_entry_properties->max_threshold      = 13;
    __search_entry_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_entry_properties->token_min_ttl = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_entry_properties->audience_type = NP_MX_AUD_PRIVATE;
  }

  if (FLAG_CMP(kind, SEARCH_SUBJECT_QUERY)) {
    np_msgproperty_conf_t *__search_query_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_query_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_query_properties);

    __search_query_properties->msg_subject        = SEARCH_QUERY_SUBJECT;
    __search_query_properties->msg_ttl            = 5.0;
    __search_query_properties->rep_subject        = NULL;
    __search_query_properties->mode_type          = INBOUND;
    __search_query_properties->mep_type           = ANY_TO_ANY;
    __search_query_properties->ack_mode           = ACK_NONE;
    __search_query_properties->priority           = 0;
    __search_query_properties->retry              = 0;
    __search_query_properties->unique_uuids_check = true;
    __search_query_properties->cache_size         = 13;
    __search_query_properties->max_threshold      = 13;
    __search_query_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_query_properties->token_min_ttl = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_query_properties->audience_type = NP_MX_AUD_PRIVATE;
  }

  if (FLAG_CMP(kind, SEARCH_SUBJECT_RESULT)) {
    np_msgproperty_conf_t *__search_result_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_result_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_result_properties);

    __search_result_properties->msg_subject        = SEARCH_RESULT_SUBJECT;
    __search_result_properties->msg_ttl            = 5.0;
    __search_result_properties->rep_subject        = NULL;
    __search_result_properties->mode_type          = INBOUND;
    __search_result_properties->mep_type           = ANY_TO_ANY;
    __search_result_properties->ack_mode           = ACK_NONE;
    __search_result_properties->priority           = 0;
    __search_result_properties->retry              = 0;
    __search_result_properties->unique_uuids_check = true;
    __search_result_properties->cache_size         = 13;
    __search_result_properties->max_threshold      = 13;
    __search_result_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_result_properties->token_min_ttl = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_result_properties->audience_type = NP_MX_AUD_PRIVATE;
  }
  return ret;
};

sll_return(np_msgproperty_conf_ptr)
    search_peer_msgproperties(np_state_t                      *context,
                              enum np_required_search_subjects kind) {
  np_sll_t(np_msgproperty_conf_ptr, ret);
  sll_init(np_msgproperty_conf_ptr, ret);

  if (FLAG_CMP(kind, SEARCH_SUBJECT_ENTRY)) {
    np_msgproperty_conf_t *__search_entry_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_entry_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_entry_properties);

    __search_entry_properties->msg_subject        = SEARCH_ENTRY_SUBJECT;
    __search_entry_properties->msg_ttl            = 5.0;
    __search_entry_properties->rep_subject        = NULL;
    __search_entry_properties->mode_type          = OUTBOUND;
    __search_entry_properties->mep_type           = ANY_TO_ANY;
    __search_entry_properties->ack_mode           = ACK_NONE;
    __search_entry_properties->priority           = 0;
    __search_entry_properties->retry              = 0;
    __search_entry_properties->unique_uuids_check = true;
    __search_entry_properties->cache_size         = 13;
    __search_entry_properties->max_threshold      = 13;
    __search_entry_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_entry_properties->token_min_ttl = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_entry_properties->audience_type = NP_MX_AUD_PRIVATE;
  }

  if (FLAG_CMP(kind, SEARCH_SUBJECT_QUERY)) {
    np_msgproperty_conf_t *__search_query_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_query_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_query_properties);

    __search_query_properties->msg_subject        = SEARCH_QUERY_SUBJECT;
    __search_query_properties->msg_ttl            = 5.0;
    __search_query_properties->rep_subject        = NULL;
    __search_query_properties->mode_type          = OUTBOUND;
    __search_query_properties->mep_type           = ANY_TO_ANY;
    __search_query_properties->ack_mode           = ACK_NONE;
    __search_query_properties->priority           = 0;
    __search_query_properties->retry              = 0;
    __search_query_properties->unique_uuids_check = true;
    __search_query_properties->cache_size         = 13;
    __search_query_properties->max_threshold      = 13;
    __search_query_properties->token_max_ttl      = NP_SEARCH_INTENT_TTL;
    __search_query_properties->token_min_ttl = NP_SEARCH_INTENT_REFRESH_TTL;
    __search_query_properties->audience_type = NP_MX_AUD_PRIVATE;
  }

  if (FLAG_CMP(kind, SEARCH_SUBJECT_RESULT)) {
    np_msgproperty_conf_t *__search_result_properties = NULL;
    np_new_obj(np_msgproperty_conf_t,
               __search_result_properties,
               ref_system_msgproperty);
    sll_append(np_msgproperty_conf_ptr, ret, __search_result_properties);

    __search_result_properties->msg_subject        = SEARCH_RESULT_SUBJECT;
    __search_result_properties->msg_ttl            = 5.0;
    __search_result_properties->rep_subject        = NULL;
    __search_result_properties->mode_type          = OUTBOUND;
    __search_result_properties->mep_type           = ANY_TO_ANY;
    __search_result_properties->ack_mode           = ACK_NONE;
    __search_result_properties->priority           = 0;
    __search_result_properties->retry              = 0;
    __search_result_properties->unique_uuids_check = true;
    __search_result_properties->cache_size         = 13;
    __search_result_properties->max_threshold      = 13;
    __search_result_properties->token_max_ttl      = NP_SEARCH_RESULT_TTL;
    __search_result_properties->token_min_ttl = NP_SEARCH_RESULT_REFRESH_TTL;
    __search_result_properties->audience_type = NP_MX_AUD_PRIVATE;
  }

  return ret;
};

#endif // SEARCH_MSGPROPERTY_SET