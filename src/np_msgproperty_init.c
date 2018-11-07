//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "np_types.h"
#include "np_memory.h"

#include "np_msgproperty.h"
#include "np_dendrit.h"
#include "np_axon.h"
#include "np_glia.h"
#include "np_list.h"
#include "np_legacy.h"
#include "np_pinging.h"

sll_return(np_msgproperty_ptr) default_msgproperties(np_state_t* context) {
    
    np_sll_t(np_msgproperty_ptr, ret);
    sll_init(np_msgproperty_ptr, ret);

    np_msgproperty_t* __default_properties = NULL;
    np_new_obj(np_msgproperty_t, __default_properties);
    sll_append(np_msgproperty_ptr, ret, __default_properties);

    __default_properties->msg_subject = _DEFAULT;
    __default_properties->rep_subject = NULL;
    __default_properties->mode_type = INBOUND | OUTBOUND | ROUTE;
    __default_properties->mep_type = DEFAULT_TYPE;
    __default_properties->priority = 0;
    __default_properties->ack_mode = ACK_NONE;
    __default_properties->retry = 0;
    sll_append(np_callback_t, __default_properties->clb_inbound, _np_in_received);
    //default: 	sll_append(np_callback_t, __default_properties->clb_outbound, _np_out);
    //sll_append(np_callback_t, __default_properties->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __default_properties->clb_route, _np_glia_route_lookup);
    __default_properties->msg_ttl = 20.0;
    __default_properties->max_threshold = UINT16_MAX;
    __default_properties->token_max_ttl = 30;
    __default_properties->token_min_ttl = 20;

    np_msgproperty_t* __handshake_properties = NULL;
    np_new_obj(np_msgproperty_t, __handshake_properties);
    sll_append(np_msgproperty_ptr, ret, __handshake_properties);

    __handshake_properties->msg_subject = _NP_MSG_HANDSHAKE;
    __handshake_properties->rep_subject = NULL;
    __handshake_properties->mode_type = INBOUND | OUTBOUND | TRANSFORM;
    __handshake_properties->mep_type = ONE_WAY;
    __handshake_properties->priority = 0;
    __handshake_properties->ack_mode = ACK_NONE;
    __handshake_properties->retry = 0;
    
    sll_append(np_callback_t, __handshake_properties->clb_inbound, _np_in_handshake);
    sll_append(np_callback_t, __handshake_properties->clb_transform, _np_out_handshake);
    //sll_append(np_callback_t, __handshake_properties->clb_route, _np_never_called_jobexec_route);
    __handshake_properties->msg_ttl = 20.0;
    __handshake_properties->max_threshold = UINT16_MAX;
    __handshake_properties->token_max_ttl = 30;
    __handshake_properties->token_min_ttl = 20;

    // we don't need to ack the ack the ack the ack ...
    np_msgproperty_t* __ack_properties = NULL;
    np_new_obj(np_msgproperty_t, __ack_properties);
    sll_append(np_msgproperty_ptr, ret, __ack_properties);

    __ack_properties->msg_subject = _NP_MSG_ACK;
    __ack_properties->rep_subject = NULL;
    __ack_properties->mode_type = OUTBOUND | INBOUND | ROUTE;
    __ack_properties->mep_type = ONE_WAY;
    __ack_properties->priority = 0;
    __ack_properties->ack_mode = ACK_NONE;
    __ack_properties->retry = 0;
    sll_append(np_callback_t, __ack_properties->clb_inbound, _np_in_ack);
    sll_remove(np_callback_t, __ack_properties->clb_outbound, _np_out, np_callback_t_sll_compare_type);
    sll_append(np_callback_t, __ack_properties->clb_outbound, _np_out_ack);
    //sll_append(np_callback_t, __ack_properties->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __ack_properties->clb_route, _np_glia_route_lookup);
    __ack_properties->msg_ttl = 5.0;
    __ack_properties->max_threshold = UINT16_MAX;
    __ack_properties->token_max_ttl = 30;
    __ack_properties->token_min_ttl = 20;

    // join request: node unknown yet; therefore send without ack; explicit ack handling via extra messages
    np_msgproperty_t* __join_req = NULL;
    np_new_obj(np_msgproperty_t, __join_req);
    sll_append(np_msgproperty_ptr, ret, __join_req);

    __join_req->msg_subject = _NP_MSG_JOIN_REQUEST;
    __join_req->rep_subject = NULL;
    __join_req->mode_type = INBOUND | OUTBOUND;
    __join_req->mep_type = REQ_REP;
    __join_req->priority = 0;
    __join_req->ack_mode = ACK_NONE;
    __join_req->retry = 5;
    sll_append(np_callback_t, __join_req->clb_inbound, _np_in_join_req);
    //default: sll_append(np_callback_t, __join_req->clb_outbound, _np_out);
    //sll_append(np_callback_t, __join_req->clb_transform, _np_never_called_jobexec_transform);
    //sll_append(np_callback_t, __join_req->clb_route, _np_out);
    __join_req->msg_ttl = 30.0;
    __join_req->max_threshold = UINT16_MAX;
    __join_req->token_max_ttl = 30;
    __join_req->token_min_ttl = 20;

    np_msgproperty_t* __join_ack = NULL;
    np_new_obj(np_msgproperty_t, __join_ack);
    sll_append(np_msgproperty_ptr, ret, __join_ack);

    __join_ack->msg_subject = _NP_MSG_JOIN_ACK;
    __join_ack->rep_subject = NULL;
    __join_ack->mode_type = INBOUND | OUTBOUND | ROUTE;
    __join_ack->mep_type = ONE_WAY;
    __join_ack->priority = 0;
    __join_ack->ack_mode = ACK_NONE;
    __join_ack->retry = 5;
    sll_append(np_callback_t, __join_ack->clb_inbound, _np_in_join_ack);
    //default: sll_append(np_callback_t, __join_ack->clb_outbound, _np_out);
    //sll_append(np_callback_t, __join_ack->clb_transform, _np_never_called_jobexec_transform);
    //sll_append(np_callback_t, __join_ack->clb_route, _np_never_called_jobexec_route);
    __join_ack->msg_ttl = 5.0;
    __join_ack->max_threshold = UINT16_MAX;
    __join_ack->token_max_ttl = 30;
    __join_ack->token_min_ttl = 20;

    np_msgproperty_t* __join_nack = NULL;
    np_new_obj(np_msgproperty_t, __join_nack);
    sll_append(np_msgproperty_ptr, ret, __join_nack);

    __join_nack->msg_subject = _NP_MSG_JOIN_NACK;
    __join_nack->rep_subject = NULL;
    __join_nack->mode_type = INBOUND | OUTBOUND | ROUTE;
    __join_nack->mep_type = ONE_WAY;
    __join_nack->priority = 0;
    __join_nack->ack_mode = ACK_NONE;
    __join_nack->retry = 5;
    sll_append(np_callback_t, __join_nack->clb_inbound, _np_in_join_nack);
    //default: sll_append(np_callback_t, __join_nack->clb_outbound, _np_out);
    //sll_append(np_callback_t, __join_nack->clb_transform, _np_never_called_jobexec_transform);
    //sll_append(np_callback_t, __join_nack->clb_route, _np_never_called_jobexec_route);
    __join_nack->msg_ttl = 5.0;
    __join_nack->max_threshold = UINT16_MAX;
    __join_nack->token_max_ttl = 30;
    __join_nack->token_min_ttl = 20;

    // leave the network and clean up the mess
    np_msgproperty_t* __leave_properties = NULL;
    np_new_obj(np_msgproperty_t, __leave_properties);
    sll_append(np_msgproperty_ptr, ret, __leave_properties);

    __leave_properties->msg_subject = _NP_MSG_LEAVE_REQUEST;
    __leave_properties->rep_subject = NULL;
    __leave_properties->mode_type = INBOUND | OUTBOUND | ROUTE;
    __leave_properties->mep_type = ONE_WAY;
    __leave_properties->priority = 0;
    __leave_properties->ack_mode = ACK_DESTINATION;
    __leave_properties->retry = 5;
    sll_append(np_callback_t, __leave_properties->clb_inbound, _np_in_leave_req);
    //default: sll_append(np_callback_t, __leave_properties->clb_outbound, _np_out);
    //sll_append(np_callback_t, __leave_properties->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __leave_properties->clb_route, _np_glia_route_lookup);
    __leave_properties->msg_ttl = 3.0;
    __leave_properties->max_threshold = UINT16_MAX;
    __leave_properties->token_max_ttl = 30;
    __leave_properties->token_min_ttl = 20;

    np_msgproperty_t* __ping = NULL;
    np_new_obj(np_msgproperty_t, __ping);
    sll_append(np_msgproperty_ptr, ret, __ping);

    __ping->msg_subject = _NP_MSG_PING_REQUEST;
    __ping->rep_subject = NULL;
    __ping->mode_type = INBOUND | OUTBOUND | ROUTE;
    __ping->mep_type = ONE_WAY;
    __ping->priority = 0;
    __ping->ack_mode = ACK_DESTINATION;
    __ping->retry = 3;
    sll_append(np_callback_t, __ping->clb_inbound, _np_in_ping);
    //default: sll_append(np_callback_t, __ping->clb_outbound, _np_out);
    //sll_append(np_callback_t, __ping->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __ping->clb_route, _np_glia_route_lookup);
    __ping->msg_ttl = 5.0;
    __ping->max_threshold = 1;
    __ping->token_max_ttl = 30;
    __ping->token_min_ttl = 20;
    
    np_msgproperty_t* __piggy = NULL;
    np_new_obj(np_msgproperty_t, __piggy);
    sll_append(np_msgproperty_ptr, ret, __piggy);

    __piggy->msg_subject = _NP_MSG_PIGGY_REQUEST;
    __piggy->rep_subject = NULL;
    __piggy->mode_type = INBOUND | OUTBOUND | TRANSFORM | ROUTE;
    __piggy->mep_type = ONE_WAY;
    __piggy->priority = 0;
    __piggy->ack_mode = ACK_DESTINATION;
    __piggy->retry = 0;
    sll_append(np_callback_t, __piggy->clb_inbound, _np_in_piggy);
    //default: sll_append(np_callback_t, __piggy->clb_outbound, _np_out);
    sll_append(np_callback_t, __piggy->clb_transform, _np_send_rowinfo_jobexec);
    //default: sll_append(np_callback_t, __piggy->clb_route, _np_glia_route_lookup);
    __piggy->msg_ttl = 20.0;
    __piggy->max_threshold = UINT16_MAX;
    __piggy->token_max_ttl = 30;
    __piggy->token_min_ttl = 20;

    np_msgproperty_t* __update = NULL;
    np_new_obj(np_msgproperty_t, __update);
    sll_append(np_msgproperty_ptr, ret, __update);

    __update->msg_subject = _NP_MSG_UPDATE_REQUEST;
    __update->rep_subject = NULL;
    __update->mode_type = INBOUND | OUTBOUND | ROUTE;
    __update->mep_type = ONE_WAY;
    __update->priority = 0;
    __update->ack_mode = ACK_DESTINATION;
    __update->retry = 2;
    sll_append(np_callback_t, __update->clb_inbound, _np_in_update);
    //default: sll_append(np_callback_t, __update->clb_outbound, _np_out);
    //sll_append(np_callback_t, __update->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __update->clb_route, _np_glia_route_lookup);
    __update->msg_ttl = 20.0;
    __update->max_threshold = UINT16_MAX;
    __update->token_max_ttl = 30;
    __update->token_min_ttl = 20;

    np_msgproperty_t* __discover_receiver = NULL;
    np_new_obj(np_msgproperty_t, __discover_receiver);
    sll_append(np_msgproperty_ptr, ret, __discover_receiver);

    __discover_receiver->msg_subject = _NP_MSG_DISCOVER_RECEIVER;
    __discover_receiver->rep_subject = _NP_MSG_AVAILABLE_RECEIVER;
    __discover_receiver->mode_type = INBOUND | OUTBOUND | ROUTE;
    __discover_receiver->mep_type = A2A_STICKY_REPLY;
    __discover_receiver->priority = 0;
    __discover_receiver->ack_mode = ACK_NONE;
    __discover_receiver->retry = 0;
    sll_append(np_callback_t, __discover_receiver->clb_inbound, _np_in_discover_receiver);
    //default: 	sll_append(np_callback_t, __discover_receiver->clb_outbound, _np_out);
    //sll_append(np_callback_t, __discover_receiver->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __discover_receiver->clb_route, _np_glia_route_lookup);
    __discover_receiver->msg_ttl = 20.0;
    __discover_receiver->max_threshold = UINT16_MAX;
    __discover_receiver->token_max_ttl = 30;
    __discover_receiver->token_min_ttl = 20;

    np_msgproperty_t* __discover_sender = NULL;
    np_new_obj(np_msgproperty_t, __discover_sender);
    sll_append(np_msgproperty_ptr, ret, __discover_sender);

    __discover_sender->msg_subject = _NP_MSG_DISCOVER_SENDER;
    __discover_sender->rep_subject = _NP_MSG_AVAILABLE_SENDER;
    __discover_sender->mode_type = INBOUND | OUTBOUND | ROUTE;
    __discover_sender->mep_type = A2A_STICKY_REPLY;
    __discover_sender->priority = 0;
    __discover_sender->ack_mode = ACK_NONE;
    __discover_sender->retry = 0;
    sll_append(np_callback_t, __discover_sender->clb_inbound, _np_in_discover_sender);
    //default: 	sll_append(np_callback_t, __discover_sender->clb_outbound, _np_out);
    //sll_append(np_callback_t, __discover_sender->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __discover_sender->clb_route, _np_glia_route_lookup);
    __discover_sender->msg_ttl = 20.0;
    __discover_sender->max_threshold = UINT16_MAX;
    __discover_sender->token_max_ttl = 30;
    __discover_sender->token_min_ttl = 20;

    np_msgproperty_t* __available_receiver = NULL;
    np_new_obj(np_msgproperty_t, __available_receiver);
    sll_append(np_msgproperty_ptr, ret, __available_receiver);

    __available_receiver->msg_subject = _NP_MSG_AVAILABLE_RECEIVER;
    __available_receiver->rep_subject = NULL;
    __available_receiver->mode_type = INBOUND | OUTBOUND | ROUTE;
    __available_receiver->mep_type = ONE_WAY;
    __available_receiver->priority = 0;
    __available_receiver->ack_mode = ACK_NONE;
    __available_receiver->retry = 0;
    sll_append(np_callback_t, __available_receiver->clb_inbound, _np_in_available_receiver);
    //default: 	sll_append(np_callback_t, __available_receiver->clb_outbound, _np_out);
    //sll_append(np_callback_t, __available_receiver->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __available_receiver->clb_route, _np_glia_route_lookup);
    __available_receiver->msg_ttl = 20.0;
    __available_receiver->max_threshold = UINT16_MAX;
    __available_receiver->token_max_ttl = 30;
    __available_receiver->token_min_ttl = 20;

    np_msgproperty_t* __available_sender = NULL;
    np_new_obj(np_msgproperty_t, __available_sender);
    sll_append(np_msgproperty_ptr, ret, __available_sender);

    __available_sender->msg_subject = _NP_MSG_AVAILABLE_SENDER;
    __available_sender->rep_subject = NULL;
    __available_sender->mode_type = INBOUND | OUTBOUND | ROUTE;
    __available_sender->mep_type = ONE_WAY;
    __available_sender->priority = 0;
    __available_sender->ack_mode = ACK_NONE;
    __available_sender->retry = 0;
    sll_append(np_callback_t, __available_sender->clb_inbound, _np_in_available_sender);
    //default: 	sll_append(np_callback_t, __available_sender->clb_outbound, _np_out);
    //sll_append(np_callback_t, __available_sender->clb_transform, _np_never_called_jobexec_transform);
    //default: sll_append(np_callback_t, __available_sender->clb_route, _np_glia_route_lookup);
    __available_sender->msg_ttl = 20.0;
    __available_sender->max_threshold = UINT16_MAX;
    __available_sender->token_max_ttl = 30;
    __available_sender->token_min_ttl = 20;

    np_msgproperty_t* __authenticate = NULL;
    np_new_obj(np_msgproperty_t, __authenticate);
    sll_append(np_msgproperty_ptr, ret, __authenticate);

    __authenticate->msg_subject = _NP_MSG_AUTHENTICATION_REQUEST;
    __authenticate->rep_subject = _NP_MSG_AUTHENTICATION_REPLY;
    __authenticate->mode_type = INBOUND | OUTBOUND | TRANSFORM | ROUTE;
    __authenticate->mep_type = A2G_STICKY_REPLY;
    __authenticate->priority = 0;
    __authenticate->ack_mode = ACK_DESTINATION;
    __authenticate->retry = 5;
    sll_append(np_callback_t, __authenticate->clb_inbound, _np_in_authenticate);
    //default: 	sll_append(np_callback_t, __authenticate->clb_outbound, _np_out);
    sll_append(np_callback_t, __authenticate->clb_transform,_np_out_authentication_request);
    //default: sll_append(np_callback_t, __authenticate->clb_route, _np_glia_route_lookup);
    __authenticate->cache_policy = FIFO | OVERFLOW_PURGE;
    __authenticate->msg_ttl = 20.0;
    __authenticate->max_threshold = UINT16_MAX;
    __authenticate->token_max_ttl = 30;
    __authenticate->token_min_ttl = 20;

    np_msgproperty_t* __authenticate_reply = NULL;
    np_new_obj(np_msgproperty_t, __authenticate_reply);
    sll_append(np_msgproperty_ptr, ret, __authenticate_reply);

    __authenticate_reply->msg_subject = _NP_MSG_AUTHENTICATION_REPLY;
    __authenticate_reply->rep_subject = NULL;
    __authenticate_reply->mode_type = INBOUND | OUTBOUND | ROUTE;
    __authenticate_reply->mep_type = ONE_WAY | STICKY_REPLY;
    __authenticate_reply->priority = 0;
    __authenticate_reply->ack_mode = ACK_DESTINATION;
    __authenticate_reply->retry = 5;
    sll_append(np_callback_t, __authenticate_reply->clb_inbound, _np_in_authenticate_reply);
    //default: 	sll_append(np_callback_t, __authenticate_reply->clb_outbound, _np_out);
    sll_append(np_callback_t, __authenticate_reply->clb_transform, _np_out_authentication_reply);
    //default: sll_append(np_callback_t, __authenticate_reply->clb_route, _np_glia_route_lookup);
    __authenticate_reply->msg_ttl = 20.0;
    __authenticate_reply->max_threshold = UINT16_MAX;
    __authenticate_reply->token_max_ttl = 30;
    __authenticate_reply->token_min_ttl = 20;

    np_msgproperty_t* __authorize = NULL;
    np_new_obj(np_msgproperty_t, __authorize);
    sll_append(np_msgproperty_ptr, ret, __authorize);

    __authorize->msg_subject = _NP_MSG_AUTHORIZATION_REQUEST;
    __authorize->rep_subject = _NP_MSG_AUTHORIZATION_REPLY;
    __authorize->mode_type = INBOUND | OUTBOUND | TRANSFORM | ROUTE;
    __authorize->mep_type = G2G_STICKY_REPLY;
    __authorize->priority = 0;
    __authorize->ack_mode = ACK_DESTINATION;
    __authorize->retry = 5;
    sll_append(np_callback_t, __authorize->clb_inbound, _np_in_authorize);
    //default: 	sll_append(np_callback_t, __authorize->clb_outbound, _np_out);
    sll_append(np_callback_t, __authorize->clb_transform, _np_out_authorization_request); 
    //default: sll_append(np_callback_t, __authorize->clb_route, _np_glia_route_lookup);	
    __authorize->cache_policy = FIFO | OVERFLOW_PURGE;
    __authorize->msg_ttl = 20.0;
    __authorize->max_threshold = UINT16_MAX;
    __authorize->token_max_ttl = 30;
    __authorize->token_min_ttl = 20;

    np_msgproperty_t* __authorize_reply = NULL;
    np_new_obj(np_msgproperty_t, __authorize_reply);
    sll_append(np_msgproperty_ptr, ret, __authorize_reply);

    __authorize_reply->msg_subject = _NP_MSG_AUTHORIZATION_REPLY;
    __authorize_reply->rep_subject = NULL;
    __authorize_reply->mode_type = INBOUND | OUTBOUND | ROUTE;
    __authorize_reply->mep_type = ONE_WAY;
    __authorize_reply->priority = 0;
    __authorize_reply->ack_mode = ACK_DESTINATION;
    __authorize_reply->retry = 5;
    sll_append(np_callback_t, __authorize_reply->clb_inbound, _np_in_authorize_reply);
    //default: 	sll_append(np_callback_t, __authorize_reply->clb_outbound, _np_out);
    sll_append(np_callback_t, __authorize_reply->clb_transform, _np_out_authorization_reply);
    //default: sll_append(np_callback_t, __authorize_reply->clb_route, _np_glia_route_lookup);
    __authorize_reply->msg_ttl = 20.0;
    __authorize_reply->max_threshold = UINT16_MAX;
    __authorize_reply->token_max_ttl = 30;
    __authorize_reply->token_min_ttl = 20;

    np_msgproperty_t* __account = NULL;
    np_new_obj(np_msgproperty_t, __account);
    sll_append(np_msgproperty_ptr, ret, __account);

    __account->msg_subject = _NP_MSG_ACCOUNTING_REQUEST;
    __account->rep_subject = NULL;
    __account->mode_type = INBOUND | OUTBOUND | TRANSFORM | ROUTE;
    __account->mep_type = GROUP_TO_GROUP;
    __account->priority = 0;
    __account->ack_mode = ACK_DESTINATION;
    __account->retry = 5;
    sll_append(np_callback_t, __account->clb_inbound,	_np_in_account);
    //default: 	sll_append(np_callback_t, __account->clb_outbound,	_np_out);
    sll_append(np_callback_t, __account->clb_transform,	_np_out_accounting_request);
    //default: sll_append(np_callback_t, __account->clb_route,		_np_glia_route_lookup);
    __account->cache_policy = FIFO | OVERFLOW_PURGE;
    __account->msg_ttl = 20.0;
    __account->max_threshold = UINT16_MAX;
    __account->token_max_ttl = 30;
    __account->token_min_ttl = 20;

    return (ret);
}
