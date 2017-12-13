//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_msgproperty

#define RB_ENTRY(x) x

%{
#include "np_msgproperty.h"
%}

%rename(np_msgproperty) np_msgproperty_s;
%rename(np_msgproperty) np_msgproperty_t;

%extend np_msgproperty_s {

	%feature ("ref") np_message_s "np_mem_refobj($this->obj, NULL);"
	%feature ("unref") np_message_s "np_mem_unrefobj($this->obj, NULL);"

	%immutable msg_subject;
	%immutable last_update;
    %immutable mode_type; // potentially destroying dicovery sending -> read-only
	
	// internal fields, do not expose to python
	%ignore obj;
	%ignore link;
	%ignore partner_key;
	%ignore is_internal;
	%ignore msg_cache_in;
	%ignore msg_cache_out;
	%ignore lock;
	%ignore msg_received;
	%ignore clb_inbound;			// internal neuropil supplied
	%ignore clb_outbound;			// internal neuropil supplied
	%ignore clb_route;				// internal neuropil supplied
	%ignore clb_transform;			// internal neuropil supplied

	// for python these are set by using set_listener and set_sender on the global state object
	%ignore user_receive_clb;	// external user supplied for inbound
	%ignore user_send_clb;		// external user supplied for outnound
};

%ignore np_msgproperty_register;
%ignore np_msgproperty_get;
%ignore _np_msgproperty_init;
%ignore _np_msgproperty_comp;
%ignore _np_msgproperty_check_sender_msgcache;
%ignore _np_msgproperty_check_receiver_msgcache;
%ignore _np_msgproperty_add_msg_to_send_cache;
%ignore _np_msgproperty_add_msg_to_recv_cache;
%ignore __np_msgproperty_internal_msgs_ack;
%ignore _np_msgproperty_add_receive_listener;
%ignore _np_msgproperty_cleanup_receiver_cache;


%include "np_msgproperty.h"
