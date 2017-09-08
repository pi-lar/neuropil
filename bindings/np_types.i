//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_types

%{
#include "../include/np_types.h"
%}

%ignore np_aaatoken_t;
%ignore np_aaatoken_ptr;
%ignore np_dhkey_t;
%ignore np_job_t;
%ignore np_jobargs_t;
%ignore np_key_t;
%ignore np_message_t;
%ignore np_msgproperty_t;
%ignore np_network_t;
%ignore np_node_t;
%ignore np_state_t;
%ignore np_tree_t;
%ignore np_treeval_t;
%ignore char_ptr;
%ignore np_key_ptr;
%ignore np_thread_ptr;
%ignore np_node_ptr;
%ignore np_msgproperty_ptr;
%ignore np_message_ptr;

%ignore np_usercallback_t;

%include "../include/np_types.h"
