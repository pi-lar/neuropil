//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") neuropil

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_types.h"
#include "../include/neuropil.h"
%}

%rename(np_state_s) np_state;
%rename(np_state_t) np_state;

%extend np_state_s {
    %immutable my_node_key;

    // reference to main identity on this node
    %immutable my_identity;
    %immutable realm_name;

    %ignore msg_tokens;
    %ignore msg_part_cache;

    %ignore attr;
    %ignore thread_ids;
    %ignore thread_count;

    %ignore enable_realm_master; // act as a realm master for other nodes or not
    %ignore enable_realm_slave; // act as a realm salve and ask master for aaatokens

    %ignore authenticate_func; // authentication callback
    %ignore authorize_func;    // authorization callback
    %ignore accounting_func;   // really needed ?    
};

%ignore _np_state;
%ignore _np_ping;
%ignore _np_send_ack;


%include "np_aaatoken.i"
%include "np_tree.i"
%include "np_val.i"

%include "../include/neuropil.h"
