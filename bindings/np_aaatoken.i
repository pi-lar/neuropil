//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_aaatoken

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_types.h"
#include "../include/np_list.h"
#include "../include/np_memory.h"
#include "../include/np_aaatoken.h"
%}

%rename(np_aaatoken_s) np_aaatoken;
%rename(np_aaatoken_t) np_aaatoken;

%extend np_aaatoken_s {
    %ignore obj;

    %immutable issued_at;

    %immutable state;
    %immutable uuid;

    %immutable public_key;
    %immutable session_key;
    %immutable private_key;

    np_aaatoken_s() {
        np_aaatoken_t *token;
        np_new_obj(np_aaatoken_t, token);
        return token;
    }
    ~np_aaatoken_s() {
        np_free_obj(np_aaatoken_t, $self);
    }
};

%ignore np_aaastate_e;

%ignore _np_aaatoken_t_new;
%ignore _np_aaatoken_t_del;

%ignore np_aaatoken_encode;
%ignore np_aaatoken_decode;

%ignore _np_aaatoken_create_dhkey;

%ignore _np_aaatoken_add_sender;
%ignore _np_aaatoken_get_sender;
%ignore _np_aaatoken_get_sender_all;

%ignore _np_aaatoken_add_receiver;
%ignore _np_aaatoken_get_receiver;
%ignore _np_aaatoken_get_receiver_all;

%ignore _np_aaatoken_add_signature;
%ignore _np_aaatoken_add_local_mx;
%ignore _np_aaatoken_get_local_mx;

%nodefaultctor np_aaatoken_s;

%include "../include/np_list.h"
%include "../include/np_aaatoken.h"
