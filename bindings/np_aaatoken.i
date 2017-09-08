//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_aaatoken

%{
#include "../include/np_aaatoken.h"
%}

%rename(np_aaatoken) np_aaatoken_s;
%rename(np_aaatoken) np_aaatoken_t;


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
        _np_aaatoken_t_new(token);
        return token;
    }
    ~np_aaatoken_s() {
        _np_aaatoken_t_del($self);
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
