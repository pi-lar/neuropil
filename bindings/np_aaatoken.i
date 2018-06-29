//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_aaatoken

%include "carrays.i"
%include "cdata.i"

%{
#include "np_aaatoken.h"
%}

%rename(np_aaatoken) np_aaatoken_s;
%rename(np_aaatoken) np_aaatoken_t;

%extend np_aaatoken_s {

    %feature ("ref") np_aaatoken_s "np_mem_refobj($this->obj, NULL);"
    %feature ("unref") np_aaatoken_s "np_mem_unrefobj($this->obj, NULL);"

    %immutable version;
    %immutable uuid;

	%immutable realm;
	%immutable issuer; // from (can be self signed)
	%immutable subject; // about
	%immutable audience; // to

	%immutable issued_at;
	%immutable not_before;
	%immutable expires_at;

    %immutable signed_hash;
    %immutable signature;
    %immutable public_key;

    %immutable extensions;

    %ignore obj;
    %ignore state;
    %ignore private_key;
    %ignore private_key_is_set;
    %ignore is_signature_verified;
    %ignore is_core_token;
};

%array_class(char, extensions_bytes);
%cdata(char, extensions_bytes) 


%ignore np_aaastate_e;

%ignore _np_aaatoken_t_new;
%ignore _np_aaatoken_t_del;

%ignore np_aaatoken_encode;
%ignore np_aaatoken_decode;

%ignore np_aaatoken_core_encode;
%ignore _np_aaatoken_get_fingerprint;
%ignore _np_aaatoken_is_core_token;
%ignore _np_aaatoken_mark_as_core_token;
%ignore _np_aaatoken_mark_as_full_token;
%ignore _np_aaatoken_upgrade_core_token;

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

%include "np_list.h"
%include "np_aaatoken.h"
