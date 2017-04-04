//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_val

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_val.h"
%}

%rename(np_val_t) np_val;
%rename(np_val_s) np_val;

%extend val {
    %immutable v;
    %immutable bin;
    %immutable tree;
    %immutable key;
    %immutable obj;
    %immutable sh;
    %immutable i;
    %immutable l;
    %immutable ll;
    %immutable f;
    %immutable d;
    %immutable s;
    %immutable c;
    %immutable uc;
    %immutable ush;
    %immutable ui;
    %immutable ul;
    %immutable ull;
    %immutable a2_ui;
    %immutable farray;
    %immutable carray;
    %immutable ucarray;
};

%extend np_val_s {
    %immutable type;
    %immutable size;
    %immutable value;
};

%ignore val;

%include "../include/np_val.h"
