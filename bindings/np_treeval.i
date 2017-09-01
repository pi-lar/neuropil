//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_treeval

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_treeval.h"
%}

%rename(np_treeval) np_treeval_t;
%rename(np_treeval) np_treeval_s;

%extend np_val_u {
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

%extend np_treeval_s {
    %immutable type;
    %immutable size;
    %immutable value;

    np_treeval_s(int8_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_sh(val);
        return treeval;
    }
    np_treeval_s(int16_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_i(val);
        return treeval;
    }
    np_treeval_s(int32_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_l(val);
        return treeval;
    }
    np_treeval_s(int64_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_ll(val);
        return treeval;
    }
    np_treeval_s(uint8_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_ush(val);
        return treeval;
    }
    np_treeval_s(uint16_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_ui(val);
        return treeval;
    }
    np_treeval_s(uint32_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_ul(val);
        return treeval;
    }
    np_treeval_s(uint64_t val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_ull(val);
        return treeval;
    }
    np_treeval_s(char* val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_s(val);
        return treeval;
    }
    np_treeval_s(char val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_c(val);
        return treeval;
    }
/*
    np_treeval_s(unsigned char val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_uc(val);
        return treeval;
    }
*/
    np_treeval_s(float val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_f(val);
        return treeval;
    }
    np_treeval_s(double val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_d(val);
        return treeval;
    }
    np_treeval_s(void* val, uint32_t len) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_bin(val, len);
        return treeval;
    }
    np_treeval_s(np_tree_t* val) {
        np_treeval_t* treeval = malloc(sizeof (np_treeval_t) );
        *treeval = np_treeval_new_tree(val);
        return treeval;
    }

    // destructor
    ~np_treeval_s() {
        free($self);
    }

};


%ignore np_treeval_new_sh;
%ignore np_treeval_new_i;
%ignore np_treeval_new_l;
%ignore np_treeval_new_ll;
%ignore np_treeval_new_ush;
%ignore np_treeval_new_ui;
%ignore np_treeval_new_ul;
%ignore np_treeval_new_ull;
%ignore np_treeval_new_s;
%ignore np_treeval_new_c;
%ignore np_treeval_new_uc;
%ignore np_treeval_new_f;
%ignore np_treeval_new_d;
%ignore np_treeval_new_bin;
%ignore np_treeval_new_tree;

%include "../include/np_treeval.h"
