//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_tree

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_types.h"
#include "../include/np_tree.h"
%}

%rename(np_tree_t) np_tree;
%rename(np_tree_s) np_tree;

%extend np_tree_s {
    %immutable rbh_root;
    %immutable size;
    %immutable byte_size;
};

%ignore np_tree_elem_s;

%ignore _val_cmp;
%ignore _tree_replace_all_with_str;
%ignore jrb_get_byte_size;
%ignore np_print_tree;

%include "../include/np_tree.h"

