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

    np_tree_s() {
        np_tree_t *tree = make_nptree();
        return tree;
    }
    ~np_tree_s() {
        np_free_tree($self);
    }
    void clear() {
        np_clear_tree($self);
    }
    
    void insert_str (const char *key, np_val_t val) {
        tree_insert_str ($self, key, val);
    }
    void insert_int (int16_t ikey, np_val_t val) {
        tree_insert_int ($self, ikey, val);
    }
    void insert_ulong (uint32_t ulkey, np_val_t val) {
        tree_insert_ulong ($self, ulkey, val);
    }
    void insert_dbl (double dkey, np_val_t val) {
        tree_insert_dbl ($self, dkey, val);
    }

    void replace_str (const char *key, np_val_t val){
        tree_replace_str ($self,  key,  val);
    }
    void replace_int (int16_t ikey, np_val_t val){
        tree_replace_int ($self,  ikey,  val);
    }
    void replace_ulong (uint32_t ulkey, np_val_t val){
        tree_replace_ulong ($self, ulkey, val);
    }
    void replace_dbl (double dkey, np_val_t val){
        tree_replace_dbl ($self, dkey, val);
    }
    
    np_val_t find_str (const char *key) {
        np_tree_elem_t*  elem = elem = tree_find_str ($self, key);
        if (elem) return elem->val;
        else return NP_VAL_NULL;
    }
    np_val_t find_int (int16_t ikey){
        np_tree_elem_t*  elem = tree_find_int ($self, ikey);
        if (elem) return elem->val;
        else return NP_VAL_NULL;
    }
    np_val_t find_ulong (uint32_t ikey){
        np_tree_elem_t*  elem = tree_find_ulong ($self, ikey);
        if (elem) return elem->val;
        else return NP_VAL_NULL;
    }
    np_val_t find_dbl (double dkey){
        np_tree_elem_t* elem = tree_find_dbl ($self, dkey);
        if (elem) return elem->val;
        else return NP_VAL_NULL;
    }
    
    void del_str (const char *key) {
        tree_del_str ($self, key);
    }
    void del_int (const int16_t key) {
        tree_del_int ($self, key);
    }
    void del_double (const double key){
        tree_del_double ($self, key);
    }
    void del_ulong (const uint32_t key) {
        tree_del_ulong ($self, key);
    }
};

%ignore np_tree_elem_s;

%ignore _val_cmp;
%ignore _tree_replace_all_with_str;
%ignore jrb_get_byte_size;
%ignore np_print_tree;

%ignore make_nptree;
%ignore np_free_tree;
%ignore np_clear_tree;

%ignore tree_insert_str;
%ignore tree_insert_int;
%ignore tree_insert_ulong;
%ignore tree_insert_dbl;

%ignore tree_replace_str;
%ignore tree_replace_int;
%ignore tree_replace_ulong;
%ignore tree_replace_dbl;

%ignore tree_find_str;
%ignore tree_find_int;
%ignore tree_find_ulong;
%ignore tree_find_dbl;

%ignore tree_find_gte_str;
%ignore tree_find_gte_int;
%ignore tree_find_gte_ulong;
%ignore tree_find_gte_dbl;

%ignore tree_del_str;
%ignore tree_del_int;
%ignore tree_del_double;
%ignore tree_del_ulong;

%include "../include/np_tree.h"

