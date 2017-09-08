//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_tree

%{
#include "../include/np_tree.h"
%}

%rename(np_tree) np_tree_t;
%rename(np_tree) np_tree_s;

%extend np_tree_s {

    %immutable rbh_root;
    %immutable size;
    %immutable byte_size;

    np_tree_s() {
        np_tree_t *tree = np_tree_create();
        return tree;
    }
    ~np_tree_s() {
        np_tree_free($self);
    }
    void clear() {
        np_tree_clear($self);
    }

    void insert_str (const char *key, np_treeval_t val) {
        np_tree_insert_str ($self, key, val);
    }
    void insert_int (int16_t ikey, np_treeval_t val) {
        np_tree_insert_int ($self, ikey, val);
    }
    void insert_ulong (uint32_t ulkey, np_treeval_t val) {
        np_tree_insert_ulong ($self, ulkey, val);
    }
    void insert_dbl (double dkey, np_treeval_t val) {
        np_tree_insert_dbl ($self, dkey, val);
    }

    void replace_str (const char *key, np_treeval_t val){
        np_tree_replace_str ($self,  key,  val);
    }
    void replace_int (int16_t ikey, np_treeval_t val){
        np_tree_replace_int ($self,  ikey,  val);
    }
    void replace_ulong (uint32_t ulkey, np_treeval_t val){
        np_tree_replace_ulong ($self, ulkey, val);
    }
    void replace_dbl (double dkey, np_treeval_t val){
        np_tree_replace_dbl ($self, dkey, val);
    }

    np_treeval_t find_str (const char *key) {
        np_tree_elem_t*  elem = elem = np_tree_find_str ($self, key);
        if (elem) return elem->val;
        else return np_treeval_NULL;
    }
    np_treeval_t find_int (int16_t ikey){
        np_tree_elem_t*  elem = np_tree_find_int ($self, ikey);
        if (elem) return elem->val;
        else return np_treeval_NULL;
    }
    np_treeval_t find_ulong (uint32_t ikey){
        np_tree_elem_t*  elem = np_tree_find_ulong ($self, ikey);
        if (elem) return elem->val;
        else return np_treeval_NULL;
    }
    np_treeval_t find_dbl (double dkey){
        np_tree_elem_t* elem = np_tree_find_dbl ($self, dkey);
        if (elem) return elem->val;
        else return np_treeval_NULL;
    }

    void del_str (const char *key) {
        np_tree_del_str ($self, key);
    }
    void del_int (const int16_t key) {
        np_tree_del_int ($self, key);
    }
    void del_double (const double key){
        np_tree_del_double ($self, key);
    }
    void del_ulong (const uint32_t key) {
        np_tree_del_ulong ($self, key);
    }
};

%ignore np_tree_elem_s;

%ignore _val_cmp;
%ignore _np_tree_replace_all_with_str;
%ignore jrb_get_byte_size;
%ignore np_print_tree;

%ignore np_tree_create;
%ignore np_tree_free;
%ignore np_tree_clear;

%ignore _np_print_tree;
%ignore np_tree_get_byte_size;
%ignore _np_tree_deserialize;
%ignore _np_tree_serialize;
%ignore _np_tree_elem_cmp;
%ignore __np_tree_serialize_read_type;
%ignore __np_tree_serialize_read_type_key;
%ignore __np_tree_serialize_write_type;
%ignore __np_tree_serialize_write_type_key;

%ignore np_tree_insert_str;
%ignore np_tree_insert_int;
%ignore np_tree_insert_ulong;
%ignore np_tree_insert_dbl;

%ignore np_tree_replace_str;
%ignore np_tree_replace_int;
%ignore np_tree_replace_ulong;
%ignore np_tree_replace_dbl;

%ignore np_tree_find_str;
%ignore np_tree_find_int;
%ignore np_tree_find_ulong;
%ignore np_tree_find_dbl;

%ignore np_tree_find_gte_str;
%ignore np_tree_find_gte_int;
%ignore np_tree_find_gte_ulong;
%ignore np_tree_find_gte_dbl;

%ignore np_tree_del_str;
%ignore np_tree_del_int;
%ignore np_tree_del_double;
%ignore np_tree_del_ulong;

%include "../include/np_tree.h"
