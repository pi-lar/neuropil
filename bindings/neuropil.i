//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") neuropil

%include "stdint.i" 

#define NP_ENUM
#define NP_API_EXPORT
#define NP_API_HIDDEN
#define NP_API_PROTEC
#define NP_API_INTERN

%{
#include "../include/np_types.h"
#include "../include/neuropil.h"
#include "../include/np_threads.h"
#include "../include/np_val.h"
#include "../include/np_message.h"
#include "../include/np_msgproperty.h"
#include "../include/np_tree.h"
#include "../include/np_jobqueue.h"
#include "../include/np_dendrit.h"
%}

%include "np_types.i"
%include "np_aaatoken.i"

%rename(np_state_s) np_state;
%rename(np_state_t) np_state;

%{

static PyObject *py_authenticate_func = NULL;
static PyObject *py_authorize_func = NULL;
static PyObject *py_accounting_func = NULL;


static np_bool python_authenticate_callback(struct np_aaatoken_s* aaa_token)
{
   PyObject *arglist;
   PyObject *result;

   // arglist = Py_BuildValue("()"); 
   // arglist = Py_BuildValue("(isO)", the_int, the_str, the_pyobject);

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_authenticate_func, arglist);
   np_bool ret_val = PyObject_IsTrue(result);

   Py_DECREF(arglist);
   Py_XDECREF(result);

   return ret_val;
}

static np_bool python_authorize_callback(struct np_aaatoken_s* aaa_token)
{
   PyObject *arglist;
   PyObject *result;

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_authorize_func, arglist);
   np_bool ret_val = PyObject_IsTrue(result);

   Py_DECREF(arglist);
   Py_XDECREF(result);

   return ret_val;
}

static np_bool python_accounting_callback(struct np_aaatoken_s* aaa_token)
{
   PyObject *arglist;
   PyObject *result;

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_accounting_func, arglist);
   np_bool ret_val = PyObject_IsTrue(result);

   Py_DECREF(arglist);
   Py_XDECREF(result);

   return ret_val;
}

static np_tree_t* callback_tree = NULL;

// _NP_ENABLE_MODULE_LOCK(py_callback_wrap);
// _NP_MODULE_LOCK_IMPL(py_callback_wrap);

// static const char* NP_MSG_INST_UUID = "_np.uuid";

static void _py_callback_wrapper(np_jobargs_t* args) 
{
    np_val_t msg_uuid = NP_VAL_NULL;
    if (NULL == tree_find_str(args->msg->instructions, NP_MSG_INST_UUID) ) goto __np_cleanup__;
    else msg_uuid = tree_find_str(args->msg->instructions, NP_MSG_INST_UUID)->val;    

    if (NULL == callback_tree) {
        callback_tree = make_nptree();
    }

    PyObject* obj = tree_find_str(callback_tree, args->properties->msg_subject)->val.value.v;
    tree_insert_str(callback_tree, msg_uuid.value.s, new_val_v(obj));
    
    tree_insert_str(args->msg->properties, "_py.cid", msg_uuid);
    // find correct python handler and store this info for later    
    _np_job_submit_transform_event(0.0, args->properties, args->target, args->msg);

    __np_cleanup__:
        return;            
}

static PyObject* _py_convert_callback_data(np_tree_t* msg_properties, np_tree_t* msg_body)
{
    PyObject *arglist;

    PyObject* prop = SWIG_NewPointerObj(SWIG_as_voidptr(msg_properties), SWIGTYPE_p_np_tree_s, 0);
    PyObject* body = SWIG_NewPointerObj(SWIG_as_voidptr(msg_body), SWIGTYPE_p_np_tree_s, 0);
    arglist = Py_BuildValue("(OO)", prop, body);
    return arglist;
}

static np_bool _py_subject_callback(np_tree_t* msg_properties, np_tree_t* msg_body)
{
    // lookup handler
    np_val_t msg_uuid = tree_find_str(msg_properties, "_py.cid")->val;
    tree_del_str(msg_properties, "_py.cid");

    PyObject* py_callback = tree_find_str(callback_tree, msg_uuid.value.s)->val.value.v;
    
    // convert arguments to python args
    PyObject *arglist = _py_convert_callback_data(msg_properties, msg_body);
    
    // find real python handler

    // call real python handler
    PyObject* result = PyEval_CallObject(py_callback, arglist);
    np_bool ret_val = PyObject_IsTrue(result);

    Py_DECREF(arglist);
    Py_XDECREF(result);
    
    return ret_val;
}


%}


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

    void py_set_listener(PyObject* PyString, PyObject *PyFunc)
    {        
//          _MODULE_LOCK(py_callback_wrapper) {           
            if (NULL == callback_tree) {
                callback_tree = make_nptree();
            }
            char* subject = PyString_AsString(PyString);
            // char* subject = Py_BuildValue("s", PyString);

            tree_insert_str(callback_tree, subject, new_val_v(PyFunc));
            np_set_listener(_py_subject_callback, subject);
        
            np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, subject);

            msg_prop->clb_transform = _np_callback_wrapper;
            msg_prop->clb_inbound = _py_callback_wrapper;
            msg_prop->user_clb = _py_subject_callback;            
//          }
    }

    
    void py_set_authenticate_func(PyObject *PyFunc)
    {
        Py_XDECREF(py_authenticate_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);               /* Add a reference to new callback */
        py_authenticate_func = PyFunc;    /* Remember new callback */
        np_setauthenticate_cb(python_authenticate_callback);
    }

    void py_set_authorize_func(PyObject *PyFunc)
    {
        Py_XDECREF(py_authorize_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);            /* Add a reference to new callback */
        py_authorize_func = PyFunc;    /* Remember new callback */
        np_setauthenticate_cb(python_authorize_callback);
    }

    void py_set_accounting_func(PyObject *PyFunc)
    {
        Py_XDECREF(py_accounting_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);            /* Add a reference to new callback */
        py_accounting_func = PyFunc;   /* Remember new callback */
        np_setauthenticate_cb(python_accounting_callback);
    }  
};


#ifdef SWIG<python>
%typemap(in) PyObject *PyFunc {
  if (!PyCallable_Check($input)) {
      PyErr_SetString(PyExc_TypeError, "Need a callable object!");
      return NULL;
  }
  $1 = $input;
}
#endif 


%ignore _np_state;
%ignore _np_ping;
%ignore _np_send_ack;

%include "np_log.i"
%include "np_tree.i"
%include "np_val.i"

%include "../include/neuropil.h"