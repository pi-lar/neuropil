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

// static bool _py_subject_callback(np_jobargs_t* args)
static np_bool _py_subject_callback(np_tree_t* msg_properties, np_tree_t* msg_body)
{

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
//         _MODULE_LOCK(py_callback_wrapper) {           
            if (!callback_tree) {
                callback_tree = make_nptree();
            }
//         }
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