//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") neuropil


%include "stdint.i"

%{
#include "../include/neuropil.h"
%}

%include "np_types.i"
%include "np_aaatoken.i"
%include "np_log.i"
%include "np_tree.i"
%include "np_treeval.i"
%include "np_message.i"

%rename(np_state) np_state_s;
%rename(np_state) np_state_t;

%{

static PyObject *py_authenticate_func = NULL;
static PyObject *py_authorize_func = NULL;
static PyObject *py_accounting_func = NULL;

PyGILState_STATE gstate;

static np_bool python_authenticate_callback(struct np_aaatoken_s* aaa_token)
{
    PyObject *arglist;
    PyObject *result;

    gstate = PyGILState_Ensure();

    PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
    arglist = Py_BuildValue("(O)", obj);

    result = PyObject_CallObject(py_authenticate_func, arglist);
    np_bool ret_val = PyObject_IsTrue(result);

    Py_DECREF(arglist);
    Py_XDECREF(result);

    PyGILState_Release(gstate);

    return ret_val;
}

static np_bool python_authorize_callback(struct np_aaatoken_s* aaa_token)
{
   PyObject *arglist;
   PyObject *result;

   gstate = PyGILState_Ensure();

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_authorize_func, arglist);
   np_bool ret_val = PyObject_IsTrue(result);

   Py_DECREF(arglist);
   Py_XDECREF(result);

   PyGILState_Release(gstate);

   return ret_val;
}

static np_bool python_accounting_callback(struct np_aaatoken_s* aaa_token)
{
   PyObject *arglist;
   PyObject *result;

   gstate = PyGILState_Ensure();

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_accounting_func, arglist);
   np_bool ret_val = PyObject_IsTrue(result);

   Py_DECREF(arglist);
   Py_XDECREF(result);

   PyGILState_Release(gstate);

   return ret_val;
}

static np_tree_t* callback_tree = NULL;

static np_bool _py_subject_callback(const struct np_message_s *const msg, np_tree_t* msg_prop, np_tree_t* msg_body)
{
    // lookup handler
    np_tree_elem_t* msg_subject = np_tree_find_str(msg->header, "_np.subj");
    if (NULL == msg_subject) {
        log_msg(LOG_ERROR, "incoming message without subject, giving up");
        return FALSE;
    }
    if (NULL == callback_tree) {
        log_msg(LOG_INFO, "no callback tree found ");
        return FALSE;
    }

    log_msg(LOG_INFO, "lookup of python handler for message %s", msg_subject->val.value.s);
    np_tree_elem_t* py_func_elem = np_tree_find_str(callback_tree, msg_subject->val.value.s);

    if (NULL == py_func_elem) {
        log_msg(LOG_ERROR, "no python user callback handler found for message %s", msg_subject->val.value.s);
        return FALSE;
    }

    gstate = PyGILState_Ensure();

    // use found functor, convert arguments to python args
    PyObject* py_callback = py_func_elem->val.value.v;

    PyObject* py_msg  = SWIG_NewPointerObj(SWIG_as_voidptr(msg     ), SWIGTYPE_p_np_message_s, 0);
    PyObject* py_prop = SWIG_NewPointerObj(SWIG_as_voidptr(msg_prop), SWIGTYPE_p_np_tree_s, 0);
    PyObject* py_body = SWIG_NewPointerObj(SWIG_as_voidptr(msg_body), SWIGTYPE_p_np_tree_s, 0);

    PyObject *arglist = Py_BuildValue("(OOO)", py_msg, py_prop, py_body);

    log_msg(LOG_INFO, "conversion of callback args done");

    // call real python handler
    PyObject* result = PyEval_CallObject(py_callback, arglist);
    Py_DECREF(arglist);

    log_msg(LOG_INFO, "retrieved result");
    np_bool cb_result = FALSE;
    if (result != NULL) {
        int ret_val = PyObject_IsTrue(result);
        if (ret_val == 1) {
            log_msg(LOG_ERROR, "callback function returned an success");
            cb_result = TRUE;
        } else {
            log_msg(LOG_ERROR, "callback function returned an error");
        }
        Py_DECREF(result);
    }
    else
    {
        // PyErr_Print();
        log_msg(LOG_ERROR, "error calling python module");
    }

    PyGILState_Release(gstate);

    log_msg(LOG_INFO, "callback function done");
    return cb_result;
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

    void set_listener(PyObject* PyString, PyObject *PyFunc)
    {
        if (NULL == callback_tree) {
            callback_tree = np_tree_create();
        }

        gstate = PyGILState_Ensure();

        char* subject = PyString_AsString(PyString);
        log_msg(LOG_INFO, "setting python callback for subject %s", subject);

        // find old (eventually)
        np_tree_elem_t* old_py_func_elem = np_tree_find_str(callback_tree, subject);

        Py_XINCREF(PyFunc); /* Add a reference to new callback */
        np_tree_replace_str(callback_tree, subject, np_treeval_new_v(PyFunc)); /* set new callback */

        np_add_receive_listener(_py_subject_callback, subject); /* set python proxy as listener */

        if (NULL != old_py_func_elem) {
            PyObject* old_py_func = old_py_func_elem->val.value.v;
            Py_XDECREF(old_py_func); /* Dispose of previous callback */
            log_msg(LOG_INFO, "deleting old python callback for subject %s", subject);
        }
        PyGILState_Release(gstate);
    }

    void set_authn_func(PyObject *PyFunc)
    {
        gstate = PyGILState_Ensure();

        Py_XDECREF(py_authenticate_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);               /* Add a reference to new callback */
        py_authenticate_func = PyFunc;    /* Remember new callback */
        np_setauthenticate_cb(python_authenticate_callback);

        PyGILState_Release(gstate);
    }

    void set_authz_func(PyObject *PyFunc)
    {
        gstate = PyGILState_Ensure();

        Py_XDECREF(py_authorize_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);            /* Add a reference to new callback */
        py_authorize_func = PyFunc;    /* Remember new callback */
        np_setauthorizing_cb(python_authorize_callback);

        PyGILState_Release(gstate);
    }

    void set_acc_func(PyObject *PyFunc)
    {
        gstate = PyGILState_Ensure();

        Py_XDECREF(py_accounting_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);            /* Add a reference to new callback */
        py_accounting_func = PyFunc;   /* Remember new callback */
        np_setaccounting_cb(python_accounting_callback);

        PyGILState_Release(gstate);
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

%include "../include/neuropil.h"
