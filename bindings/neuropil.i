//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") neuropil

#define NP_API_INTERN
#define NP_API_EXPORT
#define NP_API_PROTEC
#define NP_UNUSED
#define NP_ENUM

%include "stdint.i"

%{
#include "neuropil.h"
%}

%include "np_types.i"
%include "np_aaatoken.i"
%include "np_identity.i"
%include "np_log.i"
%include "np_tree.i"
%include "np_treeval.i"
%include "np_message.i"
%include "np_msgproperty.i"

%rename(np_state) np_state_s;
%rename(np_state) np_state_t;

%{

static PyObject *py_authenticate_func = NULL;
static PyObject *py_authorize_func = NULL;
static PyObject *py_accounting_func = NULL;


static np_bool python_authenticate_callback(struct np_aaatoken_s* aaa_token)
{
    np_bool ret_val = FALSE;
    PyObject *arglist;
    PyObject *result;

    PyGILState_STATE gstate;
    gstate = PyGILState_Ensure();

    PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
    arglist = Py_BuildValue("(O)", obj);

    result = PyObject_CallObject(py_authenticate_func, arglist);
    Py_DECREF(arglist);

    if (result != NULL) {
       ret_val = PyObject_IsTrue(result);
       Py_XDECREF(result);
    } else {
       log_msg(LOG_ERROR, "error calling authn python callback");
       PyErr_Clear();
    }

    PyGILState_Release(gstate);

    return ret_val;
}

static np_bool python_authorize_callback(struct np_aaatoken_s* aaa_token)
{
   np_bool ret_val = FALSE;
   PyObject *arglist;
   PyObject *result;

   PyGILState_STATE gstate;
   gstate = PyGILState_Ensure();

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_authorize_func, arglist);
   Py_DECREF(arglist);

   if (result != NULL) {
       ret_val = PyObject_IsTrue(result);
       Py_XDECREF(result);
   } else {
       log_msg(LOG_ERROR, "error calling authz python callback");
       PyErr_Clear();
   }

   PyGILState_Release(gstate);

   return ret_val;
}

static np_bool python_accounting_callback(struct np_aaatoken_s* aaa_token)
{
   np_bool ret_val = FALSE;
   PyObject *arglist;
   PyObject *result;

   PyGILState_STATE gstate;
   gstate = PyGILState_Ensure();

   PyObject* obj = SWIG_NewPointerObj(SWIG_as_voidptr(aaa_token), SWIGTYPE_p_np_aaatoken_s, 0);
   arglist = Py_BuildValue("(O)", obj);

   result = PyEval_CallObject(py_accounting_func, arglist);
   Py_DECREF(arglist);

   if (result != NULL) {
       ret_val = PyObject_IsTrue(result);
       Py_XDECREF(result);
   } else {
       log_msg(LOG_ERROR, "error calling accounting python callback");
       PyErr_Clear();
   }

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
        log_msg(LOG_ERROR, "no callback tree found ");
        abort();
    }

    log_msg(LOG_INFO, "lookup of python handler for message %s", msg_subject->val.value.s);
    np_tree_elem_t* py_func_elem = np_tree_find_str(callback_tree, msg_subject->val.value.s);

    if (NULL == py_func_elem) {
        log_msg(LOG_ERROR, "no python user callback handler found for message %s", msg_subject->val.value.s);
        return FALSE;
    }

    PyGILState_STATE gstate;
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
        } else if (ret_val == 0) {
            log_msg(LOG_ERROR, "callback function returned an error");
        } else {
            log_msg(LOG_ERROR, "callback function result evaluation failed");
            ret_val = PyBool_Check(result);
            log_msg(LOG_ERROR, "return value is a bool: %d", ret_val);
        }
        Py_DECREF(result);
    }
    else
    {
        // PyErr_Print();
        log_msg(LOG_ERROR, "error calling python module");
        PyErr_Clear();
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
    %ignore accounting_func;   // accounting callback ?


    PyObject* get_connection_string()
    {
#if PY_VERSION_HEX >= 0x03000000
        return PyUnicode_FromString(np_get_connection_string());
#else
        return PyString_FromString(np_get_connection_string());
#endif
    }

    void set_listener(PyObject* PyString, PyObject *PyFunc)
    {
        if (NULL == callback_tree) {
            callback_tree = np_tree_create();
        }

        PyGILState_STATE gstate;
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

	np_msgproperty_t* get_inout_mx_property(PyObject* PyString)
	{
		PyGILState_STATE gstate;
		gstate = PyGILState_Ensure();

		char* subject = PyString_AsString(PyString);
		log_msg(LOG_INFO, "searching for mx property with subject %s", subject);
		np_msgproperty_t* prop = np_msgproperty_get(INBOUND | OUTBOUND, subject);

		if (prop == NULL) {
			np_new_obj(np_msgproperty_t, prop);
			prop->msg_subject = strndup(subject, 255);
			prop->mode_type = INBOUND | OUTBOUND;
			np_msgproperty_register(prop);
        } else {
            log_msg(LOG_INFO, "found mx property with subject %s", prop->msg_subject);
        }

        PyGILState_Release(gstate);
		return prop;
	}

	np_msgproperty_t* get_out_mx_property(PyObject* PyString)
	{
		PyGILState_STATE gstate;
		gstate = PyGILState_Ensure();

		char* subject = PyString_AsString(PyString);
		log_msg(LOG_INFO, "searching for mx property with subject %s", subject);
		np_msgproperty_t* prop = np_msgproperty_get(OUTBOUND, subject);

		if (prop == NULL) {
			np_new_obj(np_msgproperty_t, prop);
			prop->msg_subject = strndup(subject, 255);
			prop->mode_type = OUTBOUND;
			np_msgproperty_register(prop);
            log_msg(LOG_INFO, "registered python subject %s (length: %lu)", subject, strlen(subject));
        } else {
            log_msg(LOG_INFO, "found mx property with subject %s", prop->msg_subject);
        }

        PyGILState_Release(gstate);
		return prop;
	}

	np_msgproperty_t* get_in_mx_property(PyObject* PyString)
	{
        PyGILState_STATE gstate;
        gstate = PyGILState_Ensure();

		char* subject = PyString_AsString(PyString);
		log_msg(LOG_INFO, "searching for mx property with subject %s", subject);
		np_msgproperty_t* prop = np_msgproperty_get(INBOUND, subject);

		if (prop == NULL) {
			np_new_obj(np_msgproperty_t, prop);
			prop->msg_subject = strndup(subject, 255);
			prop->mode_type = INBOUND;
			np_msgproperty_register(prop);
            log_msg(LOG_INFO, "registered python subject %s (length: %lu)", subject, strlen(subject));
		} else {
		    log_msg(LOG_INFO, "found mx property with subject %s", prop->msg_subject);
		}

        PyGILState_Release(gstate);
		return prop;
	}

    void set_authn_func(PyObject *PyFunc)
    {
        PyGILState_STATE gstate;
        gstate = PyGILState_Ensure();

        Py_XDECREF(py_authenticate_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);               /* Add a reference to new callback */
        py_authenticate_func = PyFunc;    /* Remember new callback */
        np_setauthenticate_cb(python_authenticate_callback);

        PyGILState_Release(gstate);
    }

    void set_authz_func(PyObject *PyFunc)
    {
        PyGILState_STATE gstate;
        gstate = PyGILState_Ensure();

        Py_XDECREF(py_authorize_func); /* Dispose of previous callback */
        Py_XINCREF(PyFunc);            /* Add a reference to new callback */
        py_authorize_func = PyFunc;    /* Remember new callback */
        np_setauthorizing_cb(python_authorize_callback);

        PyGILState_Release(gstate);
    }

    void set_acc_func(PyObject *PyFunc)
    {
        PyGILState_STATE gstate;
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
%ignore _np_ping_send;
%ignore np_time_now;
%ignore _np_send_simple_invoke_request;

%include "neuropil.h"
