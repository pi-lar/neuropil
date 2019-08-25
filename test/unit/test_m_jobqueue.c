//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "np_jobqueue.h"
#include "np_types.h"

#include "../test_macros.c"


TestSuite(np_jobqueue);

// already defined in np_jobqueue.h
/*
	bool np_job_t_compare(np_job_t new_ele, np_job_t j) {
		return (new_ele.priority < j.priority);
	}
	uint16_t np_job_t_binheap_get_priority(np_job_t ele) {
		return ele.priority;
	}
	NP_BINHEAP_GENERATE_PROTOTYPES(np_job_t);
	NP_BINHEAP_GENERATE_IMPLEMENTATION(np_job_t);
*/
Test(np_jobqueue, _np_jobqueue, .description = "test the jobqueue module of the neuropil library")
{
	CTX() {

		// needed test data
		// a key
		np_dhkey_t dhkey = { 0 };
		np_key_t* test_key = _np_keycache_find_or_create(context, dhkey);

		// a subject
		char* test_subject = "urn:np:test:subject";

		// the corresponding msgproperty for the subject
		np_msgproperty_t* msg_prop = NULL;
	    np_new_obj(np_msgproperty_t, msg_prop, __func__);
	    msg_prop->msg_subject = strndup(test_subject, 255);
	    np_msgproperty_register(msg_prop);

	    // a message for the subject
		np_message_t* msg = NULL;
		np_new_obj(np_message_t, msg, ref_obj_creation);
		_np_message_create(msg, dhkey, dhkey, test_subject, "urn:np:test:data:{ name: \"key\", value: \"value\" }");

		cr_expect( NULL != context->np_module_jobqueue, "jobqueue module should be initialized");
		cr_expect( NULL != context->np_module_jobqueue->job_list, "jobqueue job list should be initialized");

		cr_expect( NULL != context->np_module_jobqueue->job_list->elements, "jobqueue job elements should not be NULL");
		cr_expect(  512 == context->np_module_jobqueue->job_list->size, "jobqueue size should be 512 elements");

		cr_expect(   18 == context->np_module_jobqueue->job_list->count, "jobqueue count has 17 jobs (default number of jobs)");

/*
		_np_job_submit_msgin_event(2.0, msg_prop, &test_key, msg, test_subject);
		cr_expect(   18 == context->np_module_jobqueue->job_list->count, "jobqueue count has 18 jobs");

		_np_job_submit_transform_event(context, 1.0, msg_prop, &test_key, msg);
		cr_expect(   19 == context->np_module_jobqueue->job_list->count, "jobqueue count has 19 jobs");

		_np_job_submit_route_event(context, 2.0, msg_prop, &test_key, msg);
		cr_expect(   20 == context->np_module_jobqueue->job_list->count, "jobqueue count has 20 jobs");

		_np_job_submit_msgout_event(context, 1.0, msg_prop, &test_key, msg);
		cr_expect(   21 == context->np_module_jobqueue->job_list->count, "jobqueue count has 21 jobs");
*/
	}
}


