#include <criterion/criterion.h>

#include "sodium.h"
#include "event/ev.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_memory.h"
#include "np_msgproperty.h"
#include "np_log.h"

void setup_aaatoken(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_AAATOKEN;
	np_log_init("test_aaatoken.log", log_level);

	np_init(NULL, NULL, FALSE);
}

void teardown_aaatoken(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_aaatoken_t, .init=setup_aaatoken, .fini=teardown_aaatoken);

Test(np_aaatoken_t, create_msg_token, .description="test the creation of a msg token")
{
	np_msgproperty_t* msg_prop = np_msgproperty_get(INBOUND, "this.is.a.test");
	if (NULL == msg_prop)
	{
		np_new_obj(np_msgproperty_t, msg_prop);
		msg_prop->msg_subject = strndup("this.is.a.test", 255);
		msg_prop->mep_type = ANY_TO_ANY;
		msg_prop->mode_type = INBOUND;
		msg_prop->clb_inbound = NULL;
		// when creating, set to zero because callback function is not used
		msg_prop->max_threshold = 10;

		// register the handler so that message can be received
		np_msgproperty_register(msg_prop);
	}

	np_aaatoken_t* test_token_1 = NULL;
	np_new_obj(np_aaatoken_t, test_token_1);

	test_token_1 = _np_create_msg_token(msg_prop);

	cr_expect (NULL != test_token_1);
	cr_expect (TRUE == token_is_valid(test_token_1));

	np_tree_t* aaa_tree = make_jtree();
	np_encode_aaatoken(aaa_tree, test_token_1);

	np_aaatoken_t* test_token_2 = NULL;
	np_new_obj(np_aaatoken_t, test_token_2);
	np_decode_aaatoken(aaa_tree, test_token_2);

	cr_expect (TRUE == token_is_valid(test_token_1));
	cr_expect (TRUE == token_is_valid(test_token_2));

	cmp_ctx_t cmp_empty;
    char buffer[65536];
    void* buf_ptr = buffer;
    memset(buf_ptr, 0, 65536);

    cmp_init(&cmp_empty, buf_ptr, buffer_reader, buffer_writer);
	serialize_jrb_node_t(aaa_tree, &cmp_empty);

	np_tree_t* out_jrb = make_jtree();
	cmp_ctx_t cmp_out;
	// int cmp_err_out;
	cmp_init(&cmp_out, buffer, buffer_reader, buffer_writer);

	deserialize_jrb_node_t(out_jrb, &cmp_out);

	np_aaatoken_t* test_token_3 = NULL;
	np_new_obj(np_aaatoken_t, test_token_3);
	np_decode_aaatoken(out_jrb, test_token_3);

	cr_expect (TRUE == token_is_valid(test_token_1));
	cr_expect (TRUE == token_is_valid(test_token_2));
	cr_expect (TRUE == token_is_valid(test_token_3));

	ev_sleep(10.0);

	cr_expect (FALSE == token_is_valid(test_token_1));



}

