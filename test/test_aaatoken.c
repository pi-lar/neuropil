//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "sodium.h"
#include "event/ev.h"

#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_glia.h"
#include "np_keycache.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_constants.h"

void setup_aaatoken(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_AAATOKEN;

	np_log_init("test_aaatoken.log", log_level);
	np_init("udp4", "31416", "localhost");
}

void teardown_aaatoken(void)
{
	np_destroy();
	np_log_destroy();
}

TestSuite(np_aaatoken_t, .init=setup_aaatoken, .fini=teardown_aaatoken);

Test(np_aaatoken_t, create_node_token, .description="test the creation of a node token")
{
	np_aaatoken_t* test_token_1 = NULL;

	np_key_t* test_key = NULL;

	np_dhkey_t dhkey = { .t[0] = 1, .t[1] = 1, .t[2] = 1, .t[3] = 1};
	np_new_obj(np_key_t, test_key);
	test_key->dhkey = dhkey;

	np_node_t* test_node = NULL;
	np_new_obj(np_node_t, test_node, ref_key_node);
	_np_node_update(test_node, IPv4 | UDP, "localhost", "1111");
	test_key->node = test_node;

	test_token_1 = _np_node_create_token(test_node);
	// re-set the validity of this token for this test only
	test_token_1->expiration = test_token_1->not_before + 9.0;

	cr_expect (NULL != test_token_1, "expect the token to be not NULL");
	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_1), "expect that the token is not valid");

	np_tree_t* aaa_tree = np_tree_create();
	np_aaatoken_encode(aaa_tree, test_token_1);

	np_aaatoken_t* test_token_2 = NULL;
	np_new_obj(np_aaatoken_t, test_token_2);
	np_aaatoken_decode(aaa_tree, test_token_2);

	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_1), "expect that the token is valid");
	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_2), "expect that the token is valid");

	cmp_ctx_t cmp_empty;
	char buffer[65536];
	void* buf_ptr = buffer;
	memset(buf_ptr, 0, 65536);

	cmp_init(&cmp_empty, buf_ptr, _np_buffer_reader, _np_buffer_writer);
	_np_tree_serialize(aaa_tree, &cmp_empty);

	np_tree_t* out_jrb = np_tree_create();
	cmp_ctx_t cmp_out;
	cmp_init(&cmp_out, buffer, _np_buffer_reader, _np_buffer_writer);

	_np_tree_deserialize(out_jrb, &cmp_out);

	np_aaatoken_t* test_token_3 = NULL;
	np_new_obj(np_aaatoken_t, test_token_3);
	np_aaatoken_decode(out_jrb, test_token_3);

	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_1), "expect that the token is valid");
	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_2), "expect that the token is valid");
	cr_expect (TRUE == _np_aaatoken_is_valid(test_token_3), "expect that the token is valid");

	ev_sleep(10.0);

	cr_expect (FALSE == _np_aaatoken_is_valid(test_token_1), "expect that the token is not valid");
	cr_expect (FALSE == _np_aaatoken_is_valid(test_token_3), "expect that the token is not valid");

	np_unref_obj(np_key_t, test_key, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, test_token_1, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, test_token_2, ref_obj_creation);
	np_unref_obj(np_aaatoken_t, test_token_3, ref_obj_creation);

}

Test(np_aaatoken_t, encode_decode_loop, .description="test the encoding and decoding of an aaa token")
{
	np_aaatoken_t* ref = NULL;
	np_aaatoken_t* test_token_1 = NULL;
	np_aaatoken_t* test_token_2 = NULL;
	np_key_t* test_key = NULL;

	np_node_t* test_node = NULL;
	np_new_obj(np_node_t, test_node);
	_np_node_update(test_node, IPv4 | UDP, "localhost", "1111");

	ref = _np_node_create_token(test_node);

	np_new_obj(np_key_t, test_key);
	test_key->dhkey = _np_aaatoken_create_dhkey(ref);
	test_key->node = test_node;
	np_ref_obj(np_aaatoken_t, test_node, ref_key_node);
	test_key->aaa_token = ref;
	np_ref_obj(np_aaatoken_t, ref, ref_key_aaa_token);

	test_token_1 = ref;
	for (int i=0; i< 10; ++i)
	{
		np_tree_t* tmp = np_tree_create();
		np_aaatoken_encode(tmp, test_token_1);

		np_new_obj(np_aaatoken_t, test_token_2);
		np_aaatoken_decode(tmp, test_token_2);
		test_token_1 = test_token_2;

		np_tree_free(tmp);

		cr_expect( 1 == 1, "test the equality of 1");
		cr_expect( 0 == strncmp(ref->realm, test_token_1->realm, 255), "test the realm to be equal");
		cr_expect( 0 == strncmp(ref->issuer, test_token_1->issuer, 255), "test the issuer to be equal");
		cr_expect( 0 == strncmp(ref->subject, test_token_1->subject, 255), "test the subject to be equal");
		// cr_expect( 0 == strncmp((char*) ref->public_key, (char*) test_token_1->public_key, 255), "test the public_key to be equal");
		cr_expect( 0 == strncmp(ref->audience, test_token_1->audience, 255), "test the audience to be equal");
		cr_expect( 0 == strncmp(ref->uuid, test_token_1->uuid, 255), "test the uuid to be equal");

		// tree_find_str(test_token_1->extensions, NP_HS_SIGNATURE, new_val_bin(signature, crypto_sign_BYTES));
	}

	np_unref_obj(np_key_t, test_key, ref_obj_creation);
	np_unref_obj(np_node_t, test_node, ref_obj_creation);
}
