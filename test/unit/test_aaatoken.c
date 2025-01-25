//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>

#include "../test_macros.c"
#include "event/ev.h"
#include "sodium.h"

#include "neuropil_log.h"

#include "core/np_comp_msgproperty.h"
#include "util/np_serialization.h"

#include "np_aaatoken.h"
#include "np_constants.h"
#include "np_glia.h"
#include "np_keycache.h"
#include "np_legacy.h"
#include "np_log.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_node.h"
#include "np_token_factory.h"

TestSuite(np_aaatoken_t);

Test(np_aaatoken_t,
     create_node_token,
     .description = "test the creation of a node token") {
  CTX() {
    np_aaatoken_t *test_token_1 = NULL;

    np_key_t *test_key = NULL;

    np_dhkey_t dhkey = {.t[0] = 1,
                        .t[1] = 1,
                        .t[2] = 1,
                        .t[3] = 1,
                        .t[4] = 1,
                        .t[5] = 1,
                        .t[6] = 1,
                        .t[7] = 1};
    np_new_obj(np_key_t, test_key);
    test_key->dhkey = dhkey;

    // np_node_t* test_node = NULL;
    // np_new_obj(np_node_t, test_node, ref_key_node);
    // _np_node_update(test_node, IPv4 | UDP, "localhost", "1111");
    // test_key->node = test_node;

    test_token_1 = _np_token_factory_new_node_token(context);
    cr_assert(NULL != test_token_1, "expect the token to be not NULL");

    // re-set the validity of this token for this test only
    test_token_1->expires_at = test_token_1->not_before + 3.;
    _np_aaatoken_set_signature(test_token_1, NULL); // self signed
    cr_expect(true == _np_aaatoken_is_valid(context,
                                            test_token_1,
                                            np_aaatoken_type_node),
              "expect that the token is valid");

    np_tree_t *aaa_tree = np_tree_create();
    np_aaatoken_encode(aaa_tree, test_token_1);

    np_aaatoken_t *test_token_2 =
        np_token_factory_read_from_tree(context, aaa_tree);
    // np_new_obj(np_aaatoken_t, test_token_2);
    // np_aaatoken_decode(aaa_tree, test_token_2);
    cr_assert(test_token_2 != NULL, "expect a token");
    cr_assert(true == _np_aaatoken_is_valid(context,
                                            test_token_1,
                                            np_aaatoken_type_node),
              "expect that the 1.token (%s) is valid",
              test_token_1->uuid);
    cr_assert(true == _np_aaatoken_is_valid(context,
                                            test_token_2,
                                            np_aaatoken_type_node),
              "expect that the 2.token (%s) is valid",
              test_token_2->uuid);

    size_t buf_size = 65536;
    char   buffer[buf_size];
    void  *buf_ptr = buffer;
    memset(buf_ptr, 0, buf_size);

    np_serialize_buffer_t serializer = {
        ._tree          = aaa_tree,
        ._target_buffer = buffer,
        ._buffer_size   = buf_size,
        ._error         = 0,
        ._bytes_written = 0,
    };
    np_serializer_write_map(context, &serializer, aaa_tree);

    np_tree_t *out_jrb = np_tree_create();

    np_deserialize_buffer_t deserializer = {
        ._target_tree = out_jrb,
        ._buffer      = buffer,
        ._buffer_size = buf_size,
        ._error       = 0,
        ._bytes_read  = 0,
    };
    np_serializer_read_map(context, &deserializer, out_jrb);

    np_aaatoken_t *test_token_3 = NULL;
    np_new_obj(np_aaatoken_t, test_token_3);
    np_aaatoken_decode(out_jrb, test_token_3);

    cr_assert(true == _np_aaatoken_is_valid(context,
                                            test_token_1,
                                            np_aaatoken_type_node),
              "expect that the 1st token is valid");
    cr_assert(true == _np_aaatoken_is_valid(context,
                                            test_token_2,
                                            np_aaatoken_type_node),
              "expect that the 2nd token is valid");
    cr_assert(true == _np_aaatoken_is_valid(context,
                                            test_token_3,
                                            np_aaatoken_type_node),
              "expect that the 3rd token is valid");

    ev_sleep(3.);

    cr_assert(false == _np_aaatoken_is_valid(context,
                                             test_token_1,
                                             np_aaatoken_type_node),
              "expect that the 1.token is not valid");
    cr_assert(false == _np_aaatoken_is_valid(context,
                                             test_token_3,
                                             np_aaatoken_type_node),
              "expect that the 3.token is not valid");

    np_unref_obj(np_key_t, test_key, ref_obj_creation);
    np_unref_obj(np_aaatoken_t,
                 test_token_1,
                 "_np_token_factory_new_node_token");
    np_unref_obj(np_aaatoken_t,
                 test_token_2,
                 "np_token_factory_read_from_tree");
    np_unref_obj(np_aaatoken_t, test_token_3, ref_obj_creation);
  }
}

Test(np_aaatoken_t,
     encode_decode_loop,
     .description = "test the encoding and decoding of an aaa token") {
  CTX() {
    np_aaatoken_t *ref          = NULL;
    np_aaatoken_t *test_token_1 = NULL;
    np_aaatoken_t *test_token_2 = NULL;
    np_key_t      *test_key     = NULL;

    // np_node_t* test_node = NULL;
    // np_new_obj(np_node_t, test_node);
    // _np_node_update(test_node, IPv4 | UDP, "localhost", "1111");

    ref = _np_token_factory_new_node_token(context);

    np_new_obj(np_key_t, test_key);
    test_key->dhkey = np_aaatoken_get_fingerprint(ref, false);
    // np_ref_obj(np_node_t, test_node, ref_key_node);
    // test_key->node = test_node;
    // np_ref_obj(np_aaatoken_t, ref, ref_key_aaa_token);
    // test_key->aaa_token = ref;

    test_token_1 = ref;
    for (int i = 0; i < 10; ++i) {
      np_tree_t *tmp = np_tree_create();
      np_aaatoken_encode(tmp, test_token_1);

      np_new_obj(np_aaatoken_t, test_token_2);
      np_aaatoken_decode(tmp, test_token_2);
      test_token_1 = test_token_2;

      np_tree_free(tmp);

      cr_expect(1 == 1, "test the equality of 1");
      cr_expect(0 == strncmp(ref->realm, test_token_1->realm, 255),
                "test the realm to be equal");
      cr_expect(0 == strncmp(ref->issuer, test_token_1->issuer, 65),
                "test the issuer to be equal");
      cr_expect(0 == strncmp(ref->subject, test_token_1->subject, 255),
                "test the subject to be equal");
      // cr_expect( 0 == strncmp((char*) ref->public_key, (char*)
      // test_token_1->public_key, 255), "test the public_key to be equal");
      cr_expect(0 == strncmp(ref->audience, test_token_1->audience, 255),
                "test the audience to be equal");
      cr_expect(0 == strncmp(ref->uuid, test_token_1->uuid, 255),
                "test the uuid to be equal");

      // tree_find_str(test_token_1->extensions, NP_HS_SIGNATURE,
      // new_val_bin(signature, crypto_sign_BYTES));
    }

    np_unref_obj(np_key_t, test_key, ref_obj_creation);
    // np_unref_obj(np_node_t, test_node, ref_obj_creation);
  }
}
Test(np_aaatoken_t,
     test_audience_filtering,
     .description = "test the filtering based on audience/issuer/realm field") {
  CTX() {
    // set a realm name that will be copied into the tokens
    np_set_realm_name(context, "test_realm");

    // create a send msgproerty to create message intent token
    np_msgproperty_conf_t *test_send_prop_1 = NULL;
    np_new_obj(np_msgproperty_conf_t, test_send_prop_1);
    test_send_prop_1->msg_subject = strndup("test_subject", 255);
    test_send_prop_1->mep_type    = REQ_REP;
    test_send_prop_1->ack_mode    = ACK_NONE;
    test_send_prop_1->retry       = 0;
    test_send_prop_1->msg_ttl     = 20.0;
    test_send_prop_1->priority -= 1;
    test_send_prop_1->mode_type     = OUTBOUND;
    test_send_prop_1->max_threshold = 20;

    // create a recv msgproerty to create message intent token
    np_msgproperty_conf_t *test_recv_prop_1 = NULL;
    np_new_obj(np_msgproperty_conf_t, test_recv_prop_1);
    test_recv_prop_1->msg_subject = strndup("test_subject", 255);
    test_recv_prop_1->mep_type    = REQ_REP;
    test_recv_prop_1->ack_mode    = ACK_NONE;
    test_recv_prop_1->retry       = 0;
    test_recv_prop_1->msg_ttl     = 20.0;
    test_recv_prop_1->priority -= 1;
    test_recv_prop_1->mode_type     = INBOUND;
    test_recv_prop_1->max_threshold = 20;

    // create message token
    np_aaatoken_t *test_send_token_1 =
        _np_token_factory_new_message_intent_token(test_send_prop_1);
    np_aaatoken_t *test_recv_token_1 =
        _np_token_factory_new_message_intent_token(test_recv_prop_1);

    /*
                    // add token to our internal ledger
                    _np_aaatoken_add_sender("test_subject", test_send_token_1);
                    _np_aaatoken_add_receiver("test_subject",
       test_recv_token_1);

                    np_sll_t(np_aaatoken_ptr, result);

                    // test sender selection filtering
                    result = _np_aaatoken_get_all_sender(context,
       "test_subject", NULL); cr_expect(1 == sll_size(result), "expecting one
       token as a search result"); sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_sender(context,
       "test_subject", ""); cr_expect(1 == sll_size(result), "expecting one
       token as a search result"); sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_sender(context,
       "test_subject", test_send_token_1->issuer); cr_expect(1 ==
       sll_size(result), "expecting one token as a search result");
                    sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_sender(context,
       "test_subject", "test_realm"); cr_expect(1 == sll_size(result),
       "expecting one token as a search result"); sll_free(np_aaatoken_ptr,
       result);

                    result = _np_aaatoken_get_all_sender(context,
       "test_subject", "other realm"); cr_expect(0 == sll_size(result),
       "expecting no token as a search result"); sll_free(np_aaatoken_ptr,
       result);

                    // test receiver selection filtering
                    result = _np_aaatoken_get_all_receiver(context,
       "test_subject", NULL); cr_expect(1 == sll_size(result), "expecting one
       token as a search result"); sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_receiver(context,
       "test_subject", test_recv_token_1->issuer); cr_expect(1 ==
       sll_size(result), "expecting one token as a search result");
                    sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_receiver(context,
       "test_subject", ""); cr_expect(1 == sll_size(result), "expecting one
       token as a search result"); sll_free(np_aaatoken_ptr, result);

                    result = _np_aaatoken_get_all_receiver(context,
       "test_subject", "test_realm"); cr_expect(1 == sll_size(result),
       "expecting one token as a search result"); sll_free(np_aaatoken_ptr,
       result);

                    result = _np_aaatoken_get_all_receiver(context,
       "test_subject", "other realm"); cr_expect(0 == sll_size(result),
       "expecting no token as a search result"); sll_free(np_aaatoken_ptr,
       result);
    */
  }
}

Test(np_aaatoken_t,
     token_signatures,
     .description = "test creation and verification of signed tokens") {

  CTX() {
    // Create and verify a self-signed token without issuer
    np_aaatoken_t *issuer =
        np_token_factory_new_identity_token(context,
                                            np_time_now() + 3600,
                                            NULL);
    cr_expect(issuer != NULL, "expect the token to be created");
    strncpy(issuer->subject, "issuer", 7);
    // Sign the token
    _np_aaatoken_set_signature(issuer, NULL);
    issuer->state = AAA_AUTHENTICATED | AAA_VALID;

    // Verify signature
    cr_expect(np_ok == _np_aaatoken_verify_signature(issuer, NULL));
    cr_expect(issuer->is_signature_verified == true);
    cr_expect(issuer->is_signature_attributes_verified == true);
    cr_expect(issuer->is_issuer_verified == false);

    // Verify issuer (should pass since no issuer set)
    // cr_expect(np_ok == np_verify_issuer(self_signed, NULL));

    // Create a token signed by another identity
    np_aaatoken_t *signed_token =
        np_token_factory_new_identity_token(context,
                                            np_time_now() + 3600,
                                            NULL);
    cr_expect(signed_token != NULL, "expect the token to be created");
    strncpy(signed_token->subject, "signed_token", 13);
    signed_token->state = AAA_AUTHENTICATED | AAA_VALID;

    // Set issuer and sign
    np_dhkey_t issuer_dhkey = np_aaatoken_get_fingerprint(issuer, false);
    np_id_str(signed_token->issuer, &issuer_dhkey);
    _np_aaatoken_set_signature(signed_token, NULL);   // set own signature
    _np_aaatoken_set_signature(signed_token, issuer); // set issuer signature
    _np_aaatoken_set_signature(signed_token, NULL);   // set own signature

    // Verify issuer fails with wrong issuer
    np_aaatoken_t *wrong_issuer =
        np_token_factory_new_identity_token(context,
                                            np_time_now() + 3600,
                                            NULL);
    cr_expect(wrong_issuer != NULL, "expect the token to be created");
    strncpy(wrong_issuer->subject, "wrong_issuer", 13);
    _np_aaatoken_set_signature(wrong_issuer, NULL);
    wrong_issuer->state = AAA_AUTHENTICATED | AAA_VALID;

    cr_expect(np_operation_failed ==
              _np_aaatoken_verify_signature(signed_token, wrong_issuer));
    cr_expect(signed_token->is_signature_verified == true);
    cr_expect(signed_token->is_signature_attributes_verified == true);
    cr_expect(signed_token->is_issuer_verified == false);

    // Verify signature with real issuer
    cr_expect(np_ok == _np_aaatoken_verify_signature(signed_token, issuer));
    cr_expect(signed_token->is_signature_verified == true);
    cr_expect(signed_token->is_signature_attributes_verified == true);
    cr_expect(signed_token->is_issuer_verified == true);

    // Cleanup
    np_unref_obj(np_aaatoken_t, issuer, "np_token_factory_new_identity_token");
    np_unref_obj(np_aaatoken_t,
                 signed_token,
                 "np_token_factory_new_identity_token");
    np_unref_obj(np_aaatoken_t,
                 wrong_issuer,
                 "np_token_factory_new_identity_token");
  }
}
