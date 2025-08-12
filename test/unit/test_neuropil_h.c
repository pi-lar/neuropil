//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include <assert.h>
#include <criterion/criterion.h>
#include <stdlib.h>

#include "../test_macros.c"

#include "neuropil.h"

TestSuite(neuropil_h);

Test(neuropil_h,
     np_token_fingerprint,
     .description = "test the retrieval of a token fingerprint") {
  CTX() {
    np_id old_fp                                   = {0};
    char  old_fp_str[NP_FINGERPRINT_BYTES * 2 + 1] = {0};
    np_id fp                                       = {0};
    char  fp_str[NP_FINGERPRINT_BYTES * 2 + 1]     = {0};

    assert(context != NULL);
    assert(np_module(attributes) != NULL);

    struct np_token token =
        np_new_identity(context, np_time_now() + 3600, NULL);

    np_token_fingerprint(context, token, true, &fp);
    cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES),
              "expect the fingerprint to have changed");
    memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    np_id_str(fp_str, fp);
    np_id_str(old_fp_str, old_fp);
    log_msg(LOG_INFO, NULL, "new fp: %s ### %s: old fp", fp_str, old_fp_str);

    strncpy(token.subject, "urn:np:subject:test_subject", 255);
    np_token_fingerprint(context, token, true, &fp);
    cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES),
              "expect the fingerprint to have changed");
    memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    np_id_str(fp_str, fp);
    np_id_str(old_fp_str, old_fp);
    log_msg(LOG_INFO, NULL, "new fp: %s ### %s: old fp", fp_str, old_fp_str);

    memcpy(token.issuer, old_fp, NP_FINGERPRINT_BYTES);
    np_token_fingerprint(context, token, true, &fp);
    cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES),
              "expect the fingerprint to have changed");
    memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    np_id_str(fp_str, fp);
    np_id_str(old_fp_str, old_fp);
    log_msg(LOG_INFO, NULL, "new fp: %s ### %s: old fp", fp_str, old_fp_str);
  }
}

Test(neuropil_h,
     verify_token_signature,
     .description =
         "test the creation and verification of struct np_token signatures") {

  // create a local context which is not in state np_runnning
  struct np_settings *settings = np_default_settings(NULL);
  snprintf(settings->log_file,
           256,
           "logs/neuropil_test_%s_%s.log",
           "neuropil_h",
           "verify_token_signature");
  settings->log_level |= LOG_GLOBAL;
  settings->n_threads = 1;
  np_context *context = np_new_context(settings);
  cr_assert(context != NULL);
  cr_expect(np_stopped == np_get_status(context),
            "np_get_status returned %" PRIu8,
            np_get_status(context));

  // Create self-signed issuer token
  struct np_token issuer = np_new_identity(context, np_time_now() + 3600, NULL);
  memset(issuer.subject, 0, 255);
  strncpy(issuer.subject, "issuer.entity", strnlen("issuer.entity", 15));
  cr_expect(np_ok == np_sign_identity(context, &issuer, true));
  cr_expect(np_ok == np_use_identity(context, issuer));

  // Create token to be signed by issuer
  struct np_token token = np_new_identity(context, np_time_now() + 3600, NULL);
  memset(token.subject, 0, 255);
  strncpy(token.subject, "signed.entity", strnlen("signed.entity", 15));
  cr_expect(np_ok ==
            np_token_fingerprint(context, issuer, false, &token.issuer));
  log_msg(LOG_DEBUG, NULL, "#### TOKEN SETUP ## self-sign");
  cr_expect(np_ok == np_sign_identity(context, &token, true));

  // for testing safe the secret key, otherwise it will be zeroed when creating
  // the issuer signature
  char temp_sk[NP_SECRET_KEY_BYTES] = {0};
  memcpy(temp_sk, token.secret_key, NP_SECRET_KEY_BYTES);
  // sign the token with the issuing identity
  cr_expect(np_ok == np_sign_identity(context, &token, false));

  memcpy(token.secret_key, temp_sk, NP_SECRET_KEY_BYTES);
  // countersign sign the token with own signatire again (uddates attribute
  // signature)
  cr_expect(np_ok == np_sign_identity(context, &token, true));

  // Verify token with correct issuer
  cr_expect(np_ok == np_verify_issuer(context, token, issuer));

  // Create invalid issuer token
  struct np_token wrong_issuer =
      np_new_identity(context, np_time_now() + 3600, NULL);
  memset(wrong_issuer.subject, 0, 255);
  strncpy(wrong_issuer.subject, "wrong.entity", strnlen("wrong.entity", 15));
  cr_expect(np_ok == np_sign_identity(context, &wrong_issuer, true));

  // Verify token fails with wrong issuer
  cr_expect(np_operation_failed ==
            np_verify_issuer(context, token, wrong_issuer));
  np_destroy(context, false);
}
