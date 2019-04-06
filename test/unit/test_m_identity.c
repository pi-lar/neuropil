//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "neuropil.h"
#include "np_types.h"

#include "../test_macros.c"

np_state_t* context;

void np_identity_setup() {
    struct np_settings* settings = np_default_settings(NULL);
    snprintf(settings->log_file, 256, "neuropil_test_np_identity_module.log");
    settings->log_level |= LOG_GLOBAL;
    settings->n_threads = 1;
    context = np_new_context(settings);
    assert(context != NULL);
    assert(np_get_status(context) == np_stopped);
}

void np_identity_destroy() {
	np_destroy(context, true);
}

TestSuite(np_identity, np_identity_setup, np_identity_destroy);

Test(np_identity, np_identity_signing, .description = "test the identity usage/import of the neuropil library")
{
	FILE* buffer = NULL;

	// first step: create a new private key, set some data to the token
	// and use the token for the neuropil subsystem.
	// create a new identity / private key us set to NULL
	struct np_token my_token_1 = np_new_identity(context, 20.0, NULL);
	// obfuscate our mail address
	np_id my_name_id_1;
	char* my_name_1 = "neuropil-root@neuropil.io";
	np_get_id(&my_name_id_1, my_name_1, strnlen(my_name_1, 255));
	// set obfuscated subject
	memcpy(my_token_1.subject, my_name_id_1, NP_PUBLIC_KEY_BYTES);

	// now tell the context to use this identity
	np_use_identity(context, my_token_1);

	// extract fingerprint of issuing token
	np_id my_token_fp;
	np_token_fingerprint(context, my_token_1, false, &my_token_fp);

	// store the secret token in a file
	if ( NULL != (buffer = fopen("./.np_id", "wb")) ) {
		// and wipe out the secret key from the token
		fwrite(&my_token_1, sizeof(struct np_token), 1, buffer);
		fclose(buffer);
	}

	// store the public token in a file
	if ( NULL != (buffer = fopen("./.np_id.pub", "wb")) ) {
		struct np_token pub_token = my_token_1;
		memset(pub_token.secret_key, 0, NP_SECRET_KEY_BYTES);
		// and wipe out the secret key from the token
		fwrite(&pub_token, sizeof(struct np_token), 1, buffer);
		fclose(buffer);
	}

	// create a second identity
	struct np_token my_token_2 = np_new_identity(context, 20.0, NULL);
	// obfuscate our mail address
	np_id my_name_id_2;
	char* my_name_2 = "neuropil@neuropil.io";
	np_get_id(&my_name_id_2, my_name_2, strnlen(my_name_2, 255));
	// set obfuscated subject
	memcpy(my_token_2.subject, my_name_id_2, NP_PUBLIC_KEY_BYTES);

	// sign the new identity with our current context identity
	// set obfuscated issuer
	char my_token_fp_str[65];
	np_id_str(my_token_fp_str, my_token_fp);
	strncpy(my_token_2.issuer, my_token_fp_str, 64);
	
	np_sign_identity(context, &my_token_2);

	np_id my_token_2_fp;
	np_token_fingerprint(context, my_token_2, true, &my_token_2_fp);
	np_id_str(my_token_fp_str, my_token_2_fp);

	// store the secret token in a file
	if ( NULL != (buffer = fopen(my_token_fp_str, "wb")) ) {
		fwrite(&my_token_1, sizeof(struct np_token), 1, buffer);
		fclose(buffer);
	}
}