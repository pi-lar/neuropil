//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <sys/stat.h>
#include <criterion/criterion.h>

#include "neuropil.h"
#include "np_types.h"

#include "../test_macros.c"

np_state_t* context = NULL;

void np_identity_setup() {
    struct np_settings* settings = np_default_settings(NULL);
    snprintf(settings->log_file, 256, "logs/neuropil_test_np_identity_module.log");
    settings->log_level |= LOG_GLOBAL;
    settings->n_threads = 1;
    context = np_new_context(settings);
    cr_assert(context != NULL);
    cr_assert(np_get_status(context) == np_stopped);
}

void np_identity_destroy() {
    np_destroy(context, false);
}

TestSuite(np_identity, np_identity_setup, np_identity_destroy);

Test(np_identity, np_identity_signing, .description = "test the identity usage/import of the neuropil library")
{
	mkdir("tmp", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
	FILE* buffer = NULL;

	// first step: create a new private key, set some data to the token
	// and use the token for the neuropil subsystem.
	// create a new identity / private key us set to NULL
	struct np_token my_token_1 = np_new_identity(context, np_time_now() + 120.0, NULL);
	// obfuscate our mail address
	np_id my_name_id_1;
	char* my_name_1 = "neuropil-root@neuropil.io";
	np_get_id(&my_name_id_1, my_name_1, strnlen(my_name_1, 255));
	// set obfuscated subject
	memcpy(my_token_1.subject, my_name_id_1, NP_PUBLIC_KEY_BYTES);

	// now tell the context to use this identity
	np_use_identity(context, my_token_1);
	// we need to sign our own token to be able to distribute it to peers as a trusted 'ca'
	np_sign_identity(context, &my_token_1, true);

	// extract fingerprint of issuing token
	np_id my_token_fp;
	np_token_fingerprint(context, my_token_1, false, &my_token_fp);

	// store the secret token in a file
	if ( NULL != (buffer = fopen("./tmp/.np_id", "wb")) ) {
		// convert to base64
		size_t base64_length = sodium_base64_encoded_len(NP_SECRET_KEY_BYTES, sodium_base64_VARIANT_ORIGINAL);
		char base64_array[base64_length];
		sodium_bin2base64(base64_array, base64_length, (unsigned char*) &my_token_1.secret_key, NP_SECRET_KEY_BYTES, sodium_base64_VARIANT_ORIGINAL);
		fwrite(base64_array, base64_length, 1, buffer);
		fclose(buffer);
	}

	// store the public token in a file
	if ( NULL != (buffer = fopen("./tmp/.np_id.pub", "wb")) ) {
		struct np_token pub_token = {0};
		memcpy(&pub_token, &my_token_1, sizeof(struct np_token));
		// and wipe out the secret key from the token
		memset(pub_token.secret_key, 0, NP_SECRET_KEY_BYTES);
		// convert to base64
		size_t token_length = sizeof(struct np_token);
		size_t base64_length = sodium_base64_encoded_len(token_length, sodium_base64_VARIANT_ORIGINAL);
		char base64_array[base64_length];
		sodium_bin2base64(base64_array, base64_length, (unsigned char*) &pub_token, token_length, sodium_base64_VARIANT_ORIGINAL);
		fwrite(base64_array, base64_length, 1, buffer);
		fclose(buffer);
	}

	// create a second identity
	struct np_token my_token_2 = np_new_identity(context, np_time_now() + 60.0, NULL);
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
	memcpy(&my_token_2.issuer, &my_token_fp, sizeof(np_id));

	// update 1: own signature to match changed issuer and subject field (add own signature)
	np_sign_identity(context, &my_token_2, true);
	// update 2: with additional issuer signature in the extenions (issuer signs our token-2 signature)
	np_sign_identity(context, &my_token_2, false);
	// update 3: create a signature for the extensions as well (signe the issuer signature)
	np_sign_identity(context, &my_token_2, true);

	np_id my_token_2_fp;
	np_token_fingerprint(context, my_token_2, true, &my_token_2_fp);
	np_id_str(my_token_fp_str, my_token_2_fp);
	char tmp_filename[255];
	snprintf(tmp_filename, 255, "./tmp/%s", my_token_fp_str);

	// store the secret token in a file
	if ( NULL != (buffer = fopen(tmp_filename, "wb")) ) {
		// convert to base64
		size_t token_length = sizeof(struct np_token);
		size_t base64_length = sodium_base64_encoded_len(token_length, sodium_base64_VARIANT_ORIGINAL);
		char base64_array[base64_length];
		sodium_bin2base64(base64_array, base64_length, (unsigned char*) &my_token_2, token_length, sodium_base64_VARIANT_ORIGINAL);
		fwrite(base64_array, base64_length, 1, buffer);
		fclose(buffer);
	}
}
