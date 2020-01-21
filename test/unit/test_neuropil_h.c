#include <assert.h>
#include <stdlib.h>

#include <criterion/criterion.h>

#include "neuropil.h"

#include "../test_macros.c"


TestSuite(neuropil_h);

Test(neuropil_h, np_token_fingerprint, .description = "test the retrieval of a token fingerprint")
{
    CTX() {
    		np_id old_fp = {0};
    		char old_fp_str[NP_FINGERPRINT_BYTES*2+1] = {0};
    		np_id fp = {0};
    		char fp_str[NP_FINGERPRINT_BYTES*2+1] = {0};

    		struct np_token token = np_new_identity(context, np_time_now()+3600, NULL);

    		np_token_fingerprint(context, token, true, &fp);
    		cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES), "expect the fingerprint to have changed");
    		memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    		np_id_str(fp_str, fp);
    		np_id_str(old_fp_str, old_fp);
    		log_msg(LOG_INFO, "new fp: %s ### %s: old fp", fp_str, old_fp_str);

    		strncpy(token.subject, "urn:np:subject:test_subject", 255);
    		np_token_fingerprint(context, token, true, &fp);
    		cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES), "expect the fingerprint to have changed");
    		memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    		np_id_str(fp_str, fp);
    		np_id_str(old_fp_str, old_fp);
    		log_msg(LOG_INFO, "new fp: %s ### %s: old fp", fp_str, old_fp_str);

			// This seems wrong, old_fp is no string
    		strncpy(token.issuer, old_fp, 32);
    		np_token_fingerprint(context, token, true, &fp);
    		cr_expect(0 != memcmp(&fp, &old_fp, NP_FINGERPRINT_BYTES), "expect the fingerprint to have changed");
    		memcpy(old_fp, fp, NP_FINGERPRINT_BYTES);

    		np_id_str(fp_str, fp);
    		np_id_str(old_fp_str, old_fp);
    		log_msg(LOG_INFO, "new fp: %s ### %s: old fp", fp_str, old_fp_str);
    }
}
