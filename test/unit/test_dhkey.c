//
// SPDX-FileCopyrightText: 2016-2021 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
#include <criterion/criterion.h>
#include <inttypes.h>

#include "sodium.h"
#include "event/ev.h"

#include "np_dhkey.h"
#include "np_memory.h"

#include "neuropil_log.h"
#include "np_log.h"

#include "../test_macros.c"

TestSuite(np_dhkey_t);

Test(np_dhkey_t, _dhkey_add_sub, .description="test the addition/substraction of dhkeys")
{
	np_dhkey_t key_1 = { .t[0] = 1, .t[1] = 1, .t[2] = 1, .t[3] = 1 ,.t[4] = 1 ,.t[5] = 1 ,.t[6] = 1 ,.t[7] = 1 };
	np_dhkey_t key_2 = { .t[0] = 2, .t[1] = 2, .t[2] = 2, .t[3] = 2 ,.t[4] = 2 ,.t[5] = 2 ,.t[6] = 2 ,.t[7] = 2 };
	np_dhkey_t key_3 = { .t[0] = 3, .t[1] = 3, .t[2] = 3, .t[3] = 3, .t[4] = 3 ,.t[5] = 3 ,.t[6] = 3 ,.t[7] = 3 };
	np_dhkey_t key_4 = { .t[0] = 4, .t[1] = 4, .t[2] = 4, .t[3] = 4, .t[4] = 4 ,.t[5] = 4 ,.t[6] = 4 ,.t[7] = 4 };

	np_dhkey_t key_x7 = { .t[0] = 0xfffffffd, .t[1] = 0xfffffffd, .t[2] = 0xfffffffd, .t[3] = 0xfffffffd,
						  .t[4] = 0xfffffffd, .t[5] = 0xfffffffd, .t[6] = 0xfffffffd, .t[7] = 0xfffffffd };

	np_dhkey_t result;

	_np_dhkey_add(&result, &key_1, &key_1);
	cr_expect_arr_eq(result.t, key_2.t, 8 * sizeof (uint32_t));

	_np_dhkey_add(&result, &key_1, &key_2);
	cr_expect_arr_eq(result.t, key_3.t, 8 * sizeof (uint32_t));

	_np_dhkey_add(&result, &key_1, &key_3);
	cr_expect_arr_eq(result.t, key_4.t, 8 * sizeof (uint32_t));

	_np_dhkey_sub(&result, &key_4, &key_2);
	cr_expect_arr_eq(result.t, key_2.t, 8 * sizeof (uint32_t));

	_np_dhkey_sub(&result, &key_1, &key_4);
	cr_expect_arr_eq(result.t, key_x7.t, 8 * sizeof (uint32_t));

	_np_dhkey_add(&result, &result, &key_4);
	cr_expect_arr_eq(result.t, key_1.t, 8 * sizeof (uint32_t));

}

Test(np_dhkey_t, _np_dhkey_cmp, .description = "test the comparison of dhkeys returning -1 / 0 / 1")
{
	CTX()
	{
		char subject[] = "this.is.a.test";

		np_dhkey_t key_1 = np_dhkey_create_from_hostport( subject, "1");
		np_dhkey_t key_2 = np_dhkey_create_from_hostport( subject, "2");

		cr_expect(-1 == _np_dhkey_cmp(NULL, &key_1), "expected comparison with NULL is -1");
		cr_expect(1 == _np_dhkey_cmp(&key_1, NULL), "expected comparison with NULL is  1");
		cr_expect(0 == _np_dhkey_cmp(&key_1, &key_1), "expected comparison of same key is zero");
		cr_expect(0 == _np_dhkey_cmp(&key_2, &key_2), "expected comparison of same key is zero");
		cr_expect(1 == _np_dhkey_cmp(&key_1, &key_2), "expected comparison of lower key to be -1");
		cr_expect(-1 == _np_dhkey_cmp(&key_2, &key_1), "expected comparison of higher key to be 1");
	}
}
Test(np_dhkey_t, _dhkey_globals, .description = "test the global dhkeys max & half & min")
{
	CTX()
	{
		np_dhkey_t half = np_dhkey_half(context);
		np_dhkey_t max = np_dhkey_max(context);
		np_dhkey_t min = np_dhkey_min(context);

		cr_expect(-1 == _np_dhkey_cmp(&half, &max), "expected dhkey_half to be less than dhkey_max");
		cr_expect(1 == _np_dhkey_cmp(&max, &half), "expected dhkey_half to be less than dhkey_max");
		cr_expect(0 == _np_dhkey_cmp(&half, &half), "expected dhkey_half to be equal to dhkey_half");
		cr_expect(true == _np_dhkey_equal(&max, &max), "expected dhkey_max to be equal to dhkey_max");

		np_dhkey_t result;

		_np_dhkey_add(&result, &half, &half);
		cr_expect(0 == _np_dhkey_cmp(&result, &min), "expected 2*dhkey_half to be dhkey_min");

		_np_dhkey_sub(&result, &half, &half);
		cr_expect(0 == _np_dhkey_cmp(&result, &min), "expected dhkey_half-dhkey_half to be dhkey_min");

		_np_dhkey_sub(&result, &half, &min);
		cr_expect(0 == _np_dhkey_cmp(&result, &half), "expected dhkey_half-dhkey_min to be dhkey_half");

		_np_dhkey_sub(&result, &max, &half);
		cr_expect(-1 == _np_dhkey_cmp(&result, &half), "expected dhkey_max-dhkey_half to less than dhkey_half");
	}
}
Test(np_dhkey_t, _dhkey_equals, .description = "test for equal dhkey's")
{
	CTX() {
		char subject[] = "this.is.a.test";

		np_dhkey_t key_1 = np_dhkey_create_from_hostport( subject, "1");
		np_dhkey_t key_2 = np_dhkey_create_from_hostport( subject, "2");

		cr_expect(true == _np_dhkey_equal(&key_1, &key_1), "expected dhkey's to be equal");
		cr_expect(false == _np_dhkey_equal(&key_1, &key_2), "expected dhkey's to be different");
	}
}

Test(np_dhkey_t, _dhkey_index, .description = "test the common prefix length of two keys")
{
	CTX() {
		char subject[] = "this.is.a.test";

		np_dhkey_t key_1 = np_dhkey_create_from_hostport( subject, "1");
		np_dhkey_t key_2 = np_dhkey_create_from_hostport( subject, "2");
		np_dhkey_t key_3 = np_dhkey_create_from_hostport( subject, "3");
		np_dhkey_t key_4 = np_dhkey_create_from_hostport( subject, "4");
		np_dhkey_t key_5 = np_dhkey_create_from_hostport( subject, "5");

		cr_expect(63 == _np_dhkey_index(&key_1, &key_1), "expected index to be 64");
		cr_expect(0 == _np_dhkey_index(&key_1, &key_2), "expected index to be  0");
		cr_expect(0 == _np_dhkey_index(&key_1, &key_3), "expected index to be  0");
		cr_expect(0 == _np_dhkey_index(&key_1, &key_4), "expected index to be  0");
		cr_expect(1 == _np_dhkey_index(&key_1, &key_5), "expected index to be  1, but received %d", _np_dhkey_index(&key_1, &key_5));
	}
}

Test(np_dhkey_t, _dhkey_hexalpha_at, .description="test for getting the hexalpha int code at a dhkey's position")
{
	CTX() {
		char subject[] = "this.is.a.test";
		np_dhkey_t key_1 = np_dhkey_create_from_hostport( subject, "1");

		// => 7c5f11d1 8315519a 8c4df66e dd0ae509 4aa90a88 adbbc488 3e6ba84c b13cae5d
		uint8_t tmp = 0;
		cr_expect( 7 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 0)) , "idx  0 expected hexalpha_at to be  7 but is: %"PRIu8, tmp);
		// => 7c5f11d1 831_5_519a 8c4df66e dd0ae509 4aa90a88 adbbc488 3e6ba84c b13cae5d
		cr_expect( 5 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 11)), "idx 11 expected hexalpha_at to be  5 but is: %"PRIu8, tmp);
		// => 7c5f11d18315519a8c4df66e_d_d0ae5094aa90a88adbbc4883e6ba84cb13cae5d
		cr_expect(13 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 24)), "idx 24 expected hexalpha_at to be 13 but is: %"PRIu8, tmp);
		// => 7c5f11d1 8315519a 8c4df66e dd0ae509 4aa_9_0a88 adbbc488 3e6ba84c b13cae5d
		cr_expect( 9 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 35)), "idx 35 expected hexalpha_at to be  9 but is: %"PRIu8, tmp);
		// => 7c5f11d18315519a8c4df66edd0ae5094aa90a88adbbc488_3_e6ba84cb13cae5d
		cr_expect( 3 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 48)), "idx 48 expected hexalpha_at to be  3 but is: %"PRIu8, tmp);
		// => 7c5f11d1 8315519a 8c4df66e dd0ae509 4aa90a88 adbbc488 3e6ba84c b13c_a_e5d
		cr_expect(10 == (tmp = _np_dhkey_hexalpha_at(context, &key_1, 60)), "idx 60 expected hexalpha_at to be 10 but is: %"PRIu8, tmp);

		np_dhkey_t key_2 = np_dhkey_create_from_hostport( subject, "2");
		// => cc462cab0a689bfb232b27f4816116a2e04de54f7b0aee1fc179fae41e2c8c62
		char* key_2_reference = "cc462cab0a689bfb232b27f4816116a2e04de54f7b0aee1fc179fae41e2c8c62";
		char ele[2] = { 0 };
		for (int i = 0; i < strlen(key_2_reference); i++) {
			memcpy(ele, key_2_reference + i, 1);
			uint8_t expected_value = (uint8_t)strtoul(ele, NULL, 16);
			uint8_t actual_value = _np_dhkey_hexalpha_at(context, &key_2, i);
			cr_expect(expected_value == actual_value, "expect dhkey representation to be the same at every index. (not so at idx %"PRIi32" expected: %"PRIu8" actual: %"PRIu8")", i, expected_value, actual_value);
		}
	}
}

Test(np_dhkey_t, _dhkey_between, .description = "test the between length of two keys")
{
	CTX() {
		np_dhkey_t key_1 = { .t[0] = 0,.t[1] = 0,.t[2] = 0,.t[3] = 0,.t[4] = 0 ,.t[5] = 0 ,.t[6] = 0 ,.t[7] = 1 };
		np_dhkey_t key_2 = { .t[0] = 0,.t[1] = 0,.t[2] = 0,.t[3] = 0,.t[4] = 0 ,.t[5] = 0 ,.t[6] = 0 ,.t[7] = 2 };
		np_dhkey_t key_3 = { .t[0] = 0,.t[1] = 0,.t[2] = 0,.t[3] = 0,.t[4] = 0 ,.t[5] = 0 ,.t[6] = 0 ,.t[7] = 3 };
		np_dhkey_t key_4 = { .t[0] = 0,.t[1] = 0,.t[2] = 0,.t[3] = 0,.t[4] = 0 ,.t[5] = 0 ,.t[6] = 0 ,.t[7] = 4 };
		np_dhkey_t key_5 = { .t[0] = 0,.t[1] = 0,.t[2] = 0,.t[3] = 0,.t[4] = 0 ,.t[5] = 0 ,.t[6] = 0 ,.t[7] = 5 };

		// test out of bounds
		cr_expect(false == _np_dhkey_between(&key_1, &key_2, &key_3, true), "expected key1 to be not between key2 and key3");
		cr_expect(false == _np_dhkey_between(&key_4, &key_2, &key_3, true), "expected key4 to be not between key2 and key3");
		cr_expect(false == _np_dhkey_between(&key_2, &key_3, &key_1, true), "expected key2 to be not between key3 and key1");
		cr_expect(false == _np_dhkey_between(&key_1, &key_2, &key_3, false), "expected key1 to be not between key2 and key3");
		cr_expect(false == _np_dhkey_between(&key_4, &key_2, &key_3, false), "expected key4 to be not between key2 and key3");

		// test in bounds
		cr_expect(true == _np_dhkey_between(&key_2, &key_1, &key_3, true), "expected key2 to be between key1 and key3");
		cr_expect(true == _np_dhkey_between(&key_2, &key_1, &key_3, false), "expected key2 to be between key1 and key3");
		cr_expect(true == _np_dhkey_between(&key_4, &key_3, &key_1, true), "expected key2 to be between key1 and key3");
		cr_expect(true == _np_dhkey_between(&key_4, &key_3, &key_1, false), "expected key2 to be between key1 and key3");

		// test edges
		cr_expect(true == _np_dhkey_between(&key_2, &key_2, &key_4, true), "expected key2 to be between key2 and key4");
		cr_expect(true == _np_dhkey_between(&key_4, &key_2, &key_4, true), "expected key4 to be between key2 and key4");
		cr_expect(false == _np_dhkey_between(&key_2, &key_2, &key_4, false), "expected key2 to be not between key2 and key4");
		cr_expect(false == _np_dhkey_between(&key_4, &key_2, &key_4, false), "expected key4 to be not between key2 and key4");

	}
}

Test(np_dhkey_t, _dhkey_distance, .description = "test the distance between length of two keys")
{
	CTX() {
		np_dhkey_t key_1 = { .t[0] = 1,.t[1] = 1,.t[2] = 1,.t[3] = 1 ,.t[4] = 1 ,.t[5] = 1 ,.t[6] = 1 ,.t[7] = 1 };
		np_dhkey_t key_2 = { .t[0] = 2,.t[1] = 2,.t[2] = 2,.t[3] = 2 ,.t[4] = 2 ,.t[5] = 2 ,.t[6] = 2 ,.t[7] = 2 };
		np_dhkey_t key_3 = { .t[0] = 3,.t[1] = 3,.t[2] = 3,.t[3] = 3 ,.t[4] = 3 ,.t[5] = 3 ,.t[6] = 3 ,.t[7] = 3 };

		np_dhkey_t result;
		_np_dhkey_distance(&result, &key_3, &key_2);
		cr_expect(0 == _np_dhkey_cmp(&result, &key_1), "expected the result to be key_1");
		_np_dhkey_distance(&result, &key_2, &key_3);
		cr_expect(0 == _np_dhkey_cmp(&result, &key_1), "expected the result to be key_1");
	}
}

Test(np_dhkey_t, _dhkey_hamming_distance, .description = "test the hamming distance between length of two keys")
{
    CTX() {
        np_dhkey_t key_1 = { .t[0] = 1,.t[1] = 1,.t[2] = 1,.t[3] = 1 ,.t[4] = 1 ,.t[5] = 1 ,.t[6] = 1 ,.t[7] = 1 };
        np_dhkey_t key_2 = { .t[0] = 2,.t[1] = 2,.t[2] = 2,.t[3] = 2 ,.t[4] = 2 ,.t[5] = 2 ,.t[6] = 2 ,.t[7] = 2 };
        np_dhkey_t key_3 = { .t[0] = 3,.t[1] = 3,.t[2] = 3,.t[3] = 3 ,.t[4] = 3 ,.t[5] = 3 ,.t[6] = 3 ,.t[7] = 3 };
        np_dhkey_t key_4 = { .t[0] = 4,.t[1] = 4,.t[2] = 4,.t[3] = 4 ,.t[4] = 4 ,.t[5] = 4 ,.t[6] = 4 ,.t[7] = 4 };

        uint8_t result_1, result_2, result_3;

        _np_dhkey_hamming_distance(&result_1, &key_4, &key_1);
        _np_dhkey_hamming_distance(&result_2, &key_4, &key_2);
        _np_dhkey_hamming_distance(&result_3, &key_4, &key_3);

        cr_expect(true == (result_1 == result_2), "expected the result to be key_1");
        cr_expect(true == (result_2  < result_3), "expected the result to be key_1");
        cr_expect(true == (result_1  < result_3), "expected the result to be key_1");
    }
}
