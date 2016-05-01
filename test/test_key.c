#include <criterion/criterion.h>

#include "sodium.h"
#include "event/ev.h"

#include "np_key.h"
#include "np_memory.h"
#include "np_log.h"

void setup_key(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE | LOG_KEY;
	np_mem_init();
	np_log_init("test_key.log", log_level);

	_dhkey_init ();
}

void teardown_key(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_key_t, .init=setup_key, .fini=teardown_key);

Test(np_key_t, _dhkey_add_sub, .description="test the addition/substraction of dhkeys")
{
	np_dhkey_t key_1 = { .t[0] = 1, .t[1] = 1, .t[2] = 1, .t[3] = 1};
	np_dhkey_t key_2 = { .t[0] = 2, .t[1] = 2, .t[2] = 2, .t[3] = 2};
	np_dhkey_t key_3 = { .t[0] = 3, .t[1] = 3, .t[2] = 3, .t[3] = 3};
	np_dhkey_t key_4 = { .t[0] = 4, .t[1] = 4, .t[2] = 4, .t[3] = 4};

	np_dhkey_t result;

	_dhkey_add(&result, &key_1, &key_1);
	cr_expect_arr_eq(result.t, key_2.t, 4 * sizeof (uint64_t));

	_dhkey_add(&result, &key_1, &key_2);
	cr_expect_arr_eq(result.t, key_3.t, 4 * sizeof (uint64_t));

	_dhkey_add(&result, &key_1, &key_3);
	cr_expect_arr_eq(result.t, key_4.t, 4 * sizeof (uint64_t));

	_dhkey_sub(&result, &key_4, &key_2);
	cr_expect_arr_eq(result.t, key_2.t, 4 * sizeof (uint64_t));
}

Test(np_key_t, _dhkey_comp, .description="test the comparison of dhkeys returning -1 / 0 / 1")
{
	char subject[] = "this.is.a.test";

	np_dhkey_t key_1 = dhkey_create_from_hostport(subject, "1");
	np_dhkey_t key_2 = dhkey_create_from_hostport(subject, "2");

	cr_expect(-1  == _dhkey_comp(NULL, &key_1), "expected comparison with NULL is -1" );
	cr_expect( 1  == _dhkey_comp(&key_1, NULL), "expected comparison with NULL is  1" );
	cr_expect( 0  == _dhkey_comp(&key_1, &key_1), "expected comparison of same key is zero" );
	cr_expect( 0  == _dhkey_comp(&key_2, &key_2), "expected comparison of same key is zero" );
	cr_expect(-1  == _dhkey_comp(&key_1, &key_2), "expected comparison of same key is zero" );
	cr_expect( 1  == _dhkey_comp(&key_2, &key_1), "expected comparison of same key is zero" );
}

Test(np_key_t, _dhkey_globals, .description="test the global dhkeys max & half & min")
{
	np_dhkey_t half = dhkey_half();
	np_dhkey_t max  = dhkey_max();
	np_dhkey_t min  = dhkey_min();

	cr_expect(-1  == _dhkey_comp(&half, &max), "expected dhkey_half to be less than dhkey_max" );
	cr_expect( 1  == _dhkey_comp(&max, &half), "expected dhkey_half to be less than dhkey_max" );
	cr_expect( 0  == _dhkey_comp(&half, &half), "expected dhkey_half to be equal to dhkey_half" );
	cr_expect( TRUE  == _dhkey_equal(&max, &max), "expected dhkey_max to be equal to dhkey_max" );

	np_dhkey_t result;

	_dhkey_add(&result, &half, &half);
	cr_expect( 0  == _dhkey_comp(&result, &min), "expected 2*dhkey_half to be dhkey_min" );

	_dhkey_sub(&result, &half, &half);
	cr_expect( 0  == _dhkey_comp(&result, &min), "expected dhkey_half-dhkey_half to be dhkey_min" );

	_dhkey_sub(&result, &half, &min);
	cr_expect( 0  == _dhkey_comp(&result, &half), "expected dhkey_half-dhkey_min to be dhkey_half" );

	_dhkey_sub(&result, &max, &half);
	cr_expect( -1  == _dhkey_comp(&result, &half), "expected dhkey_max-dhkey_half to less than dhkey_half" );
}

Test(np_key_t, _dhkey_equals, .description="test for equal dhkey's")
{
	char subject[] = "this.is.a.test";

	np_dhkey_t key_1 = dhkey_create_from_hostport(subject, "1");
	np_dhkey_t key_2 = dhkey_create_from_hostport(subject, "2");

	cr_expect(TRUE  == _dhkey_equal(&key_1, &key_1), "expected dhkey's to be equal" );
	cr_expect(FALSE == _dhkey_equal(&key_1, &key_2), "expected dhkey's to be different");
}

Test(np_key_t, _dhkey_index, .description="test the common prefix length of two keys")
{
	char subject[] = "this.is.a.test";

	np_dhkey_t key_1 = dhkey_create_from_hostport(subject, "1");
	np_dhkey_t key_2 = dhkey_create_from_hostport(subject, "2");
	np_dhkey_t key_3 = dhkey_create_from_hostport(subject, "3");
	np_dhkey_t key_4 = dhkey_create_from_hostport(subject, "4");
	np_dhkey_t key_5 = dhkey_create_from_hostport(subject, "5");

	cr_expect(63 == _dhkey_index(&key_1, &key_1), "expected index to be 64");
	cr_expect( 0 == _dhkey_index(&key_1, &key_2), "expected index to be  0");
	cr_expect( 0 == _dhkey_index(&key_1, &key_3), "expected index to be  0");
	cr_expect( 0 == _dhkey_index(&key_1, &key_4), "expected index to be  0");
	cr_expect( 1 == _dhkey_index(&key_2, &key_5), "expected index to be  1");
}

Test(np_key_t, _dhkey_hexalpha_at, .description="test for getting the hexalpha int code at a dhkey's position")
{
	char subject[] = "this.is.a.test";

	np_dhkey_t key_1 = dhkey_create_from_hostport(subject, "1");

	cr_expect( 5 == _dhkey_hexalpha_at(&key_1, 12), "expected hexalpha_at to be  5");
	cr_expect(14 == _dhkey_hexalpha_at(&key_1, 24), "expected hexalpha_at to be 14");
	cr_expect( 9 == _dhkey_hexalpha_at(&key_1, 36), "expected hexalpha_at to be  9");
	cr_expect( 3 == _dhkey_hexalpha_at(&key_1, 48), "expected hexalpha_at to be  3");
	cr_expect(12 == _dhkey_hexalpha_at(&key_1, 60), "expected hexalpha_at to be 12");
}

Test(np_key_t, _dhkey_between, .description="test the between length of two keys")
{
	char subject[] = "this.is.a.test";

	np_dhkey_t key_1 = dhkey_create_from_hostport(subject, "1");
	np_dhkey_t key_2 = dhkey_create_from_hostport(subject, "2");
	np_dhkey_t key_3 = dhkey_create_from_hostport(subject, "3");
	np_dhkey_t key_4 = dhkey_create_from_hostport(subject, "4");
	np_dhkey_t key_5 = dhkey_create_from_hostport(subject, "5");

	cr_expect(FALSE == _dhkey_between(&key_1, &key_2, &key_3), "expected key1 to be not between key2 and key3");
	cr_expect(FALSE == _dhkey_between(&key_2, &key_3, &key_4), "expected key2 to be not between key3 and key4");
	cr_expect(FALSE == _dhkey_between(&key_3, &key_4, &key_5), "expected key3 to be not between key4 and key5");
	cr_expect(FALSE == _dhkey_between(&key_4, &key_5, &key_1), "expected key4 to be not between key5 and key1");
	cr_expect(TRUE  == _dhkey_between(&key_5, &key_1, &key_2), "expected key5 to be between key1 and key2");
	// test edges
	cr_expect(TRUE == _dhkey_between(&key_2, &key_2, &key_4), "expected key2 to be between key2 and key4");
	cr_expect(TRUE == _dhkey_between(&key_4, &key_2, &key_4), "expected key4 to be between key2 and key4");

}

Test(np_key_t, _dhkey_distance, .description="test the between length of two keys")
{
	np_dhkey_t key_1 = { .t[0] = 1, .t[1] = 1, .t[2] = 1, .t[3] = 1 };
	np_dhkey_t key_2 = { .t[0] = 2, .t[1] = 2, .t[2] = 2, .t[3] = 2 };
	np_dhkey_t key_3 = { .t[0] = 3, .t[1] = 3, .t[2] = 3, .t[3] = 3 };

	np_dhkey_t result;
	_dhkey_distance(&result, &key_3, &key_2);
	cr_expect(0 == _dhkey_comp(&result, &key_1), "expected the result to be key_1");
}
