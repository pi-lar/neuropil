//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <criterion/criterion.h>

#include "np_key.h"
#include "np_keycache.h"
#include "np_memory.h"

#include "np_log.h"
#include "np_threads.h"

#include "../test_macros.c"

TestSuite(np_key_t);

Test(np_key_t, _key_create, .description = "test creation of np_keys")
{
	CTX() {
		np_key_t* key = NULL;
		np_new_obj(np_key_t, key);
		cr_expect(NULL != key, "expect key to be not null");
	}
}

Test(np_key_t, _key_cmp, .description = "test compare function for np_keys")
{
	CTX() {
		np_dhkey_t a, b, c;
		a.t[0] = 1;
		a.t[1] = 2;
		a.t[2] = 3;
		a.t[3] = 4;
		a.t[4] = 5;
		a.t[5] = 6;
		a.t[6] = 7;
		a.t[7] = 8;

		b.t[0] = 1;
		b.t[1] = 2;
		b.t[2] = 3;
		b.t[3] = 4;
		b.t[4] = 5;
		b.t[5] = 6;
		b.t[6] = 7;
		b.t[7] = 8;

		c.t[0] = 5;
		c.t[1] = 6;
		c.t[2] = 7;
		c.t[3] = 8;
		c.t[4] = 9;
		c.t[5] = 10;
		c.t[6] = 11;
		c.t[7] = 12;

		np_key_t* key_a = _np_keycache_create(context, a);
		np_key_t* key_b = _np_keycache_create(context, b);
		np_key_t* key_c = _np_keycache_create(context, c);

		cr_expect(0 == _np_key_cmp(key_a, key_b), "expect keys to be the same");
		cr_expect(0 > _np_key_cmp(key_a, key_c), "expect keys to be not the same");
		cr_expect(0 < _np_key_cmp(key_c, key_a), "expect keys to be not the same");

		cr_expect(0 == _np_key_cmp_inv(key_a, key_b), "expect keys to be the same");
		cr_expect(0 < _np_key_cmp_inv(key_a, key_c), "expect keys to be not the same");
		cr_expect(0 > _np_key_cmp_inv(key_c, key_a), "expect keys to be not the same");
	}
}