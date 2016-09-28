/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 **/
#include <criterion/criterion.h>

#include "np_util.h"
#include "np_log.h"

void setup_uuid(void)
{
	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	np_log_init("test_uuid.log", log_level);

	_dhkey_init ();
}

void teardown_uuid(void)
{
	EV_P = ev_default_loop(EVFLAG_AUTO | EVFLAG_FORKCHECK);
	ev_run(EV_A_ EVRUN_NOWAIT);
}

TestSuite(np_uuid_t, .init=setup_uuid, .fini=teardown_uuid);

Test(np_uuid_t, _uuid_create, .description="test the creation of unique uuid's")
{
	char* uuid[999];
	char subject[] = "this.is.a.test";

	for (int i = 0; i < 999; i++)
	{
		uuid[i] = np_create_uuid(subject, i);

		cr_expect(36 == strlen(uuid[i]), "expect the size of the uuid to be 32");

		cr_expect('5' == uuid[i][14], "expect to have the value '5' at position 14");
		cr_expect('9' == uuid[i][19], "expect to have the value '9' at position 19");

		cr_expect('-' == uuid[i][8],  "expect to have the value '-' at position 8");
		cr_expect('-' == uuid[i][13], "expect to have the value '-' at position 13");
		cr_expect('-' == uuid[i][18], "expect to have the value '-' at position 18");
		cr_expect('-' == uuid[i][23], "expect to have the value '-' at position 23");

		for (int j = 0; j < i; j++)
		{
			cr_expect(0 != strncmp(uuid[i], uuid[j], 255), "expect the uuid to be unique");
		}
	}
}
