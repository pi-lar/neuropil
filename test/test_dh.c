//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "sodium.h"
#include "np_util.h"
#include "log.h"

int main(int argc, char **argv) {

	int log_level = LOG_ERROR | LOG_WARN | LOG_INFO | LOG_DEBUG | LOG_TRACE;
	log_init("test_dh.log", log_level);

	char subject[] = "this.is.a.test";

	for (int i = 0; i < 100; i++) {
		char* uuid = np_create_uuid(subject, i);
		log_msg(LOG_DEBUG, "uuid size is %u", strlen(uuid));
	}
}
