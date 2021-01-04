//
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include "neuropil.h"
#include "np_legacy.h"
#include "util/np_list.h"

struct np_text_exchange_s {
	np_id id;
	uint32_t count;
	uint32_t received;
	np_sll_t(char_ptr, texts);
};
typedef struct np_text_exchange_s* np_text_exchange_ptr;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"

NP_SLL_GENERATE_PROTOTYPES(np_text_exchange_ptr)

NP_SLL_GENERATE_IMPLEMENTATION_COMPARATOR(np_text_exchange_ptr)

NP_SLL_GENERATE_IMPLEMENTATION(np_text_exchange_ptr)

#pragma clang diagnostic pop

np_sll_t(np_text_exchange_ptr, __np_text_exchange) = NULL;

int8_t __np_cmp_np_text_exchange_ptr(np_text_exchange_ptr const te, np_text_exchange_ptr const te_id) {
	return memcmp(&te->id, &te_id->id, sizeof(np_id));
}

bool __np_text_receiver(NP_UNUSED np_context* ac, struct np_message* message) {
	struct np_text_exchange_s te_s = {0};

	memcpy(&te_s.id ,&message->subject, sizeof(te_s));
	np_text_exchange_ptr cache = sll_find(np_text_exchange_ptr, __np_text_exchange, &te_s, __np_cmp_np_text_exchange_ptr, NULL);
	if (cache != NULL) {
		cache->count++;
		sll_append(char_ptr, cache->texts, strndup((char*)message->data, message->data_length));
	}
	return true;
}

DEPRECATED
uint32_t np_receive_text(np_context* ac, char* subject, char** buffer) {

	if (__np_text_exchange == NULL) {
		sll_init(np_text_exchange_ptr, __np_text_exchange);
	}
	np_id subject_dhkey = { 0 };
	np_get_id(&subject_dhkey, subject, 0);

	struct np_text_exchange_s te_s = { 0 };
	memcpy(&te_s.id, &subject_dhkey, sizeof(te_s));

	np_text_exchange_ptr cache = sll_find(np_text_exchange_ptr, __np_text_exchange, &te_s, __np_cmp_np_text_exchange_ptr, NULL);

	if (cache == NULL) {
		cache = malloc(sizeof(struct np_text_exchange_s));
		cache->count = 0;
		cache->received = 0;
		memcpy(&cache->id, &subject_dhkey, sizeof(np_id));
		sll_init(char_ptr, cache->texts);
		np_add_receive_cb(ac, subject, __np_text_receiver);
	}
	char* txt = NULL;
	while ((txt = sll_head(char_ptr, cache->texts)) == NULL) {
		np_time_sleep(0.0);
	}

	if (*buffer == NULL)
	{
		*buffer = txt;
	} else {
		strncpy(*buffer, txt, strnlen(txt, strlen(*buffer)));
		free(txt);
	}

	return cache->received++;
}
