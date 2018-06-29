#include "np_interface.h"
#include "neuropil.h"
#include "np_list.h"

struct np_text_exchange_s {
	np_id id;
	uint32_t count;
	uint32_t received;
	np_sll_t(char_ptr, texts);
};
typedef struct np_text_exchange_s* np_text_exchange_ptr;
NP_SLL_GENERATE_PROTOTYPES(np_text_exchange_ptr);
NP_SLL_GENERATE_IMPLEMENTATION(np_text_exchange_ptr);
np_sll_t(np_text_exchange_ptr, __np_text_exchange) = NULL;

int __np_cmp_np_text_exchange_ptr(const struct np_text_exchange_s * te, const struct np_text_exchange_s * te_id) {
	return memcmp(&te->id, &te_id->id, sizeof(np_id));
}

bool np_text_receiver(np_context* ac, np_id subject_dhkey, uint8_t* message, size_t length) {
	struct np_text_exchange_s te_s = {0};
	memcpy(&te_s.id ,&subject_dhkey,sizeof(te_s));
	np_text_exchange_ptr cache = sll_find(np_text_exchange_ptr, __np_text_exchange, &te_s, __np_cmp_np_text_exchange_ptr, NULL);
	if (cache != NULL) {
		cache->count++;
		sll_append(char_ptr, cache->texts, strndup(message, length));
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
		np_add_receive_cb(ac, &subject_dhkey, np_text_receiver);
	}
	char* txt = NULL;
	while ((txt = sll_head(char_ptr, cache->texts)) == NULL) {
		np_time_sleep(0);
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

DEPRECATED
void np_send_text(np_context* ac, char* subject, char* buffer, uint32_t seq, np_id* target) {
	np_id subject_dhkey = { 0 };
	np_get_id(&subject_dhkey, subject, 0);

	np_send(ac, &subject_dhkey, (uint8_t*)buffer, strlen(buffer)); // ignoring encoding etc for now
}

np_id* np_conversion_dhkey2id(np_id* buffer, np_dhkey_t dh) {	
	char* it = (char*)buffer;
	for (size_t i = 0; i < sizeof(dh.t) / sizeof(dh.t[0]); i++) {
		memcpy(it, &dh.t[0], sizeof(dh.t[0]));
		it += sizeof(dh.t[0]);
	}
	return buffer;
}