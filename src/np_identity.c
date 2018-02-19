#include <inttypes.h>
#include <stdint.h>

#include <sodium.h>

#include "neuropil.h"
#include "np_identity.h"
#include "np_types.h"
#include "np_threads.h"
#include "np_aaatoken.h"
#include "np_memory.h"
#include "np_memory_v2.h"
#include "np_log.h"
#include "np_key.h"
#include "np_tree.h"
#include "np_serialization.h"
#include "np_util.h"


size_t np_identity_export_current(void* buffer) {
	size_t ret = 0;
	if( np_state()->my_identity != NULL &&
		np_state()->my_identity->aaa_token != NULL) {
		ret = np_identity_export(np_state()->my_identity->aaa_token, buffer);
	}

	return ret;
}

size_t np_identity_export(np_aaatoken_t* token, void* buffer) {
	np_tree_t* serialization_tree = np_tree_create();

	np_aaatoken_encode_with_secrets(serialization_tree, token);

	cmp_ctx_t cmp;
	_np_obj_buffer_container_t buffer_container;
	buffer_container.buffer = buffer;
	buffer_container.bufferCount = 0;
	buffer_container.bufferMaxCount = UINT32_MAX;
	buffer_container.obj = NULL;

	cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);

	np_tree_serialize(serialization_tree, &cmp);

	return serialization_tree->byte_size;
}

np_aaatoken_t* np_identity_import(void* buffer, size_t size) {
	np_aaatoken_t* ret = NULL;

	np_tree_t* serialization_tree = np_tree_create();

	cmp_ctx_t cmp;
	_np_obj_buffer_container_t buffer_container;
	buffer_container.buffer = buffer;
	buffer_container.bufferCount = 0;
	buffer_container.bufferMaxCount = size;
	buffer_container.obj = NULL;

	cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);

	if (np_tree_deserialize(serialization_tree, &cmp)) {
		np_new_obj(np_aaatoken_t, ret, __func__);
		np_aaatoken_decode_with_secrets(serialization_tree, ret);
	}

	return ret;
}
