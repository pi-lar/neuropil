
// neuropil is copyright 2016-2021 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef _NP_SERIALIZATION_H_
#define _NP_SERIALIZATION_H_

#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

	struct _np_obj_buffer_container_s
	{
		// needs to be the first element
		void* buffer;
		void* obj;
		size_t bufferCount;
		size_t bufferMaxCount;
	} NP_API_INTERN;

	NP_API_INTERN
		void* _np_buffer_get_buffer(struct cmp_ctx_s *ctx);

	NP_API_INTERN
		void _np_buffer_set_buffer(struct cmp_ctx_s *ctx,void* new_buffer);

	// the following four are helper functions for c-message-pack to work on jtree structures
	NP_API_INTERN
		bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit);
	NP_API_INTERN
		bool _np_buffer_skipper(struct cmp_ctx_s *ctx, size_t limit);
	NP_API_INTERN
		size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count);

	NP_API_INTERN
		bool _np_buffer_container_reader(struct cmp_ctx_s* ctx, void* data, size_t limit);

	NP_API_INTERN
		bool _np_buffer_container_skipper(struct cmp_ctx_s* ctx, size_t limit);
	NP_API_INTERN
		size_t _np_buffer_container_writer(struct cmp_ctx_s* ctx, const void* data, size_t count);

#ifdef __cplusplus
}
#endif

#endif // _NP_SERIALIZATION_H_
