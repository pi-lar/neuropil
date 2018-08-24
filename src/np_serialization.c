//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <float.h>
#include <errno.h>

#include "msgpack/cmp.h"
#include "inttypes.h"

#include "np_serialization.h"
#include "np_log.h"
#include "np_types.h"

void _np_buffer_set_buffer(struct cmp_ctx_s *ctx,void* new_buffer) {
	if (ctx->read == _np_buffer_container_reader) {
		((_np_obj_buffer_container_t*)ctx->buf)->buffer = new_buffer;
	}
	else {
		ctx->buf = new_buffer;
	}
}
void* _np_buffer_get_buffer(struct cmp_ctx_s *ctx) {
	void * ret = NULL;
	if (ctx->read == _np_buffer_container_reader) {
		ret = ((_np_obj_buffer_container_t*)ctx->buf)->buffer;
	}
	else {
		ret = ctx->buf;
	}

	return ret;
}

bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit)
{
	log_trace_msg(LOG_TRACE, "start: bool _np_buffer_reader(struct cmp_ctx_s *ctx, void *data, size_t limit){");
	memmove(data, ctx->buf, limit);
	ctx->buf += limit;
	return true;
}

bool _np_buffer_skipper(struct cmp_ctx_s *ctx, size_t limit)
{	
	ctx->buf += limit;
	return true;
}

size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count)
{
	log_trace_msg(LOG_TRACE, "start: size_t _np_buffer_writer(struct cmp_ctx_s *ctx, const void *data, size_t count){");
	// log_debug_msg(LOG_DEBUG, "-- writing cmp->buf: %p size: %hd", ctx->buf, count);
	// printf( "-- writing cmp->buf: %p size: %hd\n", ctx->buf, count);

	memmove(ctx->buf, data, count);
	ctx->buf += count;
	return count;
}

bool _np_buffer_container_reader(struct cmp_ctx_s* ctx, void* data, size_t limit)
{
	log_trace_msg(LOG_TRACE, "start: bool _np_buffer_container_reader(struct cmp_ctx_s* ctx, void* data, size_t limit){");
	bool ret = false;
	_np_obj_buffer_container_t* wrapper = ctx->buf;

	size_t nextCount = wrapper->bufferCount + limit;
	/*
	log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
		"BUFFER CHECK Current size: %zu; Max size: %zu; Read size: %zu",
		wrapper->bufferCount, wrapper->bufferMaxCount, limit);
		*/

	if (nextCount > wrapper->bufferMaxCount) {
		
		ctx->error = 14;// LENGTH_READING_ERROR
						/*
		log_msg(LOG_WARN,
			"Read size exceeds buffer. May be invoked due to changed key (see: kb) Current size: %zu; Max size: %zu; Read size: %zu",
			wrapper->bufferCount, wrapper->bufferMaxCount, nextCount);
			*/
	}
	else {
		//log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "memcpy %p <- %p o %p", data, wrapper->buffer, wrapper);
		memcpy(data, wrapper->buffer, limit);
		wrapper->buffer += limit;
		wrapper->bufferCount = nextCount;
		ret = true;
	}
	return ret;
}


bool _np_buffer_container_skipper(struct cmp_ctx_s* ctx, size_t limit)
{
	log_trace_msg(LOG_TRACE, "start: bool _np_buffer_container_skipper(struct cmp_ctx_s* ctx, size_t limit){");
	bool ret = false;
	_np_obj_buffer_container_t* wrapper = ctx->buf;

	size_t nextCount = wrapper->bufferCount + limit;
	/*log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
		"BUFFER CHECK Current size: %zu; Max size: %zu; Skip size: %zu",
		wrapper->bufferCount, wrapper->bufferMaxCount, limit);
		*/
	if (nextCount > wrapper->bufferMaxCount) {		
		ctx->error = 14;// LENGTH_READING_ERROR
						/*
		log_msg(LOG_WARN,
			"Read size exceeds buffer. May be invoked due to changed key (see: kb) Current size: %zu; Max size: %zu; Skip size: %zu",
			wrapper->bufferCount, wrapper->bufferMaxCount, nextCount);
			*/
	}
	else {		
		wrapper->buffer += limit;
		wrapper->bufferCount = nextCount;
		ret = true;
	}
	return ret;
}

size_t _np_buffer_container_writer(struct cmp_ctx_s* ctx, const void* data, size_t count)
{
	log_trace_msg(LOG_TRACE, "start: size_t _np_buffer_container_writer(struct cmp_ctx_s* ctx, const void* data, size_t count){");
	_np_obj_buffer_container_t* wrapper = ctx->buf;

	size_t nextCount = wrapper->bufferCount + count;
	/*log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
		"BUFFER CHECK Current size: %zu; Max size: %zu; Read size: %zu",
		wrapper->bufferCount, wrapper->bufferMaxCount, count);
		*/
	if (nextCount > wrapper->bufferMaxCount) {

		count = 0;
		ctx->error = 15;// LENGTH_WRITING_ERROR
		/*
		log_debug_msg(LOG_WARN,
			"Write size exceeds buffer. Current size: %zu; Max size: %zu; Read size: %zu",
			wrapper->bufferCount, wrapper->bufferMaxCount, nextCount);
			*/
	}
	else {
		memcpy(wrapper->buffer, data, count);
		wrapper->buffer += count;
	}
	return count;
}
