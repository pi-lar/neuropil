//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <string.h>
#include "inttypes.h"

#include "sodium.h"
#include "msgpack/cmp.h"

#include "np_message.h"

#include "dtime.h"
#include "np_log.h"
#include "neuropil.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_tree.h"
#include "np_keycache.h"
#include "np_memory.h"
#include "np_msgproperty.h"
#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_val.h"

static const int MSG_ARRAY_SIZE = 1;
static const int MSG_PAYLOADBIN_SIZE = 15;
static const int MSG_FOOTERBIN_SIZE = 10;

// double definition in np_network.c !
static const int MSG_CHUNK_SIZE_1024 = 1024;
static const int MSG_ENCRYPTION_BYTES_40 = 40;

NP_SLL_GENERATE_IMPLEMENTATION(np_message_t);

void _np_message_t_new(void* msg)
{
	np_message_t* msg_tmp = (np_message_t*) msg;

	msg_tmp->uuid = np_create_uuid("msg", 0);

	msg_tmp->header       = np_tree_create();
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "header now (%p: %p->%p)", tmp, tmp->header, tmp->header->flink);
	msg_tmp->properties   = np_tree_create();
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "properties now (%p: %p->%p)", tmp, tmp->properties, tmp->properties->flink);
	msg_tmp->instructions = np_tree_create();
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "instructions now (%p: %p->%p)", tmp, tmp->instructions, tmp->instructions->flink);
	msg_tmp->body         = np_tree_create();
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "body now (%p: %p->%p)", tmp, tmp->body, tmp->body->flink);
	msg_tmp->footer       = np_tree_create();

	msg_tmp->no_of_chunks = 1;
	msg_tmp->is_single_part = FALSE;

	pll_init(np_messagepart_ptr, msg_tmp->msg_chunks);
}

// destructor of np_message_t
void _np_message_t_del(void* data)
{
	np_message_t* msg = (np_message_t*) data;

//	if (NULL != np_tree_find_str(msg->instructions, NP_MSG_INST_UUID)) {
//		char* msg_uuid = np_tree_find_str(msg->instructions, NP_MSG_INST_UUID)->val.value.s;
//		log_msg(LOG_MESSAGE | LOG_DEBUG, "now deleting msg (%s) %p / %p", msg_uuid, msg, msg->msg_chunks);
//	}

	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free header",msg->uuid);
	np_tree_free(msg->header);
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now deleting instructions %p", msg->instructions);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free instructions",msg->uuid);
	np_tree_free(msg->instructions);
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now deleting properties %p", msg->properties);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free properties",msg->uuid);
	np_tree_free(msg->properties);
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now deleting body %p", msg->body);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free body",msg->uuid);
	np_tree_free(msg->body);
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now deleting footer %p", msg->footer);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free footer",msg->uuid);
	np_tree_free(msg->footer);

	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) delete free msg_chunks",msg->uuid);
	if (0 < pll_size(msg->msg_chunks))
	{
		pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
		while (NULL != iter)
		{
			np_messagepart_ptr current_part = iter->val;
			free(current_part->msg_part);
			free(current_part);
			pll_next(iter);
		}
	}
	pll_free(np_messagepart_ptr, msg->msg_chunks);

	free(msg->uuid);
}

void _np_message_calculate_chunking(np_message_t* msg)
{
	// np_tree_del_str(msg->footer, NP_MSG_FOOTER_GARBAGE);

	// TODO: message part split-up informations
	uint16_t fixed_size =
			MSG_ARRAY_SIZE + MSG_ENCRYPTION_BYTES_40 + MSG_PAYLOADBIN_SIZE +
			msg->header->byte_size + msg->instructions->byte_size;
	uint16_t payload_size = msg->properties->byte_size
			+ msg->body->byte_size + msg->footer->byte_size;

	uint16_t chunks =
			((uint16_t) (payload_size) / (MSG_CHUNK_SIZE_1024 - fixed_size)) + 1;

//	uint16_t garbage_size = (chunks*MSG_CHUNK_SIZE_1024 - chunks*fixed_size) - payload_size;
//
//	if (garbage_size <= (strlen(NP_MSG_FOOTER_GARBAGE) + MSG_FOOTERBIN_SIZE) )
//	{
//		// TODO: check if this recalculation is working
//		log_msg(LOG_INFO, "recalculating garbage size for %s", msg->uuid);
//		chunks++;
//		garbage_size = (chunks*MSG_CHUNK_SIZE_1024 - chunks*fixed_size) - payload_size;
//	}
//
//	uint16_t real_garbage_size = garbage_size - strlen(NP_MSG_FOOTER_GARBAGE) - MSG_FOOTERBIN_SIZE - chunks*MSG_ARRAY_SIZE;
//
//	unsigned char garbage[real_garbage_size];
//	randombytes_buf(garbage, real_garbage_size);
//	np_tree_insert_str(msg->footer, NP_MSG_FOOTER_GARBAGE, new_val_bin(garbage, real_garbage_size));

	msg->no_of_chunks = chunks;

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "Size of msg (%s) %"PRIu16" bytes. Size of garbage %"PRIu16" Size of fixed_size %"PRIu16" bytes. Chunking into %"PRIu16" parts", msg->uuid, payload_size, real_garbage_size, fixed_size, msg->no_of_chunks);
}

np_message_t* _np_message_check_chunks_complete(np_message_t* msg_to_check)
{
	np_state_t* state = _np_state();

	char* subject = np_tree_find_str(msg_to_check->header, _NP_MSG_HEADER_SUBJECT)->val.value.s;
	char* msg_uuid = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_UUID)->val.value.s;

	uint16_t msg_chunks = np_tree_find_str(msg_to_check->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];

	if (1 < msg_chunks)
	{
		np_message_t* msg_to_submit = NULL;

		if (NULL != np_tree_find_str(state->msg_part_cache, msg_uuid))
		{
			msg_to_submit = np_tree_find_str(state->msg_part_cache, msg_uuid)->val.value.v;
			np_messagepart_ptr to_add = pll_head(np_messagepart_ptr, msg_to_check->msg_chunks);
			log_msg(LOG_MESSAGE | LOG_DEBUG,
					"message (%s) %p / %p / %p", msg_uuid, msg_to_submit, msg_to_submit->msg_chunks, to_add);
			pll_insert(np_messagepart_ptr, msg_to_submit->msg_chunks, to_add, FALSE, _np_messagepart_cmp);
		}
		else
		{
			np_tree_insert_str(state->msg_part_cache, msg_uuid, new_val_v(msg_to_check));
			msg_to_submit = msg_to_check;
			np_ref_obj(np_message_t, msg_to_check);
	//		log_msg(LOG_MESSAGE | LOG_DEBUG,
	//				"message (%s)  %p / %p", msg_uuid, args->msg, args->msg->msg_chunks);
		}

		if (pll_size(msg_to_submit->msg_chunks) < msg_chunks)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG,
					"message %s (%s) not complete yet (%d of %d), waiting for missing parts",
					subject, msg_uuid, pll_size(msg_to_submit->msg_chunks), msg_chunks);

			return (NULL);
		}
		else
		{
			np_tree_del_str(state->msg_part_cache, msg_uuid);
		}

		log_msg(LOG_MESSAGE | LOG_DEBUG,
				"message %s (%s) is complete now  (%d of %d)",
				subject, msg_uuid, pll_size(msg_to_submit->msg_chunks), msg_chunks);
		return (msg_to_submit);
	}
	else
	{
		log_msg(LOG_MESSAGE | LOG_DEBUG,
				"message %s (%s) is unchunked  ", subject, msg_uuid);
		return (msg_to_check);
	}
}

np_bool _np_message_serialize(np_jobargs_t* args)
{
	cmp_ctx_t cmp;
	np_messagepart_ptr part = pll_first(args->msg->msg_chunks)->val;
	// we simply override the header and instructions part for a single part message here
	// the byte size should be the same as before
    cmp_init(&cmp, part->msg_part, buffer_reader, buffer_writer);
	cmp_write_array(&cmp, 5);

	int i = cmp.buf-part->msg_part;
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->header->size);
	serialize_jrb_node_t(args->msg->header, &cmp);
	log_msg(LOG_MESSAGE | LOG_DEBUG,
			"serialized the header (size %llu / %ld)", args->msg->header->byte_size, (cmp.buf-part->msg_part-i));
	i = cmp.buf-part->msg_part;

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the instructions (size %hd)", msg->header->size);
	serialize_jrb_node_t(args->msg->instructions, &cmp);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "serialized the instructions (size %llu / %ld)", args->msg->instructions->byte_size, (cmp.buf-part->msg_part-i));
	// i = cmp.buf-part->msg_part;

	return (TRUE);
}

np_bool _np_message_serialize_chunked(np_jobargs_t* args)
{
	np_bool ret_val = FALSE;
	np_message_t* msg = args->msg;

	// clean up any old chunking
	if (0 < pll_size(msg->msg_chunks))
	{
		pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
		while (NULL != iter)
		{
			np_messagepart_ptr current_part = iter->val;
			free(current_part->msg_part);
			free(current_part);
			pll_next(iter);
		}
		pll_clear(np_messagepart_ptr, msg->msg_chunks);
	}

	// TODO: optimize, more streaming
	// target is an array of 1024 byte size target buffers
    cmp_ctx_t cmp;
    uint16_t i = 0;

    cmp_ctx_t cmp_header;
    void* bin_header = NULL;

    cmp_ctx_t cmp_instructions;
    void* bin_instructions = NULL;

    cmp_ctx_t cmp_properties;
    void* bin_properties = NULL;
    void* bin_properties_ptr = NULL;
    np_bool properties_done = FALSE;

    cmp_ctx_t cmp_body;
    void* bin_body = NULL;
    void* bin_body_ptr = NULL;
    np_bool body_done = FALSE;

    cmp_ctx_t cmp_footer;
    void* bin_footer = NULL;
    void* bin_footer_ptr = NULL;
    np_bool footer_done = FALSE;

	uint16_t max_chunk_size = (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

	np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0] = msg->no_of_chunks;

	uint16_t current_chunk_size = 0;

    while (i < msg->no_of_chunks)
    {
		np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1] = i+1;

		np_messagepart_ptr part = (np_messagepart_ptr) malloc(sizeof(np_messagepart_t));
		CHECK_MALLOC(part);

		if (NULL == part)
		{
			ret_val = FALSE;
			goto __np_cleanup__;
		}

		part->header = msg->header;
		// TODO: possible error ? have to pass the chunk number explicitly
		part->instructions = msg->instructions;
		part->part = i;
		part->msg_part = malloc(max_chunk_size * sizeof(char));
		CHECK_MALLOC(part->msg_part);
		if (NULL == part->msg_part)
		{
			ret_val = FALSE;
			free(part);
			goto __np_cleanup__;
		}

		// pre-fill some garbage
		randombytes_buf(part->msg_part, max_chunk_size);

		cmp_init(&cmp, part->msg_part, buffer_reader, buffer_writer);
		cmp_write_array(&cmp, 5);

		// current_chunk_size = cmp.buf - part->msg_part;
		if (NULL == bin_header)
		{
			// TODO: optimize memory handling and allocate memory during serialization
			bin_header = malloc(msg->header->byte_size);
			CHECK_MALLOC(bin_header);

			if (NULL == bin_header)
			{
				ret_val = FALSE;
				free(part);
				goto __np_cleanup__;
			}

			memset(bin_header, 0, msg->header->byte_size);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->properties->size);
		    cmp_init(&cmp_header, bin_header, buffer_reader, buffer_writer);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->header->byte_size);
			serialize_jrb_node_t(msg->header, &cmp_header);
		}

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "copying the header (size %hd)", msg->header->byte_size);
		memcpy(cmp.buf, bin_header, msg->header->byte_size);
		cmp.buf += msg->header->byte_size;
		// current_chunk_size = cmp.buf-part->msg_part;

		bin_instructions = malloc(msg->instructions->byte_size);
		CHECK_MALLOC(bin_instructions);

		if (NULL == bin_instructions)
		{
			ret_val = FALSE;
			free(part);
			goto __np_cleanup__;
		}

		memset(bin_instructions, 0, msg->instructions->byte_size);
		// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the instructions (size %hd)", msg->properties->size);
		cmp_init(&cmp_instructions, bin_instructions, buffer_reader, buffer_writer);
		// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the instructions (size %hd)", msg->instructions->byte_size);
		serialize_jrb_node_t(msg->instructions, &cmp_instructions);

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "copying the instructions (size %hd)", msg->instructions->byte_size);
		memcpy(cmp.buf, bin_instructions, msg->instructions->byte_size);
		cmp.buf += msg->instructions->byte_size;

		free(bin_instructions);
		bin_instructions = NULL;

		current_chunk_size = cmp.buf - part->msg_part;

		if (NULL == bin_properties)
		{
			// TODO: optimize memory handling and allocate memory during serialization
			bin_properties = malloc(msg->properties->byte_size);
			CHECK_MALLOC(bin_properties);

			if (NULL == bin_properties)
			{
				ret_val = FALSE;
				free(part);
				goto __np_cleanup__;
			}

			bin_properties_ptr = bin_properties;
			memset(bin_properties, 0, msg->properties->byte_size);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the properties (size %hd)", msg->properties->size);
		    cmp_init(&cmp_properties, bin_properties, buffer_reader, buffer_writer);
			serialize_jrb_node_t(msg->properties, &cmp_properties);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the properties (size %hd)", msg->properties->byte_size);
		}

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "before properties: space left in chunk: %hd / %hd",
		// 		(max_chunk_size - current_chunk_size), current_chunk_size );

		if (15 < (max_chunk_size - current_chunk_size) && FALSE == properties_done)
		{
			uint16_t left_properties_size = msg->properties->byte_size - (bin_properties_ptr - bin_properties);
			uint16_t possible_size = max_chunk_size - 15 - current_chunk_size;
			if (possible_size >= left_properties_size)
			{
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing last properties part (size %hd)", left_properties_size);
				cmp_write_bin32(&cmp, bin_properties_ptr, left_properties_size);
				bin_properties_ptr += left_properties_size;
				properties_done = TRUE;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "wrote all properties (size %hd)", msg->properties->byte_size);
			}
			else
			{
				cmp_write_bin32(&cmp, bin_properties_ptr, possible_size);
				bin_properties_ptr += possible_size;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing properties part (size %hd)", possible_size);
			}
		}
		else
		{
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "copying empty tree (size %hd)", empty_tree->byte_size);
			cmp_write_bin32(&cmp, bin_properties_ptr, 0);
			// memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
			// cmp.buf += empty_tree->byte_size;
		}
		current_chunk_size = cmp.buf - part->msg_part;

		if (NULL == bin_body)
		{
			// TODO: optimize memory handling and allocate memory during serialization
			bin_body = malloc(msg->body->byte_size);
			CHECK_MALLOC(bin_body);

			if (NULL == bin_body)
			{
				ret_val = FALSE;
				free(part);
				goto __np_cleanup__;
			}

			bin_body_ptr = bin_body;
			memset(bin_body, 0, msg->body->byte_size);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the body (size %hd)", msg->properties->size);
		    cmp_init(&cmp_body, bin_body, buffer_reader, buffer_writer);
			serialize_jrb_node_t(msg->body, &cmp_body);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the body (size %hd)", msg->body->byte_size);
		}

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "before body: space left in chunk: %hd / %hd",
		// 		(max_chunk_size - current_chunk_size), current_chunk_size );

		if (10 < (max_chunk_size - current_chunk_size) && FALSE == body_done)
		{
			uint16_t left_body_size = msg->body->byte_size - (bin_body_ptr - bin_body);
			uint16_t possible_size = max_chunk_size - 10 - current_chunk_size;
			if (possible_size >= left_body_size)
			{
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing last body part (size %hd)", left_body_size);
				cmp_write_bin32(&cmp, bin_body_ptr, left_body_size);
				bin_body_ptr += left_body_size;
				body_done = TRUE;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "wrote all body (size %hd)", msg->body->byte_size);
			}
			else
			{
				cmp_write_bin32(&cmp, bin_body_ptr, possible_size);
				bin_body_ptr += possible_size;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing body part (size %hd)", possible_size);
			}
		}
		else
		{
			cmp_write_bin32(&cmp, bin_body_ptr, 0);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "copying empty tree (size %hd)", empty_tree->byte_size);
			// memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
			// cmp.buf += empty_tree->byte_size;
		}
		current_chunk_size = cmp.buf - part->msg_part;

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "before footer: space left in chunk: %hd / %hd",
		// 		(max_chunk_size - current_chunk_size), current_chunk_size );

		if (NULL == bin_footer)
		{
			// TODO: optimize memory handling and allocate memory during serialization
			bin_footer = malloc(msg->footer->byte_size);
			CHECK_MALLOC(bin_footer);

			if (NULL == bin_footer)
			{
				ret_val = FALSE;
				free(part);
				goto __np_cleanup__;
			}

			bin_footer_ptr = bin_footer;
			memset(bin_footer, 0, msg->footer->byte_size);
		    cmp_init(&cmp_footer, bin_footer, buffer_reader, buffer_writer);
			serialize_jrb_node_t(msg->footer, &cmp_footer);
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the footer (size %hd)", msg->footer->byte_size);
		}

		if (5 < (max_chunk_size - current_chunk_size) && FALSE == footer_done)
		{
			uint16_t left_footer_size = msg->footer->byte_size - (bin_footer_ptr - bin_footer);
			uint16_t possible_size = max_chunk_size - 5 - current_chunk_size;
			if (possible_size >= left_footer_size)
			{
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing last footer part (size %hd)", left_footer_size);
				cmp_write_bin32(&cmp, bin_footer_ptr, left_footer_size);
				bin_footer_ptr += left_footer_size;
				footer_done = TRUE;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "wrote all footer (size %hd)", msg->footer->byte_size);
			}
			else
			{
				cmp_write_bin32(&cmp, bin_footer_ptr, possible_size);
				bin_footer_ptr += possible_size;
				// log_msg(LOG_MESSAGE | LOG_DEBUG, "writing footer part (size %hd)", possible_size);
			}
		}
		else
		{
			// log_msg(LOG_MESSAGE | LOG_DEBUG, "copying empty tree (size %hd)", empty_tree->byte_size);
			cmp_write_bin32(&cmp, bin_footer_ptr, 0);
			// memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
			// cmp.buf += empty_tree->byte_size;
		}
		// current_chunk_size = cmp.buf - part->msg_part;

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "after footer: space left in chunk: %hd / %hd",
		//  		(max_chunk_size - current_chunk_size), current_chunk_size );
		i++;

		pll_insert(np_messagepart_ptr, msg->msg_chunks, part, FALSE, _np_messagepart_cmp);

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "-------------------------" );
	}
	ret_val = TRUE;
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

	log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg: %s) chunked into %"PRIu32" parts (calculated no of chunks: %"PRIu16")"
			,msg->uuid, pll_size(msg->msg_chunks),msg->no_of_chunks);

    __np_cleanup__:
		if (NULL != bin_footer) free(bin_footer);
		if (NULL != bin_body) free(bin_body);
		if (NULL != bin_properties) free(bin_properties);
		if (NULL != bin_instructions) free(bin_instructions);
		if (NULL != bin_header) free(bin_header);

	return (ret_val);
}

np_bool _np_message_deserialize(np_message_t* msg, void* buffer)
{
	cmp_ctx_t cmp;
	cmp_init(&cmp, buffer, buffer_reader, buffer_writer);

	uint32_t array_size;

	if (!cmp_read_array(&cmp, &array_size))
	{
		log_msg(LOG_WARN, "unrecognized first array element while deserializing message. error: %"PRIu8, cmp.error);
		return (FALSE);
	}

	if (array_size != 5)
	{
		log_msg(LOG_WARN, "unrecognized array length while deserializing message");
		return (FALSE);
	}

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "deserializing msg header");
	deserialize_jrb_node_t(msg->header, &cmp );
	// TODO: check if the complete buffer was read (byte count match)

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "deserializing msg instructions");
	deserialize_jrb_node_t(msg->instructions, &cmp );
	// TODO: check if the complete buffer was read (byte count match)

	if (NULL != np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)) {
		msg->no_of_chunks = np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];
	}

	uint16_t chunk_id = 0;
	if (NULL != np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)) {
		chunk_id = np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1];
	}
	msg->is_single_part = TRUE;

	if (0 == msg->no_of_chunks || 0 == chunk_id){
		log_msg(LOG_WARN, "no_of_chunks (%"PRIu16") or chunk_id (%"PRIu16") zero while deserializing message.",msg->no_of_chunks,chunk_id);
		return (FALSE);
	}

	np_messagepart_ptr part = (np_messagepart_ptr) malloc(sizeof(np_messagepart_t));
	CHECK_MALLOC(part);

	part->header = msg->header;
	part->instructions = msg->instructions;
	part->part = chunk_id;
	part->msg_part = buffer;

	pll_insert(np_messagepart_ptr, msg->msg_chunks, part, FALSE, _np_messagepart_cmp);

	log_msg(LOG_MESSAGE | LOG_DEBUG, "received message part (%d / %d)", chunk_id, msg->no_of_chunks);

	return (TRUE);
}

np_bool _np_message_deserialize_chunked(np_message_t* msg)
{
	void* bin_properties = NULL;
	void* bin_properties_ptr = NULL;
	cmp_ctx_t cmp_properties;
	uint32_t size_properties = 0;

	void* bin_body = NULL;
	void* bin_body_ptr = NULL;
	cmp_ctx_t cmp_body;
	uint32_t size_body = 0;

	void* bin_footer = NULL;
	void* bin_footer_ptr = NULL;
	cmp_ctx_t cmp_footer;
	uint32_t size_footer = 0;

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

	pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
	np_messagepart_ptr current_chunk = NULL;

	while (NULL != iter)
	{
		current_chunk = iter->val;
		log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) now working on msg part %d",msg->uuid, current_chunk->part );
		uint32_t size_properties_add = 0;
		uint32_t size_body_add = 0;
		uint32_t size_footer_add = 0;

		cmp_ctx_t cmp;
		cmp_init(&cmp, current_chunk->msg_part, buffer_reader, buffer_writer);

		uint32_t array_size;
		if (!cmp_read_array(&cmp, &array_size)) return (0);
		if (array_size != 5)
		{
			log_msg(LOG_WARN, "(msg:%s) unrecognized message length while deserializing message", msg->uuid);
			return (FALSE);
		}

		if (0 == msg->header->size)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) deserializing msg header", msg->uuid);
			deserialize_jrb_node_t(msg->header, &cmp);
			// TODO: check if the complete buffer was read (byte count match)
		}
		else
		{
			cmp.buf += msg->header->byte_size;
		}

		if (0 == msg->instructions->size)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) deserializing msg instructions", msg->uuid);
			deserialize_jrb_node_t(msg->instructions, &cmp);
			// TODO: check if the complete buffer was read (byte count match)
		}
		else
		{
			cmp.buf += msg->instructions->byte_size;
		}

		cmp_read_bin_size(&cmp, &size_properties_add);
		if (0 < size_properties_add)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) adding properties part size %u", msg->uuid, size_properties_add);
			size_properties += size_properties_add;
			bin_properties = realloc(bin_properties, size_properties);
			bin_properties_ptr = bin_properties + (size_properties - size_properties_add);
			cmp.read(&cmp, bin_properties_ptr, size_properties_add);
		}
		else
		{
			// cmp.buf += size_properties_add;
		}

		cmp_read_bin_size(&cmp, &size_body_add);
		if (0 < size_body_add)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) adding body part size %u", msg->uuid, size_body_add);
			size_body += size_body_add;
			bin_body = realloc(bin_body, size_body);
			bin_body_ptr = bin_body + (size_body - size_body_add);
			cmp.read(&cmp, bin_body_ptr, size_body_add);
		}
		else
		{
			// cmp.buf += size_body_add;
		}

		cmp_read_bin_size(&cmp, &size_footer_add);
		if (0 < size_footer_add)
		{
			log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) adding footer part size %u", msg->uuid, size_footer_add);
			size_footer += size_footer_add;
			bin_footer = realloc(bin_footer, size_footer);
			bin_footer_ptr = bin_footer + (size_footer - size_footer_add);
			cmp.read(&cmp, bin_footer_ptr, size_footer_add);
		}
		else
		{
			// cmp.buf += size_footer_add;
		}

		// log_msg(LOG_MESSAGE | LOG_DEBUG, "-------------------------" );
		pll_next(iter);
	}

	if (NULL != bin_properties)
	{
		log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) deserializing msg properties %u", msg->uuid, size_properties);
		cmp_init(&cmp_properties, bin_properties, buffer_reader, buffer_writer);
		deserialize_jrb_node_t(msg->properties, &cmp_properties);
		// TODO: check if the complete buffer was read (byte count match)

	}

	if (NULL != bin_body)
	{
		log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) deserializing msg body %u", msg->uuid, size_body);
		cmp_init(&cmp_body, bin_body, buffer_reader, buffer_writer);
		deserialize_jrb_node_t(msg->body, &cmp_body);
		// TODO: check if the complete buffer was read (byte count match)

	}

	if (NULL != bin_footer)
	{
		log_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) deserializing msg footer %u", msg->uuid, size_footer);
		cmp_init(&cmp_footer, bin_footer, buffer_reader, buffer_writer);
		deserialize_jrb_node_t(msg->footer, &cmp_footer);
		// TODO: check if the complete buffer was read (byte count match)
	}

	if (0 < pll_size(msg->msg_chunks))
	{
		pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
		while (NULL != iter)
		{
			np_messagepart_ptr current_part = iter->val;
			free(current_part->msg_part);
			free(current_part);
			pll_next(iter);
		}
		pll_clear(np_messagepart_ptr, msg->msg_chunks);
	}

	uint16_t fixed_size =
			MSG_ARRAY_SIZE + MSG_ENCRYPTION_BYTES_40 + MSG_PAYLOADBIN_SIZE +
			msg->header->byte_size + msg->instructions->byte_size;
	uint16_t payload_size = msg->properties->byte_size
			+ msg->body->byte_size + msg->footer->byte_size;

	log_msg(LOG_MESSAGE | LOG_DEBUG, "msg (%s) Size of msg  %"PRIu16" bytes. Size of fixed_size %"PRIu16" bytes. Nr of chunks  %"PRIu16" parts", msg->uuid, payload_size, fixed_size, msg->no_of_chunks);

	free(bin_footer);
	free(bin_body);
	free(bin_properties);

	np_tree_del_str(msg->footer, NP_MSG_FOOTER_GARBAGE);
	msg->is_single_part = FALSE;

	// log_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

	return (TRUE);
}

/**
 ** message_create:
 ** creates the message to the destination #dest# the message format would be like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message structure.
 */
void _np_message_create(np_message_t* msg, np_key_t* to, np_key_t* from, const char* subject, np_tree_t* the_data)
{
	// np_message_t* new_msg;
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "message ptr: %p %s", msg, subject);

	np_tree_insert_str(msg->header, _NP_MSG_HEADER_SUBJECT,  new_val_s((char*) subject));
	np_tree_insert_str(msg->header, _NP_MSG_HEADER_TO,  new_val_s((char*) _np_key_as_str(to)));
	if (from != NULL) np_tree_insert_str(msg->header, _NP_MSG_HEADER_FROM, new_val_s((char*) _np_key_as_str(from)));
	if (from != NULL) np_tree_insert_str(msg->header, _NP_MSG_HEADER_REPLY_TO, new_val_s((char*) _np_key_as_str(from)));

	if (the_data != NULL)
	{
		_np_message_setbody(msg, the_data);
	}
}

inline void _np_message_setproperties(np_message_t* msg, np_tree_t* properties)
{
	np_tree_free(msg->properties);
	msg->properties = properties;
};

inline void _np_message_setinstructions(np_message_t* msg, np_tree_t* instructions)
{
	np_tree_free(msg->instructions);
	msg->instructions = instructions;
};

inline void _np_message_setbody(np_message_t* msg, np_tree_t* body)
{
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body before %p", msg->body);
	np_tree_free(msg->body);
	msg->body = body;
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body after %p", msg->body);
};

inline void _np_message_set_to(np_message_t* msg, np_key_t* target)
{
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body before %p", msg->body);
	np_tree_replace_str(msg->header, _NP_MSG_HEADER_TO,  new_val_s((char*) _np_key_as_str(target)));
	// log_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body after %p", msg->body);
};

inline void _np_message_setfooter(np_message_t* msg, np_tree_t* footer)
{
	np_tree_free(msg->footer);
	msg->footer = footer;
};

//		if (-1 == _np_messagepart_decrypt(newmsg->instructions,
//										  enc_nonce->val.value.bin,
//										  session_token->session_key, NULL))
//		{
//			log_msg(LOG_ERROR,
//				"incorrect decryption of message instructions (send from %s:%hd)",
//				ipstr, port);
//			job_submit_event(state->jobq, np_network_read);
//			return;
//		}

void _np_message_encrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token)
{
	log_msg(LOG_TRACE, ".start.np_message_encrypt_payload");
	np_state_t* state = _np_state();

	// first encrypt the relevant message part itself
	unsigned char nonce[crypto_box_NONCEBYTES];
	unsigned char sym_key[crypto_secretbox_KEYBYTES];

	randombytes_buf((void*) nonce, crypto_box_NONCEBYTES);
	randombytes_buf((void*) sym_key, crypto_secretbox_KEYBYTES);

	_np_messagepart_encrypt(msg->properties, nonce, sym_key, NULL);
	_np_messagepart_encrypt(msg->body, nonce, sym_key, NULL);

	// now encrypt the encryption key using public key crypto stuff
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	unsigned char ciphertext[crypto_box_MACBYTES + crypto_secretbox_KEYBYTES];

	// convert our own sign key to an encryption key
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,
										 state->my_identity->aaa_token->private_key);
	// convert our partner key to an encryption key
	unsigned char partner_key[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_pk_to_curve25519(partner_key, tmp_token->public_key);

	// finally encrypt
	int ret = crypto_box_easy(ciphertext, sym_key, crypto_secretbox_KEYBYTES, nonce,
							  partner_key, curve25519_sk);
	if (0 > ret)
	{
		log_msg(LOG_ERROR, "encryption of message payload failed");
		return;
	}
/*
	log_msg(LOG_MESSAGE | LOG_DEBUG, "ciphertext: %s", ciphertext);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "nonce:      %s", nonce);
	log_msg(LOG_MESSAGE | LOG_DEBUG, "sym_key:    %s", sym_key);
*/

	// TODO: use sealed boxes instead ???
	// int crypto_box_seal(unsigned char *c, const unsigned char *m,
	// unsigned long long mlen, const unsigned char *pk);

	np_tree_t* encryption_details = np_tree_create();
	// insert the public-key encrypted encryption key for each receiver of the message
	np_tree_insert_str(encryption_details, NP_NONCE,
				   new_val_bin(nonce, crypto_box_NONCEBYTES));
	np_tree_insert_str(encryption_details, tmp_token->issuer,
				   new_val_bin(ciphertext,
						   	    crypto_box_MACBYTES + crypto_secretbox_KEYBYTES));
	// add encryption details to the message
	np_tree_insert_str(msg->properties, NP_SYMKEY, new_val_tree(encryption_details));
	np_tree_free(encryption_details);

	log_msg(LOG_TRACE, ".end  .np_message_encrypt_payload");
}

np_bool _np_message_decrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token)
{
	log_msg(LOG_TRACE, ".start.np_message_decrypt_payload");
	np_state_t* state = _np_state();

	np_tree_t* encryption_details =
			np_tree_find_str(msg->properties, NP_SYMKEY)->val.value.tree;
	if(NULL == encryption_details  ) {
			log_msg(LOG_WARN, "no encryption_details! msg->properties:");
			np_tree_dump2log(msg->properties);
		}
	// insert the public-key encrypted encryption key for each receiver of the message
	unsigned char nonce[crypto_box_NONCEBYTES];
	memcpy(nonce, np_tree_find_str(encryption_details, NP_NONCE)->val.value.bin, crypto_box_NONCEBYTES);
	unsigned char enc_sym_key[crypto_secretbox_KEYBYTES + crypto_box_MACBYTES];


	np_tree_elem_t* encryption_details_elem = np_tree_find_str(encryption_details, (char*) _np_key_as_str(state->my_identity));
	if(NULL == encryption_details_elem  ) {
		log_msg(LOG_ERROR, "decryption of message payload failed. no identity information in encryption_details for %s",_np_key_as_str(state->my_identity));
		log_msg(LOG_DEBUG, "msg->properties:");
		np_tree_dump2log(msg->properties);
		log_msg(LOG_DEBUG, "encryption_details:");
		np_tree_dump2log(encryption_details);
		return (FALSE);
	}
	memcpy(enc_sym_key,
			encryption_details_elem->val.value.bin,
			crypto_secretbox_KEYBYTES + crypto_box_MACBYTES);

	unsigned char sym_key[crypto_secretbox_KEYBYTES];

	// convert own secret to encryption key
	unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,
										 state->my_identity->aaa_token->private_key);

	//	log_msg(LOG_MESSAGE | LOG_DEBUG, "ciphertext: %s", enc_sym_key);
	//	log_msg(LOG_MESSAGE | LOG_DEBUG, "nonce:      %s", nonce);

	// convert partner secret to encryption key
	unsigned char partner_key[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_pk_to_curve25519(partner_key, tmp_token->public_key);

	int ret = crypto_box_open_easy(sym_key, enc_sym_key, crypto_box_MACBYTES + crypto_secretbox_KEYBYTES,
								   nonce, partner_key, curve25519_sk);
	if (0 > ret)
	{
		log_msg(LOG_ERROR, "decryption of message payload failed");
		return (FALSE);
	}
// 	log_msg(LOG_MESSAGE | LOG_DEBUG, "sym_key:    %s", sym_key);

	_np_messagepart_decrypt(msg->properties, nonce, sym_key, NULL);
	_np_messagepart_decrypt(msg->body, nonce, sym_key, NULL);

	log_msg(LOG_TRACE, ".end  .np_message_decrypt_payload");
	return (TRUE);
}

