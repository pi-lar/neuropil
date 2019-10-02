//
// neuropil is copyright 2016-2019 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include <string.h>
#include <string.h>
#include "inttypes.h"

#include "event/ev.h"
#include "sodium.h"
#include "msgpack/cmp.h"
#include "tree/tree.h"

#include "np_message.h"

#include "np_log.h"
#include "np_legacy.h"
#include "np_aaatoken.h"
#include "np_axon.h"
#include "np_dendrit.h"
#include "np_glia.h"
#include "np_jobqueue.h"
#include "np_keycache.h"
#include "np_memory.h"

#include "core/np_comp_msgproperty.h"
#include "core/np_comp_node.h"

#include "np_network.h"
#include "np_node.h"
#include "np_threads.h"
#include "np_util.h"
#include "np_tree.h"
#include "np_treeval.h"
#include "np_settings.h"
#include "np_types.h"
#include "np_responsecontainer.h"
#include "np_constants.h"
#include "np_serialization.h"
#include "np_statistics.h"

NP_SLL_GENERATE_IMPLEMENTATION(np_message_ptr);

void _np_message_t_new(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* msg)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_message_t_new(void* msg){");
    np_message_t* msg_tmp = (np_message_t*) msg;

    char mutex_str[64];
    snprintf(mutex_str, 63, "%s", "urn:np:message:msg_chunks");
    _np_threads_mutex_init(context, &msg_tmp->msg_chunks_lock, mutex_str);

    msg_tmp->uuid = np_uuid_create("msg", 0, NULL);

    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "creating uuid %s for new msg", msg_tmp->uuid);
    
    msg_tmp->header         = np_tree_create();
    msg_tmp->instructions   = np_tree_create();
    msg_tmp->body           = np_tree_create();
    msg_tmp->footer         = np_tree_create();
    msg_tmp->send_at	    = 0;
    msg_tmp->no_of_chunks   = 1;
    msg_tmp->is_single_part = false;
    
    pll_init(np_messagepart_ptr, msg_tmp->msg_chunks);	
    msg_tmp->bin_body = NULL;
    msg_tmp->bin_footer = NULL;
    msg_tmp->bin_static = NULL;

    msg_tmp->submit_type = np_message_submit_type_ROUTE;
}

/*
    May allow the system to use the incomming buffer directly
    to populate the tree stuctures (header/body/...)
*/
void _np_message_mark_as_incomming(np_message_t* msg) {

    msg->header->attr.in_place = false;
    msg->instructions->attr.in_place = false; 
    
    msg->body->attr.in_place = true;
    msg->footer->attr.in_place = true;
}

// destructor of np_message_t
void _np_message_t_del(np_state_t *context, NP_UNUSED uint8_t type, NP_UNUSED size_t size, void* data)
{
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: void _np_message_t_del(void* data){");	
    np_message_t* msg = (np_message_t*) data;

    log_debug_msg(LOG_MEMORY | LOG_DEBUG, "msg (%s) freeing memory", msg->uuid);

    np_unref_obj(np_msgproperty_t, msg->msg_property, ref_message_msg_property);
    
    np_tree_free( msg->header);
    np_tree_free( msg->instructions);
    np_tree_free( msg->body);
    np_tree_free( msg->footer);

    _LOCK_ACCESS(&msg->msg_chunks_lock) 
    {    
        if (msg->msg_chunks != NULL)
        {
            pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
            while (NULL != iter)
            {
                np_messagepart_ptr current_part = iter->val;
                np_unref_obj(np_messagepart_t, current_part, ref_message_messagepart);
                pll_next(iter);
            }
            pll_free(np_messagepart_ptr, msg->msg_chunks);
        }
        np_unref_obj(np_messagepart_t, msg->bin_static, ref_message_bin_static);
    }

    free(msg->bin_body);
    free(msg->bin_footer);

    msg->bin_body = NULL;
    msg->bin_footer = NULL;
    msg->bin_static = NULL;
        
    _np_threads_mutex_destroy(context, &msg->msg_chunks_lock);
    free(msg->uuid);
}

void _np_message_calculate_chunking(np_message_t* msg)
{
    np_ctx_memory(msg);

    // TODO: message part split-up informations
    uint32_t header_size = (msg->header == NULL ? 0 : msg->header->byte_size);
    uint32_t instructions_size = (msg->instructions == NULL ? 0 : msg->instructions->byte_size);
    uint32_t fixed_size =
        MSG_ARRAY_SIZE + 
        MSG_ENCRYPTION_BYTES_40 + MSG_PAYLOADBIN_SIZE +
        header_size + instructions_size;

    uint32_t body_size = (msg->body == NULL ? 0 : msg->body->byte_size);
    uint32_t footer_size = (msg->footer == NULL ? 0 : msg->footer->byte_size);
    uint32_t payload_size = body_size + footer_size;

    uint32_t chunks =
            ((uint32_t) (payload_size) / (MSG_CHUNK_SIZE_1024 - fixed_size)) + 1;

    log_debug_msg(LOG_DEBUG | LOG_SERIALIZATION, "Message has payload of %"PRIu32"(%"PRIu32"/%"PRIu32") and %"PRIu32"(%"PRIu32"/%"PRIu32") header data, so we send %"PRIu32" chunks for %"PRIu32" bytes"
        , payload_size, body_size, footer_size, 
        fixed_size, header_size, instructions_size, 
        chunks, 
        (payload_size+ fixed_size)*chunks);


    msg->no_of_chunks = chunks;
}

double _np_message_get_expiery(const np_message_t* const self) 
{
    np_ctx_memory(self); 
    double now = np_time_now();
    double ret = now;

    CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TTL, msg_ttl);
    CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp);

    double tstamp = msg_tstamp.value.d;

    if (tstamp > now) {
        // timestap of msg is in the future.
        // this is not possible and may indecate
        // a faulty date/time setup on the client
        log_msg(LOG_WARN, "Detected faulty timestamp for message. Setting to now. (timestamp: %f, now: %f, diff: %f sec)", tstamp, now, tstamp - now);
        msg_tstamp.value.d = tstamp = now;
    }
    ret = (tstamp + msg_ttl.value.d);	

__np_cleanup__:

    return ret;
}

bool _np_message_is_expired(const np_message_t* const self)
{
    np_ctx_memory(self);
    bool ret = false;
    double now = np_time_now();

#ifdef DEBUG
    CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TTL, msg_ttl);
    CHECK_STR_FIELD(self->instructions, _NP_MSG_INST_TSTAMP, msg_tstamp);
    double tstamp = msg_tstamp.value.d;
#endif

    double remaining_ttl = _np_message_get_expiery(self) - now;
    ret = remaining_ttl <= 0;

    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg: %s) now: %f, msg_ttl: %f, msg_ts: %f, remaining_ttl: %f", self->uuid, now, msg_ttl.value.d, tstamp, remaining_ttl);

#ifdef DEBUG
    __np_cleanup__: {}
#endif

     return ret;
}

bool _np_message_serialize_header_and_instructions(np_state_t* context, np_jobargs_t args)
{	
    cmp_ctx_t cmp;
    np_messagepart_ptr part = NULL;

    _LOCK_ACCESS(&args.msg->msg_chunks_lock)
    {
        assert(args.msg->msg_chunks != NULL);
        pll_iterator(np_messagepart_ptr) first =  pll_first(args.msg->msg_chunks);
        assert(first != NULL);
        part = first->val;
        assert(part != NULL);
    }
    // we simply override the header and instructions part for a single part message here
    // the byte size should be the same as before
    cmp_init(&cmp, part->msg_part, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
    cmp_write_array(&cmp, 4);

    int i = cmp.buf-part->msg_part;
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->header->size);
    np_tree_serialize(context, args.msg->header, &cmp);
    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG,
            "serialized the header (size %"PRIu32" / %ld)", args.msg->header->byte_size, (cmp.buf-part->msg_part-i));
    i = cmp.buf-part->msg_part;

    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the instructions (size %hd)", msg->header->size);
    np_tree_serialize(context, args.msg->instructions, &cmp);
    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "serialized the instructions (size %"PRIu32" / %ld)", args.msg->instructions->byte_size, (cmp.buf-part->msg_part-i));
    // i = cmp.buf-part->msg_part;

    return (true);
}

bool _np_message_serialize_chunked(np_message_t* msg)
{
    np_state_t* context = np_ctx_by_memory(msg);
    NP_PERFORMANCE_POINT_START(message_serialize_chunked);
    log_trace_msg(LOG_TRACE | LOG_MESSAGE, "start: bool _np_message_serialize_chunked(np_state_t* context, np_jobargs_t args){");	

    np_ref_obj(np_message_t, msg);

    bool ret_val = false;

    //_np_message_calculate_chunking(msg);

    np_tree_insert_str( msg->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(msg->uuid));

    _LOCK_ACCESS(&msg->msg_chunks_lock){
        // clean up any old chunking

        if (0 < pll_size(msg->msg_chunks))
        {
            pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
            while (NULL != iter)
            {
                np_messagepart_ptr current_part = iter->val;
                np_unref_obj(np_messagepart_t, current_part, ref_message_messagepart);
                pll_next(iter);
            }
            pll_clear(np_messagepart_ptr, msg->msg_chunks);
        }
    }

    // TODO: optimize, more streaming
    // target is an array of 1024 byte size target buffers
    cmp_ctx_t cmp;
    uint16_t i = 0;

    cmp_ctx_t cmp_header;
    void* bin_header = NULL;

    cmp_ctx_t cmp_instructions;
    void* bin_instructions = NULL;

    cmp_ctx_t cmp_body;
    void* bin_body = NULL;
    void* bin_body_ptr = NULL;
    bool body_done = false;

    cmp_ctx_t cmp_footer;
    void* bin_footer = NULL;
    void* bin_footer_ptr = NULL;
    bool footer_done = false;

    uint16_t max_chunk_size = (MSG_CHUNK_SIZE_1024 - MSG_ENCRYPTION_BYTES_40);	
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

    np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0] = msg->no_of_chunks;

    uint16_t current_chunk_size = 0;

    // TODO: do this serialization in parallel in background
    while (i < msg->no_of_chunks)
    {
        np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1] = i + 1;

        np_messagepart_t* part;
        np_new_obj(np_messagepart_t, part);

        part->header = msg->header;
        // TODO: possible error ? have to pass the chunk number explicitly
        part->instructions = msg->instructions;
        part->part = i;
        part->msg_part = np_memory_new(context, np_memory_types_BLOB_984_RANDOMIZED);

        cmp_init(&cmp, part->msg_part, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
        cmp_write_array(&cmp, 4);

        // current_chunk_size = cmp.buf - part->msg_part;
        if (NULL == bin_header)
        {   // TODO: optimize memory handling and allocate memory during serialization
            bin_header = malloc(msg->header->byte_size);
            CHECK_MALLOC(bin_header);

            memset(bin_header, 0, msg->header->byte_size);
            // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->properties->size);
            cmp_init(&cmp_header, bin_header, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the header (size %hd)", msg->header->byte_size);
            np_tree_serialize(context, msg->header, &cmp_header);
        }

        // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "copying the header (size %hd)", msg->header->byte_size);
        memcpy(cmp.buf, bin_header, msg->header->byte_size);
        cmp.buf += msg->header->byte_size;
        // current_chunk_size = cmp.buf-part->msg_part;

        // reserialize the instructions into every chunk (_NP_MSG_INST_PARTS has changed)
        {
            bin_instructions = malloc(msg->instructions->byte_size);
            CHECK_MALLOC(bin_instructions);

            memset(bin_instructions, 0, msg->instructions->byte_size);
            // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "serializing the instructions (size %hd)", msg->properties->size);
            cmp_init(&cmp_instructions, bin_instructions, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "serializing the instructions (size %hd)", msg->instructions->byte_size);
            np_tree_serialize(context, msg->instructions, &cmp_instructions);

            // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "copying the instructions (size %hd)", msg->instructions->byte_size);
            memcpy(cmp.buf, bin_instructions, msg->instructions->byte_size);
            cmp.buf += msg->instructions->byte_size;

            free(bin_instructions);
            bin_instructions = NULL;

            // update current chunk size
            current_chunk_size = cmp.buf - part->msg_part;
        }

        if (NULL == bin_body)
        {
            // TODO: optimize memory handling and allocate memory during serialization
            bin_body = malloc(msg->body->byte_size);
            CHECK_MALLOC(bin_body);

            bin_body_ptr = bin_body;
            memset(bin_body, 0, msg->body->byte_size);
            // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the body (size %hd)", msg->properties->size);
            cmp_init(&cmp_body, bin_body, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            np_tree_serialize(context, msg->body, &cmp_body);
            // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the body (size %hd)", msg->body->byte_size);
        }

        // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "before body: space left in chunk: %hd / %hd",
        // 		(max_chunk_size - current_chunk_size), current_chunk_size );

        if (10 < (max_chunk_size - current_chunk_size) && false == body_done)
        {
            uint16_t left_body_size = msg->body->byte_size - (bin_body_ptr - bin_body);
            uint16_t possible_size = max_chunk_size - 10 - current_chunk_size;
            if (possible_size >= left_body_size)
            {
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "writing last body part (size %hd)", left_body_size);
                cmp_write_bin32(&cmp, bin_body_ptr, left_body_size);
                bin_body_ptr += left_body_size;
                body_done = true;
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "wrote all body (size %hd)", msg->body->byte_size);
            }
            else
            {
                cmp_write_bin32(&cmp, bin_body_ptr, possible_size);
                bin_body_ptr += possible_size;
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "writing body part (size %hd)", possible_size);
            }
        }
        else
        {
            cmp_write_bin32(&cmp, bin_body_ptr, 0);
            // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "copying empty tree (size %hd)", empty_tree->byte_size);
            // memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
            // cmp.buf += empty_tree->byte_size;
        }
        current_chunk_size = cmp.buf - part->msg_part;

        // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "before footer: space left in chunk: %hd / %hd",
        // 		(max_chunk_size - current_chunk_size), current_chunk_size );

        if (NULL == bin_footer)
        {
            // TODO: optimize memory handling and allocate memory during serialization
            bin_footer = malloc(msg->footer->byte_size);
            CHECK_MALLOC(bin_footer);

            bin_footer_ptr = bin_footer;
            memset(bin_footer, 0, msg->footer->byte_size);
            cmp_init(&cmp_footer, bin_footer, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            np_tree_serialize(context, msg->footer, &cmp_footer);
            // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "serializing the footer (size %hd)", msg->footer->byte_size);
        }

        if (5 < (max_chunk_size - current_chunk_size) && false == footer_done)
        {
            uint16_t left_footer_size = msg->footer->byte_size - (bin_footer_ptr - bin_footer);
            uint16_t possible_size = max_chunk_size - 5 - current_chunk_size;
            if (possible_size >= left_footer_size)
            {
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "writing last footer part (size %hd)", left_footer_size);
                cmp_write_bin32(&cmp, bin_footer_ptr, left_footer_size);
                bin_footer_ptr += left_footer_size;
                footer_done = true;
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "wrote all footer (size %hd)", msg->footer->byte_size);
            }
            else
            {
                cmp_write_bin32(&cmp, bin_footer_ptr, possible_size);
                bin_footer_ptr += possible_size;
                // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "writing footer part (size %hd)", possible_size);
            }
        }
        else
        {
            // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "copying empty tree (size %hd)", empty_tree->byte_size);
            cmp_write_bin32(&cmp, bin_footer_ptr, 0);
            // memcpy(cmp.buf, bin_empty, empty_tree->byte_size);
            // cmp.buf += empty_tree->byte_size;
        }
        // current_chunk_size = cmp.buf - part->msg_part;

        // log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "after footer: space left in chunk: %hd / %hd",
        //  		(max_chunk_size - current_chunk_size), current_chunk_size );
        i++;

        // insert new
        _LOCK_ACCESS(&msg->msg_chunks_lock) {

            np_ref_obj(np_messagepart_t, part, ref_message_messagepart);
            if(false == pll_insert(np_messagepart_ptr, msg->msg_chunks, part, false, _np_messagepart_cmp)){
                np_unref_obj(np_messagepart_t, part, ref_message_messagepart);
                // new entry is rejected (already present)
                log_msg(LOG_WARN,"Msg part was rejected in _np_message_serialize_chunked");
            }
        }
        np_unref_obj(np_messagepart_t, part, ref_obj_creation);
        // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "-------------------------" );
    }
    ret_val = true;
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "(msg: %s) chunked into %"PRIu32" parts (calculated no of chunks: %"PRIu16")"
            ,msg->uuid, pll_size(msg->msg_chunks), msg->no_of_chunks);

    // __np_cleanup__:
    if (NULL != bin_footer) free(bin_footer);
    if (NULL != bin_body) free(bin_body);
    if (NULL != bin_instructions) free(bin_instructions);
    if (NULL != bin_header) free(bin_header);
    
    np_unref_obj(np_message_t, msg, FUNC);

    NP_PERFORMANCE_POINT_END(message_serialize_chunked);
    return (ret_val);
}

bool _np_message_deserialize_header_and_instructions(np_message_t* msg, void* buffer)
{
    np_ctx_memory(msg);
    bool ret = false;
    if(msg->bin_static == NULL)
    {
        cmp_ctx_t cmp;
        _np_obj_buffer_container_t buffer_container;
        buffer_container.buffer = buffer;
        buffer_container.bufferCount = 0;
        buffer_container.bufferMaxCount = MSG_CHUNK_SIZE_1024;
        buffer_container.obj = msg;

        cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);

        uint32_t array_size = 0;

        if (!cmp_read_array(&cmp, &array_size))
        {
            log_msg(LOG_WARN, "unrecognized first array element while deserializing message. error: %"PRIu8, cmp.error);											
        }
        else
        {
            if (array_size != 4)
            {
                log_msg(LOG_WARN, "wrong array length while deserializing message");
            }
            else
            {   
                if (np_tree_deserialize( context, msg->header, &cmp) == true) {
                    msg->header->attr.immutable = false;

                    // TODO: check if the complete buffer was read (byte count match)

                    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "deserializing msg instructions");
                    if (np_tree_deserialize( context, msg->instructions, &cmp) == true) {

                        msg->instructions->attr.immutable = false;
                        // TODO: check if the complete buffer was read (byte count match)
                        if (NULL != np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)) {
                            msg->no_of_chunks = np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[0];
                        }

                        uint16_t chunk_id = 0;
                        if (NULL != np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)) {
                            chunk_id = np_tree_find_str(msg->instructions, _NP_MSG_INST_PARTS)->val.value.a2_ui[1];
                        }
                        else {
                            log_debug_msg(LOG_MESSAGE | LOG_DEBUG,
                                "_NP_MSG_INST_PARTS not available in msgs instruction tree"
                            );
                        }
                        msg->is_single_part = true;

                        if (0 == msg->no_of_chunks || 0 == chunk_id) {
                            log_msg(LOG_WARN, 
                                "no_of_chunks (%"PRIu16") or chunk_id (%"PRIu16") zero while deserializing message.", 
                                msg->no_of_chunks, chunk_id);
                        }
                        else {

                            np_messagepart_ptr part;
                            np_new_obj(np_messagepart_t, part);

                            part->header = msg->header;
                            part->instructions = msg->instructions;
                            part->part = chunk_id;
                            part->msg_part = buffer;

                            _LOCK_ACCESS(&msg->msg_chunks_lock) {
                                // insert new
                                np_ref_obj(np_messagepart_t, part, ref_message_messagepart);
                                if (false == pll_insert(np_messagepart_ptr, msg->msg_chunks, part, false, _np_messagepart_cmp)) {
                                    np_unref_obj(np_messagepart_t, part, ref_message_messagepart);
                                    // new entry is rejected (already present)
                                    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "Msg part was rejected in _np_message_deserialize_header_and_instructions");
                                }
                            }
                            if (msg->bin_static != NULL) {
                                np_unref_obj(np_messagepart_t, msg->bin_static, ref_message_bin_static);
                            }
                            ref_replace_reason(np_messagepart_t, part, ref_obj_creation, ref_message_bin_static);
                            msg->bin_static = part;

                            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "received message part (%d / %d)", chunk_id, msg->no_of_chunks);

                            CHECK_STR_FIELD(msg->instructions, _NP_MSG_INST_UUID, msg_uuid);
                            ASSERT(msg_uuid.type == np_treeval_type_char_ptr, " type is incorrectly set to: %"PRIu8, msg_uuid.type);
                            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) reset uuid to %s", msg->uuid, np_treeval_to_str(msg_uuid, NULL));
                            char* old = msg->uuid;
                            msg->uuid = strdup(np_treeval_to_str(msg_uuid, NULL));
                            free(old);

                            ret = true;
                            goto __np_wo_error;
                        __np_cleanup__:
                            log_msg(LOG_ERROR, "Message did not contain a UUID");
                        __np_wo_error:
                            ;

                        }
                    }
                }
            }
        }		
    }	
    return ret;
}

bool _np_message_deserialize_chunked(np_message_t* msg)
{
    np_ctx_memory(msg);
    bool ret = true;

    if (msg->bin_body != NULL) {
        free(msg->bin_body);
        msg->bin_body = NULL;
    }	
    void* bin_body_ptr = NULL;
    cmp_ctx_t cmp_body;
    uint32_t size_body = 0;

    if (msg->bin_footer != NULL) {
        free(msg->bin_footer);
        msg->bin_footer = NULL;
    }
    void* bin_footer_ptr = NULL;
    cmp_ctx_t cmp_footer;
    uint32_t size_footer = 0;

    _LOCK_ACCESS(&msg->msg_chunks_lock)
    {
        pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
        np_messagepart_ptr current_chunk = NULL;

        while (NULL != iter)
        {
            current_chunk = iter->val;
            log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "(msg:%s) now working on msg part %d",msg->uuid, current_chunk->part );            
            uint32_t size_body_add = 0;
            uint32_t size_footer_add = 0;

            cmp_ctx_t cmp;
            _np_obj_buffer_container_t buffer_container;
            buffer_container.buffer = current_chunk->msg_part;
            buffer_container.bufferCount = 0;
            buffer_container.bufferMaxCount = MSG_CHUNK_SIZE_1024;
            buffer_container.obj = msg;

            cmp_init(&cmp, &buffer_container, _np_buffer_container_reader, _np_buffer_container_skipper, _np_buffer_container_writer);

            uint32_t array_size;
            if (!cmp_read_array(&cmp, &array_size)) {
                log_debug_msg(LOG_WARN, "(msg:%s) wrong format (no array) for deserializing message", msg->uuid);
                return false;
            }
            if (array_size != 4)
            {
                log_msg(LOG_WARN, "(msg:%s) unrecognized message length while deserializing message", msg->uuid);
                return (false);
            }

            if (msg->bin_static == NULL)
            {
                
                void* orig_buffer = _np_buffer_get_buffer(&cmp);
                if (false == _np_message_deserialize_header_and_instructions(msg, current_chunk->msg_part)) {
                    return (false);
                }
                _np_buffer_set_buffer(&cmp, orig_buffer);
            }

            ((_np_obj_buffer_container_t*)cmp.buf)->buffer += msg->header->byte_size;
            ((_np_obj_buffer_container_t*)cmp.buf)->bufferCount += msg->header->byte_size;

            ((_np_obj_buffer_container_t*)cmp.buf)->buffer += msg->instructions->byte_size;
            ((_np_obj_buffer_container_t*)cmp.buf)->bufferCount += msg->instructions->byte_size;


            cmp_read_bin_size(&cmp, &size_body_add);
            if (0 < size_body_add)
            {
                log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "(msg:%s) adding body part size %u", msg->uuid, size_body_add);
                size_body += size_body_add;
                msg->bin_body = realloc(msg->bin_body, size_body);
                bin_body_ptr = msg->bin_body + (size_body - size_body_add);
                cmp.read(&cmp, bin_body_ptr, size_body_add);
            }

            cmp_read_bin_size(&cmp, &size_footer_add);
            if (0 < size_footer_add)
            {
                log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "(msg:%s) adding footer part size %u", msg->uuid, size_footer_add);
                size_footer += size_footer_add;
                msg->bin_footer = realloc(msg->bin_footer, size_footer);
                bin_footer_ptr = msg->bin_footer + (size_footer - size_footer_add);
                cmp.read(&cmp, bin_footer_ptr, size_footer_add);
            }

            iter->val = NULL;
            np_unref_obj(np_messagepart_t, current_chunk, ref_message_messagepart);
            pll_next(iter);
        }

        if (NULL != msg->bin_body)
        {
            log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "(msg:%s) deserializing msg body %u", msg->uuid, size_body);
            cmp_init(&cmp_body, msg->bin_body, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            if(np_tree_deserialize(context, msg->body, &cmp_body) == false) {
                return (false);
            }
            // TODO: check if the complete buffer was read (byte count match)
        }

        if (NULL != msg->bin_footer)
        {
            log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "(msg:%s) deserializing msg footer %u", msg->uuid, size_footer);
            cmp_init(&cmp_footer, msg->bin_footer, _np_buffer_reader, _np_buffer_skipper, _np_buffer_writer);
            if(np_tree_deserialize( context, msg->footer, &cmp_footer) == false) {
                return (false);
            }
            // TODO: check if the complete buffer was read (byte count match)
        }

        if (pll_size(msg->msg_chunks) > 0)
        {
            pll_iterator(np_messagepart_ptr) iter = pll_first(msg->msg_chunks);
            while (NULL != iter)
            {
                np_unref_obj(np_messagepart_t, iter->val, ref_message_messagepart);
                pll_next(iter);
            }
            pll_clear(np_messagepart_ptr, msg->msg_chunks);
        }
    }

/*
#ifdef DEBUG
    uint16_t fixed_size =
            MSG_ARRAY_SIZE + MSG_ENCRYPTION_BYTES_40 + MSG_PAYLOADBIN_SIZE +
            msg->header->byte_size + msg->instructions->byte_size;
    uint16_t payload_size = msg->properties->byte_size
            + msg->body->byte_size + msg->footer->byte_size;

    log_debug_msg(LOG_SERIALIZATION | LOG_DEBUG, "msg (%s) Size of msg  %"PRIu16" bytes. Size of fixed_size %"PRIu16" bytes. Nr of chunks  %"PRIu16" parts", msg->uuid, payload_size, fixed_size, msg->no_of_chunks);
#endif
*/
    np_tree_del_str(msg->footer, NP_MSG_FOOTER_GARBAGE);
    msg->is_single_part = false;

    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "-----------------------------------------------------" );

    return (ret);
}

/**
 ** message_create:
 ** creates the message to the destination #dest# the message format would be like:
 **  [ type ] [ size ] [ key ] [ data ]. It return the created message structure.
 */
void _np_message_create(np_message_t* msg, np_dhkey_t to, np_dhkey_t from, const char* subject, np_tree_t* the_data)
{
    np_ctx_memory(msg);
    // np_message_t* new_msg;
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "message ptr: %p %s", msg, subject);

    // in the future: header
    np_tree_insert_str( msg->header, _NP_MSG_HEADER_SUBJECT,  np_treeval_new_s((char*) subject));
    np_tree_insert_str( msg->header, _NP_MSG_HEADER_TO,  np_treeval_new_dhkey(to));
    np_tree_insert_str( msg->header, _NP_MSG_HEADER_FROM, np_treeval_new_dhkey(from));
    // insert a uuid if not yet present
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_UUID, np_treeval_new_s(msg->uuid));

    // derived message data from the msgproperty
    np_msgproperty_t* out_prop = _np_msgproperty_get(context, OUTBOUND, subject);

    // insert timestamp and time-to-live
    double now = np_time_now();
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_TSTAMP, np_treeval_new_d(now));
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_TTL, np_treeval_new_d(out_prop->msg_ttl));

    // insert msg acknowledgement indicator
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_ACK, np_treeval_new_ush(out_prop->ack_mode));
    // insert message chunking placeholder
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_PARTS, np_treeval_new_iarray(1, 1));

    // in the future: instructions
    // set re-send count to zero if not yet present
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_SEND_COUNTER, np_treeval_new_ush(0));
    // placeholder for incrementing sequence counter
    np_tree_insert_str( msg->instructions, _NP_MSG_INST_SEQ, np_treeval_new_ul(0));

    if (the_data != NULL)
    {
        _np_message_setbody(msg, the_data);
    }
}

inline void _np_message_setinstructions(np_message_t* msg, np_tree_t* instructions)
{
    np_tree_free( msg->instructions);
    msg->instructions = instructions;
};

inline void _np_message_setbody(np_message_t* msg, np_tree_t* body)
{
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body before %p", msg->body);
    if (msg->body != NULL) np_tree_free(msg->body);
    msg->body = body;
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body after %p", msg->body);
};

inline void _np_message_set_to(np_message_t* msg, np_dhkey_t target)
{
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body before %p", msg->body);
    np_tree_replace_str( msg->header, _NP_MSG_HEADER_TO,  np_treeval_new_dhkey(target));
    // log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "now setting body after %p", msg->body);
};

inline void _np_message_setfooter(np_message_t* msg, np_tree_t* footer)
{
    np_tree_t* old = msg->footer;
    msg->footer = footer;
    np_tree_free(old);
};

void _np_message_encrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token)
{
    np_ctx_memory(msg);

    // first encrypt the relevant message part itself
    unsigned char nonce[crypto_box_NONCEBYTES];
    unsigned char sym_key[crypto_secretbox_KEYBYTES];

    randombytes_buf((void*) nonce, crypto_box_NONCEBYTES);
    randombytes_buf((void*) sym_key, crypto_secretbox_KEYBYTES);

    int crypto = 0;
    _np_messagepart_encrypt(context, msg->body, nonce, sym_key, NULL);

    // now encrypt the encryption key using public key crypto stuff
    // unsigned char curve25519_sk[crypto_scalarmult_curve25519_BYTES];
    unsigned char ciphertext[crypto_box_MACBYTES + crypto_secretbox_KEYBYTES];

    // convert our own sign key to an encryption key
    // crypto += crypto_sign_ed25519_sk_to_curve25519(curve25519_sk,
    //                                                context->my_identity->aaa_token->crypto.ed25519_secret_key);

    // convert our partner key to an encryption key
    // unsigned char partner_key[crypto_scalarmult_curve25519_BYTES];
    // crypto += crypto_sign_ed25519_pk_to_curve25519(partner_key, tmp_token->crypto.ed25519_public_key);

#ifdef DEBUG
    char curve25519_pk[crypto_scalarmult_curve25519_BYTES*2+1];
    char partner_key[crypto_scalarmult_curve25519_BYTES*2+1];
    sodium_bin2hex(curve25519_pk, crypto_scalarmult_curve25519_BYTES*2+1, _np_key_get_token(context->my_identity)->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);
    sodium_bin2hex(partner_key, crypto_scalarmult_curve25519_BYTES*2+1, tmp_token->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);
    log_debug_msg(LOG_DEBUG | LOG_MESSAGE, "message (%s) encrypt: pa pk: %s ### my pk: %s\n", msg->uuid, partner_key, curve25519_pk);
#endif

    // finally encrypt
    crypto += crypto_box_easy(ciphertext, sym_key, crypto_secretbox_KEYBYTES, nonce,
    		                      tmp_token->crypto.derived_kx_public_key, _np_key_get_token(context->my_identity)->crypto.derived_kx_secret_key);
    if (0 > crypto)
    {
        log_msg(LOG_ERROR, "encryption of message payload failed");
        return;
    }
/*
    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "ciphertext: %s", ciphertext);
    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "nonce:      %s", nonce);
    log_debug_msg(LOG_MESSAGE | LOG_DEBUG, "sym_key:    %s", sym_key);
*/

    np_tree_t* encryption_details = np_tree_create();
    // insert the public-key encrypted encryption key for each receiver of the message
    np_tree_insert_str( encryption_details, NP_NONCE,
                   np_treeval_new_bin(nonce, crypto_box_NONCEBYTES));
    np_tree_insert_str( encryption_details, tmp_token->issuer,
                   np_treeval_new_bin(ciphertext,
                                crypto_box_MACBYTES + crypto_secretbox_KEYBYTES));
    // add encryption details to the message
    np_tree_insert_str( msg->body, NP_SYMKEY, np_treeval_new_tree(encryption_details));
    np_tree_free(encryption_details);

}

bool _np_message_decrypt_payload(np_message_t* msg, np_aaatoken_t* tmp_token)
{
    np_ctx_memory(msg);
    bool ret = true;
   
    np_tree_elem_t* symkey = np_tree_find_str(msg->body, NP_SYMKEY);
    if (NULL == symkey)
    {
        log_msg(LOG_ERROR, "No encryption_details! \"%s\" tree element is missing", NP_SYMKEY);
        ret = false;
    }
    else {
        np_tree_t* encryption_details = symkey->val.value.tree;
        if (NULL == encryption_details)
        {
            log_msg(LOG_ERROR, "No encryption_details! Data is missing.");
            ret = false;
        }
        else
        {
            // insert the public-key encrypted encryption key for each receiver of the message
            unsigned char nonce[crypto_box_NONCEBYTES];
            memcpy(nonce, np_tree_find_str(encryption_details, NP_NONCE)->val.value.bin, crypto_box_NONCEBYTES);
            unsigned char enc_sym_key[crypto_secretbox_KEYBYTES + crypto_box_MACBYTES];

            np_tree_elem_t* encryption_details_elem = np_tree_find_str(encryption_details, (char*)_np_key_as_str(context->my_identity));
            if (NULL == encryption_details_elem)
            {
                log_msg(LOG_ERROR, "decryption of message payload failed. no identity information in encryption_details for %s", _np_key_as_str(context->my_identity));
                ret = false;
            }
            else
            {
                memcpy(enc_sym_key,
                    encryption_details_elem->val.value.bin,
                    crypto_secretbox_KEYBYTES + crypto_box_MACBYTES
                );
                
#ifdef DEBUG

    char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2+1]; ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES*2] = '\0';
    char curve25519_pk[crypto_scalarmult_curve25519_BYTES*2+1]; curve25519_pk[crypto_scalarmult_curve25519_BYTES*2] = '\0';
    char partner_key[crypto_scalarmult_curve25519_BYTES*2+1]; partner_key[crypto_scalarmult_curve25519_BYTES*2] = '\0';

    sodium_bin2hex(ed25519_pk, crypto_sign_ed25519_PUBLICKEYBYTES*2+1, _np_key_get_token(context->my_identity)->crypto.ed25519_public_key, crypto_sign_ed25519_PUBLICKEYBYTES);
    sodium_bin2hex(curve25519_pk, crypto_scalarmult_curve25519_BYTES*2+1, _np_key_get_token(context->my_identity)->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);
    sodium_bin2hex(partner_key, crypto_scalarmult_curve25519_BYTES*2+1, tmp_token->crypto.derived_kx_public_key, crypto_scalarmult_curve25519_BYTES);

    log_debug_msg(LOG_DEBUG | LOG_MESSAGE, "message (%s) decrypt: my cu pk: %s ### my ed pk: %s ### pa pk: %s\n", msg->uuid, curve25519_pk, ed25519_pk, partner_key);
#endif

                NP_PERFORMANCE_POINT_START(message_decrypt);

                unsigned char sym_key[crypto_secretbox_KEYBYTES];
                int crypto_ret = crypto_box_open_easy(sym_key, enc_sym_key,
                    crypto_box_MACBYTES + crypto_secretbox_KEYBYTES,
                    nonce, tmp_token->crypto.derived_kx_public_key, _np_key_get_token(context->my_identity)->crypto.derived_kx_secret_key);
                if (0 > crypto_ret)
                {
                    log_msg(LOG_ERROR, "decryption of message sym_key (%s) failed", msg->uuid);
                    ret = false;
                }
                else
                {
                    np_tree_t* encrypted_body = np_tree_create();
                    if (_np_messagepart_decrypt(context, msg->body, nonce, sym_key, NULL, encrypted_body) == false)
                    {
                        np_tree_free(encrypted_body);
                        log_msg(LOG_ERROR, "decryption of message payloads body failed");
                        ret = false;
                    }
                    else
                    {
                        np_tree_t* old = msg->body;
                        msg->body = encrypted_body;
                        np_tree_free(old);
                    }
                }
                NP_PERFORMANCE_POINT_END(message_decrypt);
            }
        }
    }
    return (ret);
}

char* _np_message_get_subject(const np_message_t* const self)
{
    // np_ctx_memory(msg);
    char* ret = NULL;
    if (self->msg_property != NULL) {
        ret = self->msg_property->msg_subject;
    }
    else if(self->header != NULL){
        np_tree_elem_t* ele = np_tree_find_str(self->header, _NP_MSG_HEADER_SUBJECT);
        if(ele != NULL){
            ret =  np_treeval_to_str(ele->val, NULL);
        }
    }
    return ret;
}

void _np_message_add_key_response_handler(const np_message_t* self) 
{
    np_ctx_memory(self);

    np_responsecontainer_t* rh = NULL;
    np_new_obj(np_responsecontainer_t, rh);

    // TODO: more efficient, please ...
    memcpy(rh->uuid, self->uuid, NP_UUID_BYTES);
    rh->dest_dhkey = np_tree_find_str(self->header, _NP_MSG_HEADER_TO)->val.value.dhkey;
    rh->send_at    = np_tree_find_str(self->instructions, _NP_MSG_INST_TSTAMP)->val.value.d;
	rh->expires_at = rh->send_at + 
                     np_tree_find_str(self->instructions, _NP_MSG_INST_TTL)->val.value.d;
	rh->received_at = 0.0;
    // rh->msg_dhkey  = _np_msgproperty_dhkey(OUTBOUND, np_tree_find_str(self->header, _NP_MSG_HEADER_SUBJECT)->val.value.s);

    np_dhkey_t ack_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
    np_util_event_t rh_event = { .context=context, .user_data=rh, .target_dhkey=ack_dhkey, .type=(evt_internal|evt_response) };
    _np_keycache_handle_event(context, ack_dhkey, rh_event, false);
}

void _np_message_add_msg_response_handler(const np_message_t* self) 
{
    np_ctx_memory(self);

    np_responsecontainer_t* rh = NULL;
    np_new_obj(np_responsecontainer_t, rh);

    memcpy(rh->uuid, self->uuid, 18);
    // rh->dest_dhkey = np_tree_find_str(self->header, _NP_MSG_HEADER_TO)->val.value.dhkey;
    rh->msg_dhkey  = _np_msgproperty_dhkey(OUTBOUND, np_tree_find_str(self->header, _NP_MSG_HEADER_SUBJECT)->val.value.s);
    rh->send_at    =  np_tree_find_str(self->instructions, _NP_MSG_INST_TSTAMP)->val.value.d;
	rh->expires_at = rh->send_at + 
                     np_tree_find_str(self->instructions, _NP_MSG_INST_TTL)->val.value.d;
	rh->received_at = 0.0;

    np_dhkey_t ack_dhkey = _np_msgproperty_dhkey(INBOUND, _NP_MSG_ACK);
    np_util_event_t rh_event = { .context=context, .user_data=rh, .target_dhkey=ack_dhkey, .type=(evt_internal|evt_response) };
    _np_keycache_handle_event(context, ack_dhkey, rh_event, false);
}

np_dhkey_t* _np_message_get_sender(const np_message_t* const self){
    // np_ctx_memory(self);
    np_dhkey_t* ret = NULL;

    np_tree_elem_t* ele = np_tree_find_str(self->header, _NP_MSG_HEADER_FROM);
    if (ele != NULL) {
        ret = &ele->val.value.dhkey;
    }
    return ret;
}

void _np_message_trace_info(char* desc, np_message_t * msg_in) {

    np_ctx_memory(msg_in);
    char * info_str = NULL;
    info_str = np_str_concatAndFree(info_str, "MessageTrace_%s", desc);

#ifdef DEBUG
    bool free_key, free_value;
    char *key, *value;
    info_str = np_str_concatAndFree(info_str, " Header (");
    np_tree_elem_t * tmp;
    if(msg_in->header != NULL){
        RB_FOREACH(tmp, np_tree_s, (msg_in->header))
        {
            key = np_treeval_to_str(tmp->key, &free_key);			
            value = np_treeval_to_str(tmp->val, &free_value);
            info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
            if (free_value) free(value);
            if (free_key) free(key);
        }
    }
    info_str = np_str_concatAndFree(info_str, ") Instructions (");
    if (msg_in->instructions != NULL) {
        RB_FOREACH(tmp, np_tree_s, (msg_in->instructions))
        {
            key = np_treeval_to_str(tmp->key, &free_key);
            value = np_treeval_to_str(tmp->val, &free_value);
            info_str = np_str_concatAndFree(info_str, "%s:%s |", key, value);
            if (free_value) free(value);
            if (free_key) free(key);
        }
    }
    info_str = np_str_concatAndFree(info_str, ")");
#else
    info_str = np_str_concatAndFree(info_str, ": %s", msg_in->uuid);	
#endif

    log_msg(LOG_MESSAGE | LOG_DEBUG, info_str);	
    free(info_str);
}
