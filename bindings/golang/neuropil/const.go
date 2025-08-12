//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//
package neuropil

// #cgo CFLAGS: -I/Volumes/SAFE/net.pi-lar/repositories/neuropil_gitlab/include
// #cgo CXXFLAGS: -std=c99
// #cgo LDFLAGS: -lneuropil
// #cgo LDFLAGS: -L/Volumes/SAFE/net.pi-lar/repositories/neuropil_gitlab/build/neuropil/lib
// #include "neuropil.h"
// #include "neuropil_data.h"
// #include "neuropil_attributes.h"
// #include <stdlib.h>
// #include "cgo_helpers.h"
import "C"

// np_limits as declared in golang/neuropil_comb.h:103
type NPLimits int32

// np_limits enumeration from golang/neuropil_comb.h:103
const (
	NP_SECRET_KEY_BYTES  NPLimits = C.NP_SECRET_KEY_BYTES
	NP_SIGNATURE_BYTES   NPLimits = C.NP_SIGNATURE_BYTES
	NP_PUBLIC_KEY_BYTES  NPLimits = C.NP_PUBLIC_KEY_BYTES
	NP_FINGERPRINT_BYTES NPLimits = C.NP_FINGERPRINT_BYTES
	NP_UUID_BYTES        NPLimits = C.NP_UUID_BYTES
	NP_EXTENSION_BYTES   NPLimits = C.NP_EXTENSION_BYTES
)

// np_status as declared in golang/neuropil_comb.h:114
type NPStatus int32

// np_status enumeration from golang/neuropil_comb.h:114
const (
	Error         NPStatus = C.np_error
	Uninitialized NPStatus = C.np_uninitialized
	Running       NPStatus = C.np_running
	Stopped       NPStatus = C.np_stopped
	Shutdown      NPStatus = C.np_shutdown
)

// np_return as declared in golang/neuropil_comb.h:127
type NPReturn int32

// np_return enumeration from golang/neuropil_comb.h:127
const (
	Ok               NPReturn = C.np_ok
	OperationFailed  NPReturn = C.np_operation_failed
	UnknownError     NPReturn = C.np_unknown_error
	NotImplemented   NPReturn = C.np_not_implemented
	NetworkError     NPReturn = C.np_network_error
	InvalidArgument  NPReturn = C.np_invalid_argument
	InvalidOperation NPReturn = C.np_invalid_operation
	OutOfMemory      NPReturn = C.np_out_of_memory
	Startup          NPReturn = C.np_startup
)

// np_mx_role as declared in golang/neuropil_comb.h:271
type NPMxRole int32

// np_mx_role enumeration from golang/neuropil_comb.h:271
const (
	NP_MX_PROVIDER NPMxRole = C.NP_MX_PROVIDER
	NP_MX_CONSUMER NPMxRole = C.NP_MX_CONSUMER
	NP_MX_PROSUMER NPMxRole = C.NP_MX_PROSUMER
)

// np_mx_cache_policy as declared in golang/neuropil_comb.h:278
type NPMxCachePolicy int32

// np_mx_cache_policy enumeration from golang/neuropil_comb.h:278
const (
	NP_MX_FIFO_REJECT NPMxCachePolicy = C.NP_MX_FIFO_REJECT
	NP_MX_FIFO_PURGE  NPMxCachePolicy = C.NP_MX_FIFO_PURGE
	NP_MX_LIFO_REJECT NPMxCachePolicy = C.NP_MX_LIFO_REJECT
	NP_MX_LIFO_PURGE  NPMxCachePolicy = C.NP_MX_LIFO_PURGE
)

// np_mx_ackmode as declared in golang/neuropil_comb.h:284
type NPMxAckMode int32

// np_mx_ackmode enumeration from golang/neuropil_comb.h:284
const (
	NP_MX_ACK_NONE        NPMxAckMode = C.NP_MX_ACK_NONE
	NP_MX_ACK_DESTINATION NPMxAckMode = C.NP_MX_ACK_DESTINATION
	NP_MX_ACK_CLIENT      NPMxAckMode = C.NP_MX_ACK_CLIENT
)

// np_mx_audience_type as declared in golang/neuropil_comb.h:291
type NPMxAudienceType int32

// np_mx_audience_type enumeration from golang/neuropil_comb.h:291
const (
	NP_MX_AUD_PUBLIC    NPMxAudienceType = C.NP_MX_AUD_PUBLIC
	NP_MX_AUD_VIRTUAL   NPMxAudienceType = C.NP_MX_AUD_VIRTUAL
	NP_MX_AUD_PROTECTED NPMxAudienceType = C.NP_MX_AUD_PROTECTED
	NP_MX_AUD_PRIVATE   NPMxAudienceType = C.NP_MX_AUD_PRIVATE
)

// np_data_return as declared in golang/neuropil_comb.h:415
type NPDataReturn int32

// np_data_return enumeration from golang/neuropil_comb.h:415
const (
	np_data_ok                      NPDataReturn = C.np_data_ok
	np_key_not_found                NPDataReturn = C.np_key_not_found
	np_insufficient_memory          NPDataReturn = C.np_insufficient_memory
	np_invalid_structure            NPDataReturn = C.np_invalid_structure
	np_invalid_arguments            NPDataReturn = C.np_invalid_arguments
	np_could_not_write_magicno      NPDataReturn = C.np_could_not_write_magicno
	np_could_not_write_total_length NPDataReturn = C.np_could_not_write_total_length
	np_could_not_write_used_length  NPDataReturn = C.np_could_not_write_used_length
	np_could_not_write_object_count NPDataReturn = C.np_could_not_write_object_count
	np_could_not_write_bin          NPDataReturn = C.np_could_not_write_bin
	np_could_not_write_str          NPDataReturn = C.np_could_not_write_str
	np_could_not_write_int          NPDataReturn = C.np_could_not_write_int
	np_could_not_write_uint         NPDataReturn = C.np_could_not_write_uint
	np_could_not_write_key          NPDataReturn = C.np_could_not_write_key
	np_could_not_read_magicno       NPDataReturn = C.np_could_not_read_magicno
	np_could_not_read_total_length  NPDataReturn = C.np_could_not_read_total_length
	np_could_not_read_used_length   NPDataReturn = C.np_could_not_read_used_length
	np_could_not_read_object_count  NPDataReturn = C.np_could_not_read_object_count
	np_could_not_read_object        NPDataReturn = C.np_could_not_read_object
	np_could_not_read_key           NPDataReturn = C.np_could_not_read_key
)

// np_data_type as declared in golang/neuropil_comb.h:422
type NPDataType int32

// np_data_type enumeration from golang/neuropil_comb.h:422
const (
	NP_DATA_TYPE_BIN          NPDataType = C.NP_DATA_TYPE_BIN
	NP_DATA_TYPE_INT          NPDataType = C.NP_DATA_TYPE_INT
	NP_DATA_TYPE_UNSIGNED_INT NPDataType = C.NP_DATA_TYPE_UNSIGNED_INT
	NP_DATA_TYPE_STR          NPDataType = C.NP_DATA_TYPE_STR
)

// np_msg_attr_type as declared in golang/neuropil_comb.h:515
type NPMsgAttributeType int32

// np_msg_attr_type enumeration from golang/neuropil_comb.h:515
const (
	NP_ATTR_NONE                  NPMsgAttributeType = C.NP_ATTR_NONE
	NP_ATTR_USER_MSG              NPMsgAttributeType = C.NP_ATTR_USER_MSG
	NP_ATTR_INTENT                NPMsgAttributeType = C.NP_ATTR_INTENT
	NP_ATTR_IDENTITY              NPMsgAttributeType = C.NP_ATTR_IDENTITY
	NP_ATTR_IDENTITY_AND_USER_MSG NPMsgAttributeType = C.NP_ATTR_IDENTITY_AND_USER_MSG
	NP_ATTR_INTENT_AND_USER_MSG   NPMsgAttributeType = C.NP_ATTR_INTENT_AND_USER_MSG
	NP_ATTR_INTENT_AND_IDENTITY   NPMsgAttributeType = C.NP_ATTR_INTENT_AND_IDENTITY
	NP_ATTR_MAX                   NPMsgAttributeType = C.NP_ATTR_MAX
)

