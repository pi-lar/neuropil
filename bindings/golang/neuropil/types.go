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
import "unsafe"

// np_id type as declared in golang/neuropil_comb.h:140
type NPId [32]byte

// np_subject type as declared in golang/neuropil_comb.h:144
type NPSubject [32]byte

// np_attributes type as declared in golang/neuropil_comb.h:141
type NPAttributes [10240]byte

// np_signature type as declared in golang/neuropil_comb.h:142
type NPSignature [64]byte

// np_mx_properties as declared in golang/neuropil_comb.h:293
type MxProperties struct {
	Role              NPMxRole
	AckMode           NPMxAckMode
	ReplyId           NPSubject
	AudienceType      NPMxAudienceType
	AudienceId        NPId
	CachePolicy       NPMxCachePolicy
	CacheSize         uint16
	MaxParallel       byte
	MaxRetry          byte
	IntentTtl         float64
	IntentUpdateAfter float64
	MessageTtl        float64

	ref33f198f4        *C.struct_np_mx_properties
	allocs33f198f4     interface{}
}

// np_settings as declared in golang/neuropil_comb.h:195
type Settings struct {
	NoThreads        uint32
	LogFile         [256]byte
	LogLevel        uint32
	LeafsetSize      byte
	JobQueueSize     uint16
	MaxMessagesPerSec uint16

	// hidden private member
	ref75f33333      *C.struct_np_settings
	allocs75f33333   interface{}
}

// np_token as declared in golang/neuropil_comb.h:170
type Token struct {
	Uuid                 [16]byte
	Subject              NPSubject
	Issuer               NPId
	Realm                NPId
	Audience             NPId
	IssuedAt             float64
	NotBefore            float64
	ExpiresAt            float64
	PublicKey            [32]byte
	// SecretKey            [64]byte
	Signature            NPSignature
	Attributes           NPAttributes
	AttributesSignature  NPSignature

	// hidden private member
	refacd16999          *C.struct_np_token
	allocsacd16999       interface{}

}

// np_message as declared in golang/neuropil_comb.h:185
type Message struct {
	Uuid           [16]byte
	From           NPId
	Subject        NPSubject
	Received_at    float64
	Data           []byte

	Attributes     NPAttributes

	// hidden private member
	refbf335770    *C.struct_np_message
	allocsbf335770 interface{}
}

// np_aaa_callback type as declared in golang/neuropil_comb.h:253
type AAACallbackFunc func(ac unsafe.Pointer, token Token) bool

// np_receive_callback type as declared in golang/neuropil_comb.h:339
type ReceiveCallbackFunc func(ac unsafe.Pointer, message Message) bool

