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
import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"
)

// cgoAllocMap stores pointers to C allocated memory for future reference.
type cgoAllocMap struct {
	mux sync.RWMutex
	m   map[unsafe.Pointer]struct{}
}

var cgoAllocsUnknown = new(cgoAllocMap)

func (a *cgoAllocMap) Add(ptr unsafe.Pointer) {
	a.mux.Lock()
	if a.m == nil {
		a.m = make(map[unsafe.Pointer]struct{})
	}
	a.m[ptr] = struct{}{}
	a.mux.Unlock()
}

func (a *cgoAllocMap) IsEmpty() bool {
	a.mux.RLock()
	isEmpty := len(a.m) == 0
	a.mux.RUnlock()
	return isEmpty
}

func (a *cgoAllocMap) Borrow(b *cgoAllocMap) {
	if b == nil || b.IsEmpty() {
		return
	}
	b.mux.Lock()
	a.mux.Lock()
	for ptr := range b.m {
		if a.m == nil {
			a.m = make(map[unsafe.Pointer]struct{})
		}
		a.m[ptr] = struct{}{}
		delete(b.m, ptr)
	}
	a.mux.Unlock()
	b.mux.Unlock()
}

func (a *cgoAllocMap) Free() {
	a.mux.Lock()
	for ptr := range a.m {
		C.free(ptr)
		delete(a.m, ptr)
	}
	a.mux.Unlock()
}

// packSNp_token reads sliced Go data structure out from plain C format.
func packSNp_token(v Token, ptr0 *C.struct_np_token) {
	v = *Newnp_tokenRef(unsafe.Pointer(&ptr0))
	v.Deref()
}

type sliceHeader struct {
	Data unsafe.Pointer
	Len  int
	Cap  int
}

// allocStruct_np_settingsMemory allocates memory for type C.struct_np_settings in C.
// The caller is responsible for freeing the this memory via C.free.
func allocStruct_np_settingsMemory(n int) unsafe.Pointer {
	mem, err := C.calloc(C.size_t(n), (C.size_t)(sizeOfStruct_np_settingsValue))
	if mem == nil {
		panic(fmt.Sprintln("memory alloc error: ", err))
	}
	return mem
}

const sizeOfStruct_np_settingsValue = unsafe.Sizeof([1]C.struct_np_settings{})

// Ref returns the underlying reference to C object or nil if struct is nil.
func (x *Settings) Ref() *C.struct_np_settings {
	if x == nil {
		return nil
	}
	return x.ref75f33333
}

// Free invokes alloc map's free mechanism that cleanups any allocated memory using C free.
// Does nothing if struct is nil or has no allocation map.
func (x *Settings) Free() {
	if x != nil && x.allocs75f33333 != nil {
		x.allocs75f33333.(*cgoAllocMap).Free()
		x.ref75f33333 = nil
	}
}

// Newnp_settingsRef creates a new wrapper struct with underlying reference set to the original C object.
// Returns nil if the provided pointer to C object is nil too.
func Newnp_settingsRef(ref unsafe.Pointer) *Settings {
	if ref == nil {
		return nil
	}
	obj := new(Settings)
	obj.ref75f33333 = (*C.struct_np_settings)(unsafe.Pointer(ref))
	return obj
}

// PassRef returns the underlying C object, otherwise it will allocate one and set its values
// from this wrapping struct, counting allocations into an allocation map.
func (x *Settings) PassRef() (*C.struct_np_settings, *cgoAllocMap) {
	if x == nil {
		return nil, nil
	} else if x.ref75f33333 != nil {
		return x.ref75f33333, nil
	}
	mem75f33333 := allocStruct_np_settingsMemory(1)
	ref75f33333 := (*C.struct_np_settings)(mem75f33333)
	allocs75f33333 := new(cgoAllocMap)
	allocs75f33333.Add(mem75f33333)

	var cn_threads_allocs *cgoAllocMap
	ref75f33333.n_threads, cn_threads_allocs = (C.uint32_t)(x.NoThreads), cgoAllocsUnknown
	allocs75f33333.Borrow(cn_threads_allocs)

	var clog_file_allocs *cgoAllocMap
	ref75f33333.log_file, clog_file_allocs = *(*[256]C.char)(unsafe.Pointer(&x.LogFile)), cgoAllocsUnknown
	allocs75f33333.Borrow(clog_file_allocs)

	var clog_level_allocs *cgoAllocMap
	ref75f33333.log_level, clog_level_allocs = (C.uint32_t)(x.LogLevel), cgoAllocsUnknown
	allocs75f33333.Borrow(clog_level_allocs)

	var cleafset_size_allocs *cgoAllocMap
	ref75f33333.leafset_size, cleafset_size_allocs = (C.uint8_t)(x.LeafsetSize), cgoAllocsUnknown
	allocs75f33333.Borrow(cleafset_size_allocs)

	// var clog_write_fn_allocs *cgoAllocMap
	// ref75f33333.log_write_fn, clog_write_fn_allocs = x.log_write_fn.PassValue()
	// allocs75f33333.Borrow(clog_write_fn_allocs)

	// var cjobqueue_size_allocs *cgoAllocMap
	// ref75f33333.jobqueue_size, cjobqueue_size_allocs = (C.uint16_t)(x.JobQueueSize), cgoAllocsUnknown
	// allocs75f33333.Borrow(cjobqueue_size_allocs)

	// var cmax_msgs_per_sec_allocs *cgoAllocMap
	// ref75f33333.max_msgs_per_sec, cmax_msgs_per_sec_allocs = (C.uint16_t)(x.MaxMessagesPerSec), cgoAllocsUnknown
	// allocs75f33333.Borrow(cmax_msgs_per_sec_allocs)

	x.ref75f33333 = ref75f33333
	x.allocs75f33333 = allocs75f33333
	return ref75f33333, allocs75f33333

}

// PassValue does the same as PassRef except that it will try to dereference the returned pointer.
func (x Settings) PassValue() (C.struct_np_settings, *cgoAllocMap) {
	if x.ref75f33333 != nil {
		return *x.ref75f33333, nil
	}
	ref, allocs := x.PassRef()
	return *ref, allocs
}

// Deref uses the underlying reference to C object and fills the wrapping struct with values.
// Do not forget to call this method whether you get a struct for C object and want to read its values.
func (x *Settings) Deref() {
	if x.ref75f33333 == nil {
		return
	}
	x.NoThreads = (uint32)(x.ref75f33333.n_threads)
	x.LogFile = *(*[256]byte)(unsafe.Pointer(&x.ref75f33333.log_file))
	x.LogLevel = (uint32)(x.ref75f33333.log_level)
	x.LeafsetSize = (byte)(x.ref75f33333.leafset_size)
	// x.log_write_fn = *Newnp_log_write_callbackRef(unsafe.Pointer(&x.ref75f33333.log_write_fn))
	// x.JobQueueSize = (uint16)(x.ref75f33333.jobqueue_size)
	// x.MaxMessagesPerSec = (uint16)(x.ref75f33333.max_msgs_per_sec)
}

// allocStruct_np_tokenMemory allocates memory for type C.struct_np_token in C.
// The caller is responsible for freeing the this memory via C.free.
func allocStruct_np_tokenMemory(n int) unsafe.Pointer {
	mem, err := C.calloc(C.size_t(n), (C.size_t)(sizeOfStruct_np_tokenValue))
	if mem == nil {
		panic(fmt.Sprintln("memory alloc error: ", err))
	}
	return mem
}

const sizeOfStruct_np_tokenValue = unsafe.Sizeof([1]C.struct_np_token{})

// Ref returns the underlying reference to C object or nil if struct is nil.
func (x *Token) Ref() *C.struct_np_token {
	if x == nil {
		return nil
	}
	return x.refacd16999
}

// Free invokes alloc map's free mechanism that cleanups any allocated memory using C free.
// Does nothing if struct is nil or has no allocation map.
func (x *Token) Free() {
	if x != nil && x.allocsacd16999 != nil {
		x.allocsacd16999.(*cgoAllocMap).Free()
		x.refacd16999 = nil
	}
}

// Newnp_tokenRef creates a new wrapper struct with underlying reference set to the original C object.
// Returns nil if the provided pointer to C object is nil too.
func Newnp_tokenRef(ref unsafe.Pointer) *Token {
	if ref == nil {
		return nil
	}
	obj := new(Token)
	obj.refacd16999 = (*C.struct_np_token)(unsafe.Pointer(ref))
	return obj
}

// PassRef returns the underlying C object, otherwise it will allocate one and set its values
// from this wrapping struct, counting allocations into an allocation map.
func (x *Token) PassRef() (*C.struct_np_token, *cgoAllocMap) {
	if x == nil {
		return nil, nil
	} else if x.refacd16999 != nil {
		return x.refacd16999, nil
	}
	memacd16999 := allocStruct_np_tokenMemory(1)
	refacd16999 := (*C.struct_np_token)(memacd16999)
	allocsacd16999 := new(cgoAllocMap)
	allocsacd16999.Add(memacd16999)

	// var cuuid_allocs *cgoAllocMap
	// refacd16999.uuid, cuuid_allocs = *(*[16]C.char)(unsafe.Pointer(&x.Uuid)), cgoAllocsUnknown
	// allocsacd16999.Borrow(cuuid_allocs)

	// var csubject_allocs *cgoAllocMap
	// refacd16999.subject, csubject_allocs = *(*[255]C.char)(unsafe.Pointer(&x.Subject)), cgoAllocsUnknown
	// allocsacd16999.Borrow(csubject_allocs)

	// var cissuer_allocs *cgoAllocMap
	// refacd16999.issuer, cissuer_allocs = *(*[32]C.np_id)(unsafe.Pointer(&x.Issuer)), cgoAllocsUnknown
	// allocsacd16999.Borrow(cissuer_allocs)

	// var crealm_allocs *cgoAllocMap
	// refacd16999.realm, crealm_allocs = *(*[32]C.np_id)(unsafe.Pointer(&x.Realm)), cgoAllocsUnknown
	// allocsacd16999.Borrow(crealm_allocs)

	// var caudience_allocs *cgoAllocMap
	// refacd16999.audience, caudience_allocs = *(*[32]C.np_id)(unsafe.Pointer(&x.Audience)), cgoAllocsUnknown
	// allocsacd16999.Borrow(caudience_allocs)

	// var cissued_at_allocs *cgoAllocMap
	// refacd16999.issued_at, cissued_at_allocs = (C.double)(x.IssuedAt), cgoAllocsUnknown
	// allocsacd16999.Borrow(cissued_at_allocs)

	// var cnot_before_allocs *cgoAllocMap
	// refacd16999.not_before, cnot_before_allocs = (C.double)(x.NotBefore), cgoAllocsUnknown
	// allocsacd16999.Borrow(cnot_before_allocs)

	// var cexpires_at_allocs *cgoAllocMap
	// refacd16999.expires_at, cexpires_at_allocs = (C.double)(x.ExpiresAt), cgoAllocsUnknown
	// allocsacd16999.Borrow(cexpires_at_allocs)

	// var cpublic_key_allocs *cgoAllocMap
	// refacd16999.public_key, cpublic_key_allocs = *(*[32]C.uchar)(unsafe.Pointer(&x.PublicKey)), cgoAllocsUnknown
	// allocsacd16999.Borrow(cpublic_key_allocs)

	// var csecret_key_allocs *cgoAllocMap
	// refacd16999.secret_key, csecret_key_allocs = *(*[64]C.uchar)(unsafe.Pointer(&x.secret_key)), cgoAllocsUnknown
	// allocsacd16999.Borrow(csecret_key_allocs)

	// var csignature_allocs *cgoAllocMap
	// refacd16999.signature, csignature_allocs = *(*[64]C.np_signature_t)(unsafe.Pointer(&x.Signature)), cgoAllocsUnknown
	// allocsacd16999.Borrow(csignature_allocs)

	// var cattributes_allocs *cgoAllocMap
	// refacd16999.attributes, cattributes_allocs = *(*[10240]C.np_attributes_t)(unsafe.Pointer(&x.Attributes)), cgoAllocsUnknown
	// allocsacd16999.Borrow(cattributes_allocs)

	// var cattributes_signature_allocs *cgoAllocMap
	// refacd16999.attributes_signature, cattributes_signature_allocs = *(*[64]C.np_signature_t)(unsafe.Pointer(&x.Attributes_Signature)), cgoAllocsUnknown
	// allocsacd16999.Borrow(cattributes_signature_allocs)

	x.refacd16999 = refacd16999
	x.allocsacd16999 = allocsacd16999
	return refacd16999, allocsacd16999

}

// PassValue does the same as PassRef except that it will try to dereference the returned pointer.
func (x Token) PassValue() (C.struct_np_token, *cgoAllocMap) {
	if x.refacd16999 != nil {
		return *x.refacd16999, nil
	}
	ref, allocs := x.PassRef()
	return *ref, allocs
}

// Deref uses the underlying reference to C object and fills the wrapping struct with values.
// Do not forget to call this method whether you get a struct for C object and want to read its values.
func (x *Token) Deref() {
	if x.refacd16999 == nil {
		return
	}
	x.Uuid = *(*[16]byte)(unsafe.Pointer(&x.refacd16999.uuid))
	x.Subject = *(*NPSubject)(unsafe.Pointer(&x.refacd16999.subject))
	x.Issuer = *(*NPId)(unsafe.Pointer(&x.refacd16999.issuer))
	x.Realm = *(*NPId)(unsafe.Pointer(&x.refacd16999.realm))
	x.Audience = *(*NPId)(unsafe.Pointer(&x.refacd16999.audience))
	// x.IssuedAt = (float64)(x.refacd16999.issued_at)
	// x.NotBefore = (float64)(x.refacd16999.not_before)
	// x.ExpiresAt = (float64)(x.refacd16999.expires_at)
	x.PublicKey = *(*[32]byte)(unsafe.Pointer(&x.refacd16999.public_key))
	// x.secret_key = *(*[64]byte)(unsafe.Pointer(&x.refacd16999.secret_key))
	x.Signature = *(*NPSignature)(unsafe.Pointer(&x.refacd16999.signature))
	x.Attributes = *(*NPAttributes)(unsafe.Pointer(&x.refacd16999.attributes))
	x.AttributesSignature = *(*NPSignature)(unsafe.Pointer(&x.refacd16999.attributes_signature))
}

// safeString ensures that the string is NULL-terminated, a NULL-terminated copy is created otherwise.
func safeString(str string) string {
	if len(str) > 0 && str[len(str)-1] != '\x00' {
		str = str + "\x00"
	} else if len(str) == 0 {
		str = "\x00"
	}
	return str
}

// unpackPCharString copies the data from Go string as *C.char.
func unpackPCharString(str string) (*C.char, *cgoAllocMap) {
	allocs := new(cgoAllocMap)
	defer runtime.SetFinalizer(allocs, func(a *cgoAllocMap) {
		go a.Free()
	})

	str = safeString(str)
	mem0 := unsafe.Pointer(C.CString(str))
	allocs.Add(mem0)
	return (*C.char)(mem0), allocs
}

// unpackArgSNp_settings transforms a sliced Go data structure into plain C format.
func unpackArgSNp_settings(x []Settings) (unpacked *C.struct_np_settings, allocs *cgoAllocMap) {
	if x == nil {
		return nil, nil
	}
	allocs = new(cgoAllocMap)
	defer runtime.SetFinalizer(allocs, func(a *cgoAllocMap) {
		go a.Free()
	})

	len0 := len(x)
	mem0 := allocStruct_np_settingsMemory(len0)
	allocs.Add(mem0)
	h0 := &sliceHeader{
		Data: mem0,
		Cap:  len0,
		Len:  len0,
	}
	v0 := *(*[]C.struct_np_settings)(unsafe.Pointer(h0))
	for i0 := range x {
		allocs0 := new(cgoAllocMap)
		v0[i0], allocs0 = x[i0].PassValue()
		allocs.Borrow(allocs0)
	}
	h := (*sliceHeader)(unsafe.Pointer(&v0))
	unpacked = (*C.struct_np_settings)(h.Data)
	return
}

// packSNp_settings reads sliced Go data structure out from plain C format.
func packSNp_settings(v []Settings, ptr0 *C.struct_np_settings) {
	const m = 0x7fffffff
	for i0 := range v {
		ptr1 := (*(*[m / sizeOfStruct_np_settingsValue]C.struct_np_settings)(unsafe.Pointer(ptr0)))[i0]
		v[i0] = *Newnp_settingsRef(unsafe.Pointer(&ptr1))
	}
}

func (x AAACallbackFunc) PassAuthn() (ref C.np_aaa_callback, allocs *cgoAllocMap) {
	if x == nil {
		return nil, nil
	}
	if np_authn_callback_func == nil {
		np_authn_callback_func = x
	}
	return (C.np_aaa_callback)(C.np_go_authn_callback_internal), nil
}

func (x AAACallbackFunc) PassAuthz() (ref C.np_aaa_callback, allocs *cgoAllocMap) {
	if x == nil {
		return nil, nil
	}
	if np_authz_callback_func == nil {
		np_authz_callback_func = x
	}
	return (C.np_aaa_callback)(C.np_go_authz_callback_internal), nil
}

//export np_go_authn_callback
func np_go_authn_callback(cac unsafe.Pointer, caaa_token *C.struct_np_token) C._Bool {
	if np_authn_callback_func != nil {
		ac11b32c49 := (unsafe.Pointer)(unsafe.Pointer(cac))
		// fmt.Println(caaa_token.subject, caaa_token.uuid, caaa_token.public_key)
		var aaa_token11b32c49 = Newnp_tokenRef(unsafe.Pointer(caaa_token))
		aaa_token11b32c49.Deref()
		// fmt.Println(aaa_token11b32c49.Subject, aaa_token11b32c49.Uuid, aaa_token11b32c49.PublicKey)
		ret11b32c49 := np_authn_callback_func(ac11b32c49, *aaa_token11b32c49)
		ret, _ := (C._Bool)(ret11b32c49), cgoAllocsUnknown
		return ret
	}
	return false
}

//export np_go_authz_callback
func np_go_authz_callback(cac unsafe.Pointer, caaa_token *C.struct_np_token) C._Bool {
	if np_authz_callback_func != nil {
		ac11b32c49 := (unsafe.Pointer)(unsafe.Pointer(cac))
		// fmt.Println(caaa_token.subject, caaa_token.uuid, caaa_token.public_key)
		var aaa_token11b32c49 = Newnp_tokenRef(unsafe.Pointer(caaa_token))
		aaa_token11b32c49.Deref()
		// fmt.Println(aaa_token11b32c49.Subject, aaa_token11b32c49.Uuid, aaa_token11b32c49.PublicKey)
		ret11b32c49 := np_authz_callback_func(ac11b32c49, *aaa_token11b32c49)
		ret, _ := (C._Bool)(ret11b32c49), cgoAllocsUnknown
		return ret
	}
	return false
}

var np_authn_callback_func AAACallbackFunc
var np_authz_callback_func AAACallbackFunc

// Newnp_mx_propertiesRef creates a new wrapper struct with underlying reference set to the original C object.
// Returns nil if the provided pointer to C object is nil too.
func Newnp_mx_propertiesRef(ref unsafe.Pointer) *MxProperties {
	if ref == nil {
		return nil
	}
	obj := new(MxProperties)
	obj.ref33f198f4 = (*C.struct_np_mx_properties)(unsafe.Pointer(ref))
	return obj
}

// allocStruct_np_mx_propertiesMemory allocates memory for type C.struct_np_mx_properties in C.
// The caller is responsible for freeing the this memory via C.free.
func allocStruct_np_mx_propertiesMemory(n int) unsafe.Pointer {
	mem, err := C.calloc(C.size_t(n), (C.size_t)(sizeOfStruct_np_mx_propertiesValue))
	if mem == nil {
		panic(fmt.Sprintln("memory alloc error: ", err))
	}
	return mem
}

const sizeOfStruct_np_mx_propertiesValue = unsafe.Sizeof([1]C.struct_np_mx_properties{})


// PassRef returns the underlying C object, otherwise it will allocate one and set its values
// from this wrapping struct, counting allocations into an allocation map.
func (x *MxProperties) PassRef() (*C.struct_np_mx_properties, *cgoAllocMap) {
	if x == nil {
		return nil, nil
	} else if x.ref33f198f4 != nil {
		return x.ref33f198f4, nil
	}
	mem33f198f4 := allocStruct_np_mx_propertiesMemory(1)
	ref33f198f4 := (*C.struct_np_mx_properties)(mem33f198f4)
	allocs33f198f4 := new(cgoAllocMap)
	allocs33f198f4.Add(mem33f198f4)

	var crole_allocs *cgoAllocMap
	ref33f198f4.role, crole_allocs = (C.enum_np_mx_role)(x.Role), cgoAllocsUnknown
	allocs33f198f4.Borrow(crole_allocs)

	var cackmode_allocs *cgoAllocMap
	ref33f198f4.ackmode, cackmode_allocs = (C.enum_np_mx_ackmode)(x.AckMode), cgoAllocsUnknown
	allocs33f198f4.Borrow(cackmode_allocs)

	// var creply_id_allocs *cgoAllocMap
	// ref33f198f4.reply_id, creply_id_allocs = *(*[32]C.np_subject)(unsafe.Pointer(&x.ReplyId)), cgoAllocsUnknown
	// allocs33f198f4.Borrow(creply_id_allocs)

	var caudience_type_allocs *cgoAllocMap
	ref33f198f4.audience_type, caudience_type_allocs = (C.enum_np_mx_audience_type)(x.AudienceType), cgoAllocsUnknown
	allocs33f198f4.Borrow(caudience_type_allocs)

	// var caudience_id_allocs *cgoAllocMap
	// ref33f198f4.audience_id, caudience_id_allocs = *(*[32]C.np_id)(unsafe.Pointer(&x.AudienceId)), cgoAllocsUnknown
	// allocs33f198f4.Borrow(caudience_id_allocs)

	var ccache_policy_allocs *cgoAllocMap
	ref33f198f4.cache_policy, ccache_policy_allocs = (C.enum_np_mx_cache_policy)(x.CachePolicy), cgoAllocsUnknown
	allocs33f198f4.Borrow(ccache_policy_allocs)

	var ccache_size_allocs *cgoAllocMap
	ref33f198f4.cache_size, ccache_size_allocs = (C.uint16_t)(x.CacheSize), cgoAllocsUnknown
	allocs33f198f4.Borrow(ccache_size_allocs)

	var cmax_parallel_allocs *cgoAllocMap
	ref33f198f4.max_parallel, cmax_parallel_allocs = (C.uint8_t)(x.MaxParallel), cgoAllocsUnknown
	allocs33f198f4.Borrow(cmax_parallel_allocs)

	var cmax_retry_allocs *cgoAllocMap
	ref33f198f4.max_retry, cmax_retry_allocs = (C.uint8_t)(x.MaxRetry), cgoAllocsUnknown
	allocs33f198f4.Borrow(cmax_retry_allocs)

	// var cintent_ttl_allocs *cgoAllocMap
	// ref33f198f4.intent_ttl, cintent_ttl_allocs = (C.double)(x.IntentTtl), cgoAllocsUnknown
	// allocs33f198f4.Borrow(cintent_ttl_allocs)

	// var cintent_update_after_allocs *cgoAllocMap
	// ref33f198f4.intent_update_after, cintent_update_after_allocs = (C.double)(x.IntentUpdateAfter), cgoAllocsUnknown
	// allocs33f198f4.Borrow(cintent_update_after_allocs)

	// var cmessage_ttl_allocs *cgoAllocMap
	// ref33f198f4.message_ttl, cmessage_ttl_allocs = (C.double)(x.MessageTtl), cgoAllocsUnknown
	// allocs33f198f4.Borrow(cmessage_ttl_allocs)

	x.ref33f198f4 = ref33f198f4
	x.allocs33f198f4 = allocs33f198f4
	return ref33f198f4, allocs33f198f4

}

// PassValue does the same as PassRef except that it will try to dereference the returned pointer.
func (x MxProperties) PassValue() (C.struct_np_mx_properties, *cgoAllocMap) {
	if x.ref33f198f4 != nil {
		return *x.ref33f198f4, nil
	}
	ref, allocs := x.PassRef()
	return *ref, allocs
}

// Deref uses the underlying reference to C object and fills the wrapping struct with values.
// Do not forget to call this method whether you get a struct for C object and want to read its values.
func (x *MxProperties) Deref() {
	if x.ref33f198f4 == nil {
		return
	}
	x.Role = (NPMxRole)(x.ref33f198f4.role)
	x.AckMode = (NPMxAckMode)(x.ref33f198f4.ackmode)
	// x.ReplyId = *(*[32]NPSubject)(unsafe.Pointer(&x.ref33f198f4.reply_id))
	x.AudienceType = (NPMxAudienceType)(x.ref33f198f4.audience_type)
	// x.AudienceId = *(*[32]NPId)(unsafe.Pointer(&x.ref33f198f4.audience_id))
	x.CachePolicy = (NPMxCachePolicy)(x.ref33f198f4.cache_policy)
	x.CacheSize = (uint16)(x.ref33f198f4.cache_size)
	x.MaxParallel = (byte)(x.ref33f198f4.max_parallel)
	x.MaxRetry = (byte)(x.ref33f198f4.max_retry)
	// x.intent_ttl = (float64)(x.ref33f198f4.intent_ttl)
	// x.intent_update_after = (float64)(x.ref33f198f4.intent_update_after)
	// x.message_ttl = (float64)(x.ref33f198f4.message_ttl)
}

func (x ReceiveCallbackFunc) PassValue() (ref C.np_receive_callback, allocs *cgoAllocMap) {
	if x == nil {
		return nil, nil
	}
	if np_receive_callback == nil {
		np_receive_callback = x
	}
	return (C.np_receive_callback)(C.np_go_receive_callback_internal), nil
}

// Newnp_messageRef creates a new wrapper struct with underlying reference set to the original C object.
// Returns nil if the provided pointer to C object is nil too.
func Newnp_messageRef(ref unsafe.Pointer) *Message {
	if ref == nil {
		return nil
	}
	obj := new(Message)
	obj.refbf335770 = (*C.struct_np_message)(unsafe.Pointer(ref))
	return obj
}

// Deref uses the underlying reference to C object and fills the wrapping struct with values.
// Do not forget to call this method whether you get a struct for C object and want to read its values.
func (x *Message) Deref() {
	if x.refbf335770 == nil {
		return
	}
	x.Uuid = *(*[16]byte)(unsafe.Pointer(&x.refbf335770.uuid))
	x.From = *(*NPId)(unsafe.Pointer(&x.refbf335770.from))
	x.Subject = *(*NPSubject)(unsafe.Pointer(&x.refbf335770.subject))
	x.Received_at = (float64)(x.refbf335770.received_at)

	x.Data = *(*[]byte)(unsafe.Pointer(&x.refbf335770.data)) // A Buffer needs no initialization.

	// hxff2234b := (*sliceHeader)(unsafe.Pointer(&x.Data))
	// hxff2234b.Data = unsafe.Pointer(x.refbf335770.data)
	// hxff2234b.Cap = 0x7fffffff
	// hxff2234b.Len = (int)(x.refbf335770.data_length)

	// x.data_length = (uint64)(x.refbf335770.data_length)
	x.Attributes = *(*NPAttributes)(unsafe.Pointer(&x.refbf335770.attributes))
}

//export np_go_receive_callback
func np_go_receive_callback(cac unsafe.Pointer, cmessage *C.struct_np_message) C._Bool {
	if np_receive_callback != nil {
		ac8f899489 := (unsafe.Pointer)(unsafe.Pointer(cac))
		var message8f899489 = Newnp_messageRef(unsafe.Pointer(cmessage))
		message8f899489.Deref()
		// packSNp_message(message8f899489, cmessage)
		ret8f899489 := np_receive_callback(ac8f899489, *message8f899489)
		ret, _ := (C._Bool)(ret8f899489), cgoAllocsUnknown
		return ret
	}
	panic("callback func has not been set (race?)")
}

var np_receive_callback ReceiveCallbackFunc
