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
	"runtime"
	"unsafe"
)

// np_error_str function as declared in golang/neuropil_comb.h:130
func ErrorString(e NPReturn) *string {
	ce, ceAllocMap := (C.enum_np_return)(e), cgoAllocsUnknown
	__ret := C.np_error_str(ce)
	runtime.KeepAlive(ceAllocMap)
	__v := *(**string)(unsafe.Pointer(&__ret))
	return __v
}

// np_get_id function as declared in golang/neuropil_comb.h:149
func GetId(id* NPId, name string) {
	cid, cidAllocMap := (*C.np_id)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&id)).Data)), cgoAllocsUnknown
	name = safeString(name)
	cstring, cstringAllocMap := unpackPCharString(name)
	// clength, clengthAllocMap := (C.size_t)(length), cgoAllocsUnknown
	clength := (C.size_t) (len(name))
	C.np_get_id(cid, cstring, clength)
	// runtime.KeepAlive(clengthAllocMap)
	runtime.KeepAlive(name)
	runtime.KeepAlive(cstringAllocMap)
	runtime.KeepAlive(cidAllocMap)
}

// np_generate_subject function as declared in golang/neuropil_comb.h:152
func GenerateSubject(subject_id* NPSubject, subject string) NPReturn {
	csubject_id, csubject_idAllocMap := (*C.np_subject)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject_id)).Data)), cgoAllocsUnknown
	subject = safeString(subject)
	csubject, csubjectAllocMap := unpackPCharString(subject)
	// clength, clengthAllocMap := (C.size_t)(length), cgoAllocsUnknown
	clength := (C.size_t) (len(subject))
	__ret := C.np_generate_subject(csubject_id, csubject, clength)
	// runtime.KeepAlive(clengthAllocMap)
	runtime.KeepAlive(subject)
	runtime.KeepAlive(csubjectAllocMap)
	runtime.KeepAlive(csubject_idAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// // np_default_settings function as declared in golang/neuropil_comb.h:207
func DefaultSettings() Settings {

	// Get default settings from C
	cSettings := C.np_default_settings(nil)
	
	// Create new Go Settings object and set the C reference
	settings := Newnp_settingsRef(unsafe.Pointer(cSettings))

	// Transfer values from C struct to Go struct
	settings.Deref()

	return *settings
}

// NewContext function as declared in golang/neuropil_comb.h:210
func NewContext(settings Settings) unsafe.Pointer {

	// Get C struct reference and allocation map from Settings
	csettings, csettingsAllocMap := settings.PassRef()
	
	// Call C function to create new context
	cContext := C.np_new_context(csettings)
	
	// Keep allocations alive until function returns
	runtime.KeepAlive(csettingsAllocMap)
	
	// Convert C pointer to Go unsafe.Pointer
	return unsafe.Pointer(cContext)
}

// np_listen function as declared in golang/neuropil_comb.h:241
func Listen(ac unsafe.Pointer, protocol string, host string, port uint16) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	protocol = safeString(protocol)
	cprotocol, cprotocolAllocMap := unpackPCharString(protocol)
	host = safeString(host)
	chost, chostAllocMap := unpackPCharString(host)
	cport, cportAllocMap := (C.uint16_t)(port), cgoAllocsUnknown
	__ret := C.np_listen(cac, cprotocol, chost, cport)
	runtime.KeepAlive(cportAllocMap)
	runtime.KeepAlive(host)
	runtime.KeepAlive(chostAllocMap)
	runtime.KeepAlive(protocol)
	runtime.KeepAlive(cprotocolAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_node_fingerprint function as declared in golang/neuropil_comb.h:243
func NodeFingerprint(ac unsafe.Pointer, id* NPId) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cid, cidAllocMap := (*C.np_id)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&id)).Data)), cgoAllocsUnknown
	__ret := C.np_node_fingerprint(cac, cid)
	runtime.KeepAlive(cidAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_join function as declared in golang/neuropil_comb.h:251
func Join(ac unsafe.Pointer, address string) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	address = safeString(address)
	caddress, caddressAllocMap := unpackPCharString(address)
	__ret := C.np_join(cac, caddress)
	runtime.KeepAlive(address)
	runtime.KeepAlive(caddressAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_run function as declared in golang/neuropil_comb.h:265
func Run(ac unsafe.Pointer, duration float64) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cduration, cdurationAllocMap := (C.double)(duration), cgoAllocsUnknown
	__ret := C.np_run(cac, cduration)
	runtime.KeepAlive(cdurationAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_send function as declared in golang/neuropil_comb.h:328
func Send(ac unsafe.Pointer, subject *NPSubject, message []byte) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	csubject, csubjectAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	cmessage, cmessageAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&message)).Data)), cgoAllocsUnknown
	clength := (C.size_t) (len(message))
	__ret := C.np_send(cac, csubject, cmessage, clength)
	runtime.KeepAlive(cmessageAllocMap)
	runtime.KeepAlive(csubjectAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_has_joined function as declared in golang/neuropil_comb.h:352
func HasJoined(ac unsafe.Pointer) bool {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	__ret := C.np_has_joined(cac)
	runtime.KeepAlive(cacAllocMap)
	__v := (bool)(__ret)
	return __v
}

// np_get_status function as declared in golang/neuropil_comb.h:354
func Status(ac unsafe.Pointer) NPStatus {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	__ret := C.np_get_status(cac)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPStatus)(__ret)
	return __v
}

// np_has_receiver_for function as declared in golang/neuropil_comb.h:356
func HasReceiver(ac unsafe.Pointer, subject *NPSubject) bool {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	csubject, csubjectAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	__ret := C.np_has_receiver_for(cac, csubject)
	runtime.KeepAlive(csubjectAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (bool)(__ret)
	return __v
}

// np_destroy function as declared in golang/neuropil_comb.h:363
func Destroy(ac unsafe.Pointer, gracefully bool) {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cgracefully, cgracefullyAllocMap := (C._Bool)(gracefully), cgoAllocsUnknown
	C.np_destroy(cac, cgracefully)
	runtime.KeepAlive(cgracefullyAllocMap)
	runtime.KeepAlive(cacAllocMap)
}

// np_set_authenticate_cb function as declared in golang/neuropil_comb.h:255
func SetAuthenticateCB(ac unsafe.Pointer, callback AAACallbackFunc) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	ccallback, ccallbackAllocMap := callback.PassAuthn()
	__ret := C.np_set_authenticate_cb(cac, ccallback)
	runtime.KeepAlive(ccallbackAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_set_authenticate_cb function as declared in golang/neuropil_comb.h:255
func SetAuthorizeCB(ac unsafe.Pointer, callback AAACallbackFunc) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	ccallback, ccallbackAllocMap := callback.PassAuthz()
	__ret := C.np_set_authorize_cb(cac, ccallback)
	runtime.KeepAlive(ccallbackAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_get_mx_properties function as declared in golang/neuropil_comb.h:314
func GetMxProperties(ac unsafe.Pointer, subject *NPSubject) MxProperties {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cid, cidAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	__ret := C.np_get_mx_properties(cac, cid)
	runtime.KeepAlive(cidAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := *Newnp_mx_propertiesRef(unsafe.Pointer(&__ret))
	return __v
}

// np_set_mx_properties function as declared in golang/neuropil_comb.h:316
func SetMxProperties(ac unsafe.Pointer, subject *NPSubject, properties MxProperties) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cid, cidAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	cproperties, cpropertiesAllocMap := properties.PassValue()
	__ret := C.np_set_mx_properties(cac, cid, cproperties)
	runtime.KeepAlive(cpropertiesAllocMap)
	runtime.KeepAlive(cidAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_mx_properties_enable function as declared in golang/neuropil_comb.h:323
func MxPropertiesEnable(ac unsafe.Pointer, subject *NPSubject) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cid, cidAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	__ret := C.np_mx_properties_enable(cac, cid)
	runtime.KeepAlive(cidAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_mx_properties_disable function as declared in golang/neuropil_comb.h:325
func MxPropertiesDisable(ac unsafe.Pointer, subject *NPSubject) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	cid, cidAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	__ret := C.np_mx_properties_disable(cac, cid)
	runtime.KeepAlive(cidAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}

// np_add_receive_cb function as declared in golang/neuropil_comb.h:344
func AddReceiveCallback(ac unsafe.Pointer, subject *NPSubject, callback ReceiveCallbackFunc) NPReturn {
	cac, cacAllocMap := ac, cgoAllocsUnknown
	csubject, csubjectAllocMap := (*C.uchar)(unsafe.Pointer((*sliceHeader)(unsafe.Pointer(&subject)).Data)), cgoAllocsUnknown
	ccallback, ccallbackAllocMap := callback.PassValue()
	__ret := C.np_add_receive_cb(cac, csubject, ccallback)
	runtime.KeepAlive(ccallbackAllocMap)
	runtime.KeepAlive(csubjectAllocMap)
	runtime.KeepAlive(cacAllocMap)
	__v := (NPReturn)(__ret)
	return __v
}
