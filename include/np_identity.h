//
// neuropil is copyright 2016-2018 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef	_NP_IDENTITY_H_
#define	_NP_IDENTITY_H_

#include "neuropil.h"
#include "np_types.h"
#include "np_threads.h"

#ifdef __cplusplus
extern "C" {
#endif

NP_API_EXPORT
size_t np_identity_export_current(np_context* ac, void* buffer);
NP_API_EXPORT
char* np_identity_fingerprint_current(np_context* ac);
NP_API_EXPORT
char* np_identity_fingerprint(np_context* ac, np_aaatoken_t* token);
NP_API_EXPORT
np_aaatoken_t* np_identity_import(np_context* ac, void* buffer, size_t size);
NP_API_EXPORT
size_t np_identity_export(np_context* ac, np_aaatoken_t* token, void* buffer);

#ifdef __cplusplus
}
#endif

#endif // _NP_IDENTITY_H_
