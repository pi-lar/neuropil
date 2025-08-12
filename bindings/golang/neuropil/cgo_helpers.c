//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#include "cgo_helpers.h"

#include "_cgo_export.h"

_Bool np_go_authn_callback_internal(void *ac, struct np_token *aaa_token) {
  return np_go_authn_callback(ac, aaa_token);
}
_Bool np_go_authz_callback_internal(void *ac, struct np_token *aaa_token) {
  return np_go_authz_callback(ac, aaa_token);
}
_Bool np_go_receive_callback_internal(void *ac, struct np_message *message) {
  return np_go_receive_callback(ac, message);
}
