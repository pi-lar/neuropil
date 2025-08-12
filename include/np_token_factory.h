//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef _NP_TOKEN_FACTORY_H_
#define _NP_TOKEN_FACTORY_H_

#include "util/np_list.h"

#include "np_dhkey.h"
#include "np_memory.h"
#include "np_network.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif
NP_API_INTERN
np_node_private_token_t *_np_token_factory_new_node_token(np_state_t *context);

NP_API_INTERN
np_handshake_token_t *
_np_token_factory_new_handshake_token(np_state_t *context,
                                      socket_type protocol,
                                      const char *hostname,
                                      const char *port);

NP_API_INTERN
np_message_intent_public_token_t *
_np_token_factory_new_message_intent_token(np_msgproperty_conf_t *msg_request);

NP_API_INTERN
np_ident_private_token_t *np_token_factory_new_identity_token(
    np_state_t *context,
    double      expires_at,
    unsigned char (*secret_key)[NP_SECRET_KEY_BYTES]);
NP_API_INTERN
np_ident_public_token_t *
np_token_factory_get_public_ident_token(np_aaatoken_t *source);

NP_API_INTERN
np_aaatoken_t *np_token_factory_read_from_tree(np_state_t *context,
                                               np_tree_t  *tree);

#ifdef __cplusplus
}
#endif

#endif // _NP_TOKEN_FACTORY_H_
