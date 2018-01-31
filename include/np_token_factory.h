//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef _NP_TOKEN_FACTORY_H_
#define _NP_TOKEN_FACTORY_H_


#include "np_dhkey.h"
#include "np_list.h"
#include "np_memory.h"
#include "np_types.h"

#ifdef __cplusplus
extern "C" {
#endif

	typedef np_aaatoken_t np_ident_public_token_t;
	typedef np_aaatoken_t np_ident_private_token_t;
	typedef np_aaatoken_t np_message_intent_public_token_t;
	typedef np_aaatoken_t np_node_public_token_t;
	typedef np_aaatoken_t np_node_private_token_t;

	NP_API_INTERN
		np_aaatoken_t* _np_token_factory_new_node_token(np_node_t* node);
	NP_API_EXPORT
		np_aaatoken_t* np_token_factory_new_identity_token(double expires_at);



#ifdef __cplusplus
}
#endif

#endif // _NP_TOKEN_FACTORY_H_
