//
// SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

#ifndef _NP_SYSINFO_H_
#define _NP_SYSINFO_H_

#include "np_legacy.h"

#ifdef __cplusplus
extern "C" {
#endif

static const char *_NP_SYSINFO_DATA = "_NP.SYSINFO.DATA";

enum np_sysinfo_opt_e {
  np_sysinfo_opt_disable = 0,
  // np_sysinfo_opt_auto = 1,
  np_sysinfo_opt_force_server = 2,
  np_sysinfo_opt_force_client = 3
} typedef np_sysinfo_opt_e;

NP_API_INTERN
void _np_sysinfo_init_cache(np_state_t *context);
NP_API_INTERN
void _np_sysinfo_destroy_cache(np_state_t *context);

/**
.. c:function:: void _np_in_sysinfo(const char* const dhkey_of_node_target)

   message callback to receive sysinfo messages from clients, stores retrieved
data in the cache

*/
NP_API_INTERN
bool _np_in_sysinfo(np_state_t *context, struct np_message *msg);

/**
.. c:function:: void np_sysinfo_get_info(const char* const dhkey_of_node_target)

   Tries to evaluate the sysinfo information for the given target.
   Make sure to enable the target as sysinfo client.

*/
NP_API_EXPORT
np_tree_t *np_sysinfo_get_info(np_state_t       *context,
                               const char *const dhkey_of_node_target);

/**
.. c:function:: np_sysinfo_get_my_info()

   Evaluates the sysinfo information for the current node.

*/
NP_API_EXPORT
np_tree_t *np_sysinfo_get_all(np_state_t *context);

NP_API_EXPORT
np_tree_t *np_sysinfo_get_my_info(np_state_t *context);
NP_API_INTERN
np_tree_t *_np_sysinfo_get_from_cache(np_state_t *context,
                                      const char *hash_of_target,
                                      uint16_t    max_cache_ttl);

/**
.. c:function:: void np_sysinfo_enable_client()

   Enables this node to send sysinfo messages

*/
NP_API_EXPORT
void np_sysinfo_enable_client(np_state_t *context);
/**
.. c:function:: void np_sysinfo_enable_server()

   Enables this node to revceive sysinfo messages

*/
NP_API_EXPORT
void np_sysinfo_enable_server(np_state_t *context);

NP_API_EXPORT
void np_sysinfo_enable_local(np_state_t *context);

#ifdef __cplusplus
}
#endif

#endif /* NP_SYSINFO_H_ */
