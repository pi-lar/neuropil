/*
 * np_sysinfo.h
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

/** \toggle_keepwhitespaces  */

#ifndef NP_SYSINFO_H_
#define NP_SYSINFO_H_

#include "np_tree.h"

#ifdef __cplusplus
extern "C" {
#endif


	#define _NP_SYSINFO_REQUEST "_NP.SYSINFO.REQUEST"
	#define _NP_SYSINFO_REPLY "_NP.SYSINFO.REPLY"

NP_API_INTERN
void _np_sysinfo_init_cache();
NP_API_INTERN
np_bool _np_in_sysinfo(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) ;
NP_API_INTERN
np_bool _np_in_sysinforeply(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) ;
/**
.. c:function:: void np_get_sysinfo(const char* const dhkey_of_node_target)

   Tries to evaluate the sysinfo informations for the given target.
   Make sure to enable the target as sysinfo slave.

*/
NP_API_EXPORT
np_tree_t* np_get_sysinfo(const char* const dhkey_of_node_target);
/**
.. c:function:: np_get_my_sysinfo()

   Evaluates the sysinfo information for the current node.

*/
NP_API_EXPORT
np_tree_t* np_get_my_sysinfo() ;

NP_API_INTERN
void _np_request_others() ;
NP_API_INTERN
void _np_request_sysinfo(const char* dhkey_of_target) ;
NP_API_INTERN
np_tree_t* _np_get_sysinfo_from_cache(const char* hash_of_target, uint16_t max_cache_ttl) ;

/**
.. c:function:: void np_sysinfo_enable_slave()

   Enables this node to send sysinfo messages

*/
NP_API_EXPORT
void np_sysinfo_enable_slave();
/**
.. c:function:: void np_sysinfo_enable_master()

   Enables this node to revceive sysinfo messages

*/
NP_API_EXPORT
void np_sysinfo_enable_master();

#ifdef __cplusplus
}
#endif


#endif /* NP_SYSINFO_H_ */
