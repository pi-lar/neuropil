/*
 * np_sysinfo.h
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

#ifndef NP_SYSINFO_H_
#define NP_SYSINFO_H_

#include "np_tree.h"

#ifdef __cplusplus
extern "C" {
#endif


NP_API_INTERN
void _np_sysinfo_init(np_bool requestOrReply);
NP_API_INTERN
np_bool _np_in_sysinfo(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) ;
NP_API_INTERN
np_bool _np_in_sysinforeply(const np_message_t* const msg, np_tree_t* properties, np_tree_t* body) ;
NP_API_EXPORT
np_tree_t* np_get_sysinfo(const char* dhkey_of_node_target);
NP_API_EXPORT
np_tree_t* np_get_my_sysinfo() ;

NP_API_INTERN
void _np_request_others() ;
NP_API_INTERN
void _np_request_sysinfo(const char* dhkey_of_target) ;
NP_API_INTERN
np_tree_t* _np_get_sysinfo_from_cache(const char* hash_of_target, uint16_t max_cache_ttl) ;
#ifdef __cplusplus
}
#endif


#endif /* NP_SYSINFO_H_ */
