//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_CONSTANTS_H_
#define NP_CONSTANTS_H_

#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif

	#define ref_msgpartcache				"ref_msgpartcache"
	#define ref_state_identity				"ref_state_identity"
	#define ref_obj_creation				"ref_obj_creation"
	#define ref_network_watcher				"ref_network_watcher"
	#define ref_keycache					"ref_keycache"
	#define ref_key_recv_property			"ref_key_recv_property"
	#define ref_key_send_property			"ref_key_send_property"
	#define ref_key_aaa_token				"ref_key_aaa_token"
	#define ref_key_node					"ref_key_node"
	#define ref_key_network					"ref_key_network"
	#define ref_message_messagepart			"ref_message_messagepart"
	#define ref_system_msgproperty			"ref_system_msgproperty"
	#define ref_route_routingtable_mykey	"ref_route_routingtable_mykey"
	#define ref_route_inroute				"ref_route_inroute"
	#define ref_route_inleafset				"ref_route_inleafset"
	#define ref_msgproperty_msgcache		"ref_msgproperty_msgcache"
	// ref for message type ack handeling
	#define ref_message_ack					"ref_message_ack"
	

#ifndef MUTEX_WAIT_SEC
	#define MUTEX_WAIT_SEC  ((const ev_tstamp )0.005)
#endif

#ifdef __cplusplus
}
#endif

#endif /* NP_CONSTANTS_H_ */
