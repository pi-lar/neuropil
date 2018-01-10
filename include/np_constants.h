//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

#ifndef NP_CONSTANTS_H_
#define NP_CONSTANTS_H_

#include <stdlib.h>


#ifdef __cplusplus
extern "C" {
#endif

	#define ref_message_bin_static			"ref_message_bin_static"
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
	#define ref_key_parent					"ref_key_parent"
	#define ref_message_msg_property		"ref_message_msg_property"
	#define ref_ack_obj						"ref_ack_obj"
	#define ref_ack_msg						"ref_ack_msg"
	#define ref_ack_key						"ref_ack_key"
	
	#define NP_SERIALISATION_NODE_KEY			"np.n.k"
	#define NP_SERIALISATION_NODE_PROTOCOL		"np.n.pr"
	#define NP_SERIALISATION_NODE_DNS_NAME		"np.n.d"
	#define NP_SERIALISATION_NODE_PORT			"np.n.p"
	#define NP_SERIALISATION_NODE_CREATED_AT	"np.n.c"
	#define NP_SERIALISATION_NODE_SUCCESS_AVG	"np.n.sa"
	#define NP_SERIALISATION_NODE_LATENCY		"np.n.l"
	#define NP_SERIALISATION_NODE_LAST_SUCCESS	"np.n.ls"

#define NP_AAATOKEN_MAX_SIZE_EXTENSIONS (1024)


	/*
	PRIORITY:
	0 defines the first job to execute
	...
	99... defines the last job to execute
	*/
#define PRIORITY_MOD_HIGHEST (0.0)

#define PRIORITY_MOD_LEVEL_0 (PRIORITY_MOD_HIGHEST)

#define PRIORITY_MOD_LEVEL_1 (1.0)

#define PRIORITY_MOD_LEVEL_2 (2.0)

#define PRIORITY_MOD_LEVEL_3 (3.0)

#define PRIORITY_MOD_LEVEL_4 (4.0)

#define PRIORITY_MOD_LEVEL_5 (5.0)

#define PRIORITY_MOD_LEVEL_6 (6.0)


/*
	Every CHAR_LENGTH_* may contain the final \0 char
*/
#define CHAR_LENGTH_PORT (8)
#define CHAR_LENGTH_IP (255)

#ifdef __cplusplus
}
#endif

#endif /* NP_CONSTANTS_H_ */
