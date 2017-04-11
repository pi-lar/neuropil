/*
 * np_sysinfo.h
 *
 *  Created on: 11.04.2017
 *      Author: sklampt
 */

#ifndef NP_SYSINFO_H_
#define NP_SYSINFO_H_


#ifdef __cplusplus
extern "C" {
#endif


void _np_sysinfo_init();
void _np_in_sysinfo(np_jobargs_t* args);
void _np_in_sysinforeply(np_jobargs_t * args);
np_tree_t* np_get_sysinfo( const char* hash_of_target, int timeout_ms);


#ifdef __cplusplus
}
#endif


#endif /* NP_SYSINFO_H_ */
