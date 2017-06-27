//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#ifndef NP_SETTINGS_H_
#define NP_SETTINGS_H_

/*
 *	A new msg receiver token will be created x sec before a exipry will take place
 *	can be changed during runtime
 */
uint8_t AAATOKEN_SOFT_FAIL_RECEIVER = 1;
/*
 *	A new msg sender token will be created x sec before a exipry will take place
 *	can be changed during runtime
 */
uint8_t AAATOKEN_SOFT_FAIL_SENDER = 1;

#endif /* NP_SETTINGS_H_ */
