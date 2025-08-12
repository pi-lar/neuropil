//
// SPDX-FileCopyrightText: 2016-2025 by pi-lar GmbH
// SPDX-License-Identifier: OSL-3.0
//

/**
 * This file contains only the 32-bit version of the PCG random number generator
 * Instead of adding the full library, we only copied the relevant 32-bit parts
 into this file.
 * The original code has been developed by Melissa O'Neill, and is licensed
 under the MIT or Apache2 license.
 *
 * see https://pcg-random.org for more details.
 * SPDXVersion: SPDX-2.1
 * DataLicense: CC0-1.0
 * PackageName: pcg-c
 * PackageOriginator: Melissa O'Neill <oneill@pcg-random.org>
 * PackageHomePage: http://www.pcg-random.org
 * PackageLicenseDeclared: (MIT OR Apache-2.0) *
 */
#ifndef NP_PCG_RNG_H_
#define NP_PCG_RNG_H_

#include <stdint.h>

#include "np_threads.h"

#ifdef __cplusplus
extern "C" {
#endif

/** a local pcg state that can be used to generate random numbers */
struct np_local_pcg_state_32 {
  uint64_t state;
  uint64_t inc;
};

NP_API_EXPORT
void np_global_rng_init();
NP_API_EXPORT
uint32_t np_global_rng_next();
NP_API_EXPORT
uint32_t np_global_rng_next_bounded(uint32_t bound);

NP_API_EXPORT
void np_rng_init(struct np_local_pcg_state_32 *rng);
NP_API_EXPORT
uint32_t np_rng_next(struct np_local_pcg_state_32 *rng);
NP_API_EXPORT
uint32_t np_rng_next_bounded(struct np_local_pcg_state_32 *rng, uint32_t bound);

#ifdef __cplusplus
}
#endif

#endif // NP_PCG_RNG_H_