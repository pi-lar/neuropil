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

#include "util/np_pcg_rng.h"

#include "sodium.h"

#define PCG_DEFAULT_MULTIPLIER_32 6364136223846793005ULL
#define PCG32_INITIALIZER         {0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL}

/** a global pcg state, protected by spinlocks */
struct pcg_global_state_32 {
  TSP(struct np_local_pcg_state_32, local_pcg);
};

// a global state
static struct pcg_global_state_32 pcg32_global = {.local_pcg =
                                                      PCG32_INITIALIZER};

static uint32_t pcg_rotr_32(uint32_t value, unsigned int rot) {
#if PCG_USE_INLINE_ASM && __clang__ && (__x86_64__ || __i386__)
  asm("rorl   %%cl, %0" : "=r"(value) : "0"(value), "c"(rot));
  return value;
#else
  return (value >> rot) | (value << ((-rot) & 31));
#endif
}

static uint32_t pcg_output_xsh_rr_32_32(struct np_local_pcg_state_32 *rng) {
  uint64_t oldstate = rng->state;
  rng->state        = rng->state * PCG_DEFAULT_MULTIPLIER_32 + rng->inc;

  return pcg_rotr_32((((oldstate >> 18U)) ^ oldstate) >> 27U, oldstate >> 59U);

  // return pcg_rotr_32(((uint32_t)(oldstate >> 32U)) ^ (uint32_t)oldstate,
  //                    oldstate >> 59U);
}

static void pcg_setseq_32_srandom_r(struct np_local_pcg_state_32 *rng,
                                    uint64_t                      initstate,
                                    uint64_t                      initseq) {
  rng->state = 0U;
  rng->inc   = (initseq << 1u) | 1u;
  pcg_output_xsh_rr_32_32(rng);
  rng->state += initstate;
  pcg_output_xsh_rr_32_32(rng);
}

void np_rng_init(struct np_local_pcg_state_32 *rng) {
  uint64_t seeds[2];
  randombytes_buf(seeds, 2 * sizeof(uint64_t));
  pcg_setseq_32_srandom_r(rng, seeds[0], seeds[1]);
}

NP_API_EXPORT
uint32_t np_rng_next(struct np_local_pcg_state_32 *rng) {
  // uint64_t oldstate = rng->state;
  return pcg_output_xsh_rr_32_32(rng);
}

uint32_t np_rng_next_bounded(struct np_local_pcg_state_32 *rng,
                             uint32_t                      bound) {
  uint32_t threshold = -bound % bound;
  for (;;) {
    uint32_t r = np_rng_next(rng);
    if (r >= threshold) return r % bound;
  }
}

void np_global_rng_init() {
  TSP_INIT(pcg32_global.local_pcg);
  TSP_SCOPE(pcg32_global.local_pcg) { np_rng_init(&pcg32_global.local_pcg); }
}

uint32_t np_global_rng_next() {
  uint32_t rand = 0;
  TSP_SCOPE(pcg32_global.local_pcg) {
    rand = np_rng_next(&pcg32_global.local_pcg);
  }
  return rand;
}

uint32_t np_global_rng_next_bounded(uint32_t bound) {
  uint32_t rand = 0;
  TSP_SCOPE(pcg32_global.local_pcg) {
    rand = np_rng_next_bounded(&pcg32_global.local_pcg, bound);
  }
  return rand;
}
