//
// neuropil is copyright 2016-2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <stdlib.h>
#include <inttypes.h>

#include <criterion/criterion.h>
#include "sodium.h"


#include "../test_macros.c"

#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)
 
TestSuite(sodium_crypt );


Test(sodium_crypt, _sodium_crypto_routines, .description="test cryptobox easy usage and creation of ed25519 key/signpairs")
{
	unsigned char node_1_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char node_1_sk[crypto_sign_SECRETKEYBYTES];
	unsigned char node_2_pk[crypto_sign_PUBLICKEYBYTES];
	unsigned char node_2_sk[crypto_sign_SECRETKEYBYTES];

	unsigned char nonce[crypto_secretbox_NONCEBYTES];

	crypto_sign_keypair(node_1_pk, node_1_sk); // ed25519
	crypto_sign_keypair(node_2_pk, node_2_sk); // ed25519

	// convert to curve key
	unsigned char node_1_curve_sk[crypto_scalarmult_curve25519_BYTES];
	unsigned char node_2_curve_sk[crypto_scalarmult_curve25519_BYTES];
	crypto_sign_ed25519_sk_to_curve25519(node_1_curve_sk, node_1_sk);
	crypto_sign_ed25519_pk_to_curve25519(node_2_curve_sk, node_2_sk);
	//
	unsigned char node_1_dh_pk[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(node_1_dh_pk, node_1_curve_sk);

	unsigned char node_2_dh_pk[crypto_scalarmult_BYTES];
	crypto_scalarmult_base(node_2_dh_pk, node_2_curve_sk);


	unsigned char node_1_shared[crypto_scalarmult_BYTES];
	crypto_scalarmult(node_1_shared, node_1_curve_sk, node_2_dh_pk);
	unsigned char node_2_shared[crypto_scalarmult_BYTES];
	crypto_scalarmult(node_2_shared, node_2_curve_sk, node_1_dh_pk);

	// crypt it
	// unsigned char nonce[crypto_secretbox_NONCEBYTES];
	// unsigned char key[crypto_secretbox_KEYBYTES];
	unsigned char ciphertext[CIPHERTEXT_LEN];

	randombytes_buf(nonce, sizeof nonce);

	crypto_secretbox_easy(ciphertext, MESSAGE, MESSAGE_LEN, nonce, node_1_shared);

	unsigned char decrypted[MESSAGE_LEN];
	cr_expect(0 == crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, node_2_shared), "could not decrypt");
	    
}


#define MESSAGE_PART1 ((const unsigned char *) "Arbitrary data to hash")
#define MESSAGE_PART1_LEN 22
#define MESSAGE_PART2 ((const unsigned char *) "is longer than expected")
#define MESSAGE_PART2_LEN 23
#define MESSAGE_PART3 ((const unsigned char *) "and may get even longer!")
#define MESSAGE_PART3_LEN 24


Test(sodium_crypt, _concat_hash_values, .description="test whether hashing can be concatenated")
{
	unsigned char hash_1[crypto_generichash_BYTES];
	unsigned char hash_2[crypto_generichash_BYTES];
	unsigned char hash_3[crypto_generichash_BYTES];
	unsigned char key[crypto_generichash_KEYBYTES];

	crypto_generichash_state state_1, state_2, state_3;

	randombytes_buf(key, sizeof key);

	// calculate combined hash
	crypto_generichash_init(&state_1, NULL, 0, sizeof hash_1);
	crypto_generichash_update(&state_1, MESSAGE_PART1, MESSAGE_PART1_LEN);
	crypto_generichash_update(&state_1, MESSAGE_PART2, MESSAGE_PART2_LEN);
	crypto_generichash_update(&state_1, MESSAGE_PART3, MESSAGE_PART3_LEN);
	crypto_generichash_final(&state_1, hash_1, sizeof hash_1);


	// first calculate only part of the hash
	crypto_generichash_init(&state_2, NULL, 0, sizeof hash_2);
	crypto_generichash_update(&state_2, MESSAGE_PART1, MESSAGE_PART1_LEN);
	crypto_generichash_update(&state_2, MESSAGE_PART2, MESSAGE_PART2_LEN);
	crypto_generichash_final(&state_2, hash_2, sizeof hash_2);


	// next add a value to this hash part
	crypto_generichash_init(&state_3, NULL, 0, sizeof hash_3);
	crypto_generichash_update(&state_3, MESSAGE_PART3, MESSAGE_PART3_LEN);
	crypto_generichash_update(&state_3, hash_2, crypto_generichash_BYTES);
	crypto_generichash_final(&state_3, hash_3, sizeof hash_3);

	cr_expect(0 != sodium_memcmp(hash_1, hash_3, crypto_generichash_BYTES), "test whether we can concat hash values");

}
