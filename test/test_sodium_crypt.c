/**
 *  neuropil is copyright 2015 by pi-lar GmbH
 **/
#include <stdlib.h>

#include "sodium.h"

#define MESSAGE ((const unsigned char *) "test")
#define MESSAGE_LEN 4
#define CIPHERTEXT_LEN (crypto_secretbox_MACBYTES + MESSAGE_LEN)

int main(int argc, char **argv)
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
	if (crypto_secretbox_open_easy(decrypted, ciphertext, CIPHERTEXT_LEN, nonce, node_2_shared) != 0) {
	    printf("not decrypted");/* message forged! */
	} else {
	    printf("decrypted");/* message forged! */
	}
}
