/**
 *  copyright 2015 pi-lar GmbH
 *  Stephan Schwichtenberg
 **/
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "sodium.h"

#include "np_key.h"

#include "log.h"
#include "np_jtree.h"

static np_dhkey_t __dhkey_min;
static np_dhkey_t __dhkey_half;
static np_dhkey_t __dhkey_max;

void _dhkey_to_str (const np_dhkey_t* k, char* key_string)
{
    // k->valid = FALSE;

    // log_msg(LOG_KEY | LOG_WARN, "key %0lu %0lu %0lu %0lu", k->t[0], k->t[1], k->t[2], k->t[3]);
	// log_msg(LOG_KEY | LOG_WARN, "key %16lx%16lx%16lx%16lx", k->t[0], k->t[1], k->t[2], k->t[3]);

    // TODO: use sodium bin2hex function
	memset  (key_string, 0, 64);
	sprintf ((char*) key_string, "%016llx%016llx%016llx%016llx", k->t[0], k->t[1], k->t[2], k->t[3]);
	key_string[64] = '\0';
	// k->valid = TRUE;
    // log_msg (LOG_KEY | LOG_DEBUG, "key string now: %s", k->keystr);
}

void _str_to_dhkey (const char* key_string, np_dhkey_t* k)
{
	// TODO: this is dangerous, encoding could be different between systems,
	// encoding has to be send over the wire to be sure ...
	// for now: all tests on the same system
    // assert (64 == strlen((char*) key_string));

    // memset (k->keystr, 0, 64);
    // memcpy (k->keystr, key_string, 64);
    // k->keystr[64] = '\0';

    for (uint8_t i = 0; i < 4; i++)
    {
    	char substring[17];
    	memcpy(substring, key_string + i*16, 16);
    	substring[16] = '\0';
    	k->t[i] = strtoull((const char*) substring, NULL, 16);
        // log_msg(LOG_KEY | LOG_DEBUG, "keystr substring to ul: %s -> %ul ", substring, k->t[i]);
    }
    log_msg(LOG_KEY | LOG_DEBUG, "key %016llx %016llx %016llx %016llx", k->t[0], k->t[1], k->t[2], k->t[3]);

    // k->valid = TRUE;
}

char* _dhkey_generate_hash (const char* key_in)
{
    unsigned char md_value[32]; //  = (unsigned char *) malloc (32);

    // TODO: move it to KECCAK because of possible length extension attack ???
    crypto_hash_sha256(md_value, (unsigned char*) key_in, strlen(key_in));

    // log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, md_value);
    // long form - could be used to add addiitonal configuration parameter
    //    crypto_hash_sha256_state state;
    //    crypto_hash_sha256_init(&state);
    //    crypto_hash_sha256_update(&state, key_in, sizeof(key_in));
    //    crypto_hash_sha256_final(&state, tmp);
    //    log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, tmp);
    char* digest_out = (char *) malloc (65);
	sodium_bin2hex(digest_out, 65, md_value, 32);

    return digest_out;
}

np_dhkey_t dhkey_create_from_hostport(const char* strOrig, char* port)
{
	char name[256];
	snprintf (name, 255, "%s:%s", strOrig, port);

	char* digest = _dhkey_generate_hash (name);
	log_msg (LOG_KEY | LOG_DEBUG, "digest calculation returned HASH: %s", digest);

    np_dhkey_t tmp = dhkey_create_from_hash(digest);
	log_msg (LOG_KEY | LOG_DEBUG, "HASH(%s) = [key %016llx %016llx %016llx %016llx]", name, tmp.t[0], tmp.t[1], tmp.t[2], tmp.t[3]);

	free (digest);
	return tmp;
}

np_dhkey_t dhkey_create_from_hash(const char* strOrig)
{
    np_dhkey_t kResult;
    _str_to_dhkey(strOrig, &kResult);
    return kResult;
}

void _np_encode_dhkey(np_jtree_t* jrb, np_dhkey_t* key)
{
    // log_msg(LOG_KEY | LOG_WARN, "encoding key %0lu %0lu %0lu %0lu", key->t[0], key->t[1], key->t[2], key->t[3]);

	jrb_insert_str(jrb, "_np.key.0", new_jval_ull(key->t[0]));
	jrb_insert_str(jrb, "_np.key.1", new_jval_ull(key->t[1]));
	jrb_insert_str(jrb, "_np.key.2", new_jval_ull(key->t[2]));
	jrb_insert_str(jrb, "_np.key.3", new_jval_ull(key->t[3]));
}

void _np_decode_dhkey(np_jtree_t* jrb, np_dhkey_t* key)
{
	key->t[0] = jrb_find_str(jrb, "_np.key.0")->val.value.ull;
	key->t[1] = jrb_find_str(jrb, "_np.key.1")->val.value.ull;
	key->t[2] = jrb_find_str(jrb, "_np.key.2")->val.value.ull;
	key->t[3] = jrb_find_str(jrb, "_np.key.3")->val.value.ull;
}

void _dhkey_assign (np_dhkey_t* k1, const np_dhkey_t* const k2)
{
    for (uint8_t i = 0; i < 4; i++)
    	k1->t[i] = k2->t[i];
}

void _dhkey_assign_ui (np_dhkey_t* k, uint64_t ul)
{
	log_msg (LOG_KEY | LOG_WARN, "!!! deprecated function called key_assign_ui");
    for (uint8_t i = 1; i < 3; i++)
    	k->t[i] = 0;
    k->t[3] = ul;

    // k->valid = FALSE;
}

np_bool _dhkey_equal (np_dhkey_t* k1, np_dhkey_t* k2)
{
    for (uint8_t i = 0; i < 4; i++)
    	if (k1->t[i] != k2->t[i])
    		return FALSE;
    return TRUE;
}

np_bool _dhkey_equal_ui (np_dhkey_t* k, uint64_t ul)
{
	log_msg (LOG_KEY | LOG_WARN, "!!! deprecated function called key_equal_ui");

	if (k->t[3] != ul) return (0);

    for (uint8_t i = 2; i-- != 0; )
    	if (k->t[i] != 0)
    		return FALSE;
    return TRUE;
}

int8_t _dhkey_comp (const np_dhkey_t* k1, const np_dhkey_t* k2)
{
	if (k1 == NULL) return -1;
	if (k2 == NULL) return  1;

    for (uint8_t i = 0; i < 4; i++)
	{
    	log_msg(LOG_KEY | LOG_DEBUG, "k1 %llu / k2 %llu", k1->t[i], k2->t[i]);
	    if 		(k1->t[i] > k2->t[i]) return (1);
	    else if (k1->t[i] < k2->t[i]) return (-1);
	}
    return (0);
}

void _dhkey_add (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2)
{
	log_msg (LOG_KEY | LOG_TRACE, ".start.key_add");
	// we dont care about buffer overflow, since we are adding hashes
	// since we are using uint64_t we always stay in valid data
    for (uint8_t i = 4; 0 != i--; )
	{
	    result->t[i] = op1->t[i] + op2->t[i];
    	log_msg(LOG_KEY | LOG_DEBUG, "op1[%llu] + op2[%llu] = r[%llu]", op1->t[i], op2->t[i], result->t[i]);
	    // log_msg(LOG_KEY | LOG_DEBUG, "[%llu] + op2[%llu] = r[%llu] / %f", 9223372036854775807, 9223372036854775807, 9223372036854775807+9223372036854775807, tmp);
	    // if (tmp > ULONG_MAX) tmp = 1; // tmp - ULONG_MAX;
	    // else                 tmp = 0;
	}
	log_msg (LOG_KEY | LOG_TRACE, ".end  .key_add");
}

void _dhkey_sub (np_dhkey_t* result, const np_dhkey_t* const op1, const np_dhkey_t* const op2)
{
	log_msg (LOG_KEY | LOG_TRACE, ".start.key_sub");
    // double tmp, a, b, carry;
    // np_dhkey_t key_a, key_b, key_tmp;
    // np_bool swapped = 0;

    // carry = 0;

    // _dhkey_assign(&key_a, op1);
    // _dhkey_assign(&key_b, op2);

//    if (_dhkey_comp (&key_a, &key_b) < 0)
//	{
//    	// swap keys and do the calculation
//    	_dhkey_assign(&key_tmp, &key_a);
//    	_dhkey_assign(&key_a, &key_b);
//    	_dhkey_assign(&key_b, &key_tmp);
//    	// log_msg (LOG_KEY | LOG_DEBUG, "swapped input data (key_a < key_b");
//    	swapped = TRUE;
//	}

    for (uint8_t i = 4; 0 != i--; )
	{
	    result->t[i] = op1->t[i] - op2->t[i];
    	log_msg(LOG_KEY | LOG_DEBUG, "op1[%llu] - op2[%llu] = r[%llu]", op1->t[i], op2->t[i], result->t[i]);
    	// if (key_a.t[i] > key_b.t[i])

	    // a = key_a.t[i] - carry;
	    // b = key_b.t[i];

	    // if (b <= a)
		// {
		//     tmp = a - b;
		//     carry = 0;
		// }
	    // else
		// {
		//    a = a + ULONG_MAX + 1;
		//    tmp = a - b;
		//     carry = 1;
		// }
	    // result->t[i] = (uint64_t) tmp;
	}

//    if (TRUE == swapped) {
//    	_dhkey_assign(&key_tmp, result);
//    	_dhkey_sub(result, &__dhkey_max, &key_tmp);
//    }

    // result->valid = FALSE;

    log_msg (LOG_KEY | LOG_TRACE, ".end  .key_sub");
}

void _dhkey_init ()
{
    for (uint8_t i = 0; i < 4; i++)
	{
    	__dhkey_max.t[i]  = ULONG_MAX;
    	__dhkey_half.t[i] = (__dhkey_max.t[i] >> 1) + 1;
    	__dhkey_min.t[1]  = 0;
    	log_msg(LOG_KEY | LOG_DEBUG,
    			"dhkey_max[%d] %llu / dhkey_half[%d] %llu / dhkey_half[%d] %llu",
				i, __dhkey_max.t[i],
				i, __dhkey_half.t[i],
				i, __dhkey_min.t[i]
		);
	}

    // __dhkey_half.t[0] = __dhkey_half.t[0] >> 1; //  __dhkey_max.t[0] / 2;
	// log_msg(LOG_KEY | LOG_DEBUG, "dhkey_half[0] %llu", __dhkey_half.t[0]);
}

np_dhkey_t dhkey_min()  { return __dhkey_min;  };
np_dhkey_t dhkey_half() { return __dhkey_half; };
np_dhkey_t dhkey_max()  { return __dhkey_max;  };

void _dhkey_distance (np_dhkey_t* diff, const np_dhkey_t* const k1, const np_dhkey_t* const k2)
{
    log_msg (LOG_KEY | LOG_TRACE, ".start._dhkey_distance");
    _dhkey_sub (diff, k1, k2);
    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_distance");
}


np_bool _dhkey_between (const np_dhkey_t* const test, const np_dhkey_t* const left, const np_dhkey_t* const right)
{
    log_msg (LOG_KEY | LOG_TRACE, ".start._dhkey_between");

    int8_t complr = _dhkey_comp (left, right);
    int8_t complt = _dhkey_comp (left, test);
    int8_t comptr = _dhkey_comp (test, right);

    /* it's on one of the edges */
    if (complt == 0 || comptr == 0) return (TRUE);

    if (complr < 0)
	{
	    if (complt < 0 && comptr < 0) return (TRUE);
	    return (FALSE);
	}
    else if (complr == 0)
	{
	    return (FALSE);
	}
    else
	{
	    if (complt < 0 || comptr < 0) return (TRUE);
	    return (FALSE);
	}
    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_between");
}

void _dhkey_midpoint (np_dhkey_t* mid, const np_dhkey_t* key)
{
    log_msg (LOG_KEY | LOG_TRACE, ".start._dhkey_midpoint");
    if   (_dhkey_comp (key, &__dhkey_half) < 0) _dhkey_add (mid, key, &__dhkey_half);
    else  	                                    _dhkey_sub (mid, key, &__dhkey_half);
    // mid->valid = FALSE;
    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_midpoint");
}


uint16_t _dhkey_index (const np_dhkey_t* mykey, const np_dhkey_t* otherkey)
{
    log_msg (LOG_KEY | LOG_TRACE, ".start._dhkey_index");
	uint16_t i = 0, max_len = 64;

    for (uint8_t k = 0; k < 4; ++k)
    {
    	uint64_t bit_mask = 0xf000000000000000;
    	for (uint8_t j = 0; j < 16; ++j)
    	{
    		uint64_t t1 = mykey->t[k]    & bit_mask;
    		uint64_t t2 = otherkey->t[k] & bit_mask;
    	    log_msg (LOG_KEY | LOG_DEBUG, "key_index: %d me: %016llx other: %016llx mask: %016llx", i, t1, t2, bit_mask);
    		if (t1 != t2)
    		{
    		    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_index");
    		    return i;
    		}
    		else
    		{
    			bit_mask = bit_mask >> 4;
    		}
    		i++;
    	}
    }

    if (i == max_len) i = max_len - 1;
    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_index");
    return i;
}

uint8_t _dhkey_hexalpha_at (const np_dhkey_t* key, const int8_t c)
{
    log_msg (LOG_KEY | LOG_TRACE, ".start._dhkey_hexalpha_at");
    uint8_t j = 1;
    uint64_t answer = 0;

    uint8_t tuple      = (uint8_t) c / 16 ; // array index
    uint8_t tuple_rest = c % 16;            // position in found array

    log_msg (LOG_KEY | LOG_DEBUG, "lookup_pos: %d -> key[%d]: %016llx mod %u", c, tuple, key->t[tuple], tuple_rest);

    uint64_t bit_mask = 0xf000000000000000;
    for (; j < tuple_rest; ++j)
    {
    	// shift bitmask to correct position
    	bit_mask = bit_mask >> 4;
    }
    log_msg (LOG_KEY | LOG_DEBUG, "bitmask: %016llx", bit_mask);
    // filter with bitmask
    answer = key->t[tuple] & bit_mask;
    log_msg (LOG_KEY | LOG_DEBUG, "bitmask & key->[%d]: %016llx", tuple, answer);

    for (; j < 16; ++j)
    {
    	// shift result to the end of the number
    	answer = answer >> 4;
    }
    log_msg (LOG_KEY | LOG_DEBUG, "final answer: %d (%0x)", answer, answer);

    log_msg (LOG_KEY | LOG_TRACE, ".end  ._dhkey_hexalpha_at");
    return (uint8_t) answer;
}
