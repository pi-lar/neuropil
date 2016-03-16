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

#include "log.h"
#include "np_key.h"
#include "np_jtree.h"


_NP_GENERATE_MEMORY_IMPLEMENTATION(np_key_t);

void _np_key_t_new(void* key)
{
	np_key_t* new_key = (np_key_t*) key;

	new_key->t[0] = new_key->t[1] = new_key->t[2] = new_key->t[3] = 0;
	memset(new_key->keystr, 0, 64);
    new_key->valid = FALSE;		  // indicates if the keystr is most up to date with value in t

    new_key->node = NULL;		  // link to a neuropil node if this key represents a node
    new_key->network = NULL;      // link to a neuropil node if this key represents a node

    new_key->authentication = NULL; // link to node if this key has an authentication token
    new_key->authorisation = NULL;  // link to node if this key has an authorisation token
    new_key->accounting = NULL;     // link to node if this key has an accounting token

    // used internally only
    new_key->recv_property = NULL;
    new_key->send_property = NULL;
    new_key->send_tokens = NULL; // link to runtime interest data on which this node is interested in
    new_key->recv_tokens = NULL; // link to runtime interest data on which this node is interested in
}

void _np_key_t_del(void* key)
{
	// empty
}

void key_to_str (np_key_t* k)
{
    k->valid = FALSE;

    // log_msg(LOG_KEY | LOG_WARN, "key %0lu %0lu %0lu %0lu", k->t[0], k->t[1], k->t[2], k->t[3]);
	// log_msg(LOG_KEY | LOG_WARN, "key %16lx%16lx%16lx%16lx", k->t[0], k->t[1], k->t[2], k->t[3]);
    // TODO: use sodium bin2hex function
	memset  (k->keystr, 0, 64);
	sprintf ((char*) k->keystr, "%016llx%016llx%016llx%016llx", k->t[0], k->t[1], k->t[2], k->t[3]);
	k->keystr[64] = '\0';
	k->valid = TRUE;
    // log_msg (LOG_KEY | LOG_DEBUG, "key string now: %s", k->keystr);
}

void str_to_key (np_key_t* k, const char* key_string)
{
	// TODO: this is dangerous, encoding could be different between systems,
	// encoding has to be send over teh wire to be sure ...
	// for now: all tests on the same system
    k->valid = FALSE;

    memset (k->keystr, 0, 64);
    memcpy (k->keystr, key_string, 64);
    k->keystr[64] = '\0';

    for (uint8_t i = 0; i < 4; i++)
    {
    	char substring[17];
    	memcpy(substring, k->keystr + i*16, 16);
    	substring[16] = '\0';
    	k->t[i] = strtoull((const char*) substring, NULL, 16);
        // log_msg(LOG_KEY | LOG_DEBUG, "keystr substring to ul: %s -> %ul ", substring, k->t[i]);
    }
    // log_msg(LOG_KEY | LOG_WARN, "key %0lu %0lu %0lu %0lu", k->t[0], k->t[1], k->t[2], k->t[3]);

    k->valid = TRUE;
}

char* _key_generate_hash (const unsigned char* key_in, size_t digest_size, char* digest_out)
{
    unsigned char md_value[32]; //  = (unsigned char *) malloc (32);
    // uint8_t i;
    // char digit[10];
    // char *tmp;

    // TODO: move it to KECCAK because of possible length extension attack ???
    // TODO: move to SHA-2 at least ?
    crypto_hash_sha256(md_value, key_in, digest_size);

    // log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, md_value);
    // long form - could be used to add addiitonal configuration parameter
    //    crypto_hash_sha256_state state;
    //    crypto_hash_sha256_init(&state);
    //    crypto_hash_sha256_update(&state, key_in, sizeof(key_in));
    //    crypto_hash_sha256_final(&state, tmp);
    //    log_msg (LOG_KEYDEBUG, "md value (%s) now: [%s]", key_in, tmp);
    digest_out = (char *) malloc (65);
	sodium_bin2hex(digest_out, 65, md_value, 32);

	// digest = strndup(md_value, 64);
    // printf("key.c:sha1_keygen digest %s\n", digest);

//    tmp = digest_out;
//    *tmp = '\0';
//    for (i = 0; i < 32; i++)
//	{
//    	convert_base16 (md_value[i], digit);
//    	// memcpy(tmp, digit, sizeof(digit));
//	    strncat ((char*)tmp, digit);
//	    tmp = tmp + strlen (digit);
//	}
//    digest_out[64] = '\0';

    return digest_out;
}

np_key_t* key_create_from_hostport(const char* strOrig, char* port)
{
	char name[256];
	snprintf (name, 255, "%s:%s", strOrig, port);
	char* digest = NULL;

	digest = _key_generate_hash ((unsigned char*) name, strlen(name), digest);
	// log_msg (LOG_KEY | LOG_DEBUG, "digest calculation returned HASH: %s", digest);

    np_key_t* tmp = key_create_from_hash(digest);
	// log_msg (LOG_KEY | LOG_DEBUG, "HASH(%s) = [%s]", name, key_get_as_string(tmp));

	free (digest);
	return tmp;
}

void np_encode_key(np_jtree_t* jrb, np_key_t* key)
{
    // log_msg(LOG_KEY | LOG_WARN, "encoding key %0lu %0lu %0lu %0lu", key->t[0], key->t[1], key->t[2], key->t[3]);

	jrb_insert_str(jrb, "_np.key.0", new_jval_ull(key->t[0]));
	jrb_insert_str(jrb, "_np.key.1", new_jval_ull(key->t[1]));
	jrb_insert_str(jrb, "_np.key.2", new_jval_ull(key->t[2]));
	jrb_insert_str(jrb, "_np.key.3", new_jval_ull(key->t[3]));
}

void np_decode_key(np_jtree_t* jrb, np_key_t* key)
{
	key->t[0] = jrb_find_str(jrb, "_np.key.0")->val.value.ull;
	key->t[1] = jrb_find_str(jrb, "_np.key.1")->val.value.ull;
	key->t[2] = jrb_find_str(jrb, "_np.key.2")->val.value.ull;
	key->t[3] = jrb_find_str(jrb, "_np.key.3")->val.value.ull;

    // log_msg(LOG_KEY | LOG_WARN, "decoded key %0lu %0lu %0lu %0lu", key->t[0], key->t[1], key->t[2], key->t[3]);

	key->valid = FALSE;
}

np_key_t* key_create_from_hash(const char* strOrig)
{
    np_key_t* kResult = NULL;
    np_new_obj(np_key_t, kResult);

    str_to_key(kResult, strOrig);

    kResult->valid = TRUE;

    return kResult;
}

void key_assign (np_key_t* k1, const np_key_t* const k2)
{
    for (uint8_t i = 0; i < 4; i++)
    	k1->t[i] = k2->t[i];

    k1->valid = FALSE;
}

void key_assign_ui (np_key_t* k, uint64_t ul)
{
	log_msg (LOG_KEY | LOG_WARN, "!!! deprecated function called key_assign_ui");
    for (uint8_t i = 1; i < 3; i++)
    	k->t[i] = 0;
    k->t[3] = ul;

    k->valid = FALSE;
}

np_bool key_equal (np_key_t* k1, np_key_t* k2)
{
    for (uint8_t i = 0; i < 4; i++)
    	if (k1->t[i] != k2->t[i])
    		return FALSE;
    return TRUE;
}

np_bool key_equal_ui (np_key_t* k, uint64_t ul)
{
	log_msg (LOG_KEY | LOG_WARN, "!!! deprecated function called key_equal_ui");

	if (k->t[3] != ul) return (0);

    for (uint8_t i = 2; i-- != 0; )
    	if (k->t[i] != 0)
    		return FALSE;
    return TRUE;
}

int8_t key_comp (const np_key_t* k1, const np_key_t* k2)
{
	if (k1 == NULL) return -1;
	if (k2 == NULL) return 1;
	if (k1 == k2) return 0;

	// log_msg(LOG_KEY | LOG_DEBUG, "k1 %p / k2 %p", k1, k2);
    for (uint8_t i = 0; i < 4; i++)
	{
	    if 		(k1->t[i] > k2->t[i]) return (1);
	    else if (k1->t[i] < k2->t[i]) return (-1);
	}
    return (0);
}

void key_add (np_key_t* result, const np_key_t* const op1, const np_key_t* const op2)
{
    double tmp, a, b;
    // a = b =
    tmp = 0;

    for (uint8_t i = 3; i-- != 0; )
	{
	    a = op1->t[i];
	    b = op2->t[i];

	    tmp += a + b;

	    if (tmp > ULONG_MAX) tmp = 1; // tmp - ULONG_MAX;
	    else                 tmp = 0;

	    result->t[i] = (uint64_t) tmp;
	}
    result->valid = FALSE;
}

void key_sub (np_key_t* result, const np_key_t* const op1, const np_key_t* const op2)
{
	log_msg (LOG_KEY | LOG_TRACE, ".start.key_sub");
    double tmp, a, b, carry;
    np_key_t key_a, key_b, key_tmp;
    np_bool swapped = 0;

    carry = 0;

    key_assign(&key_a, op1);
	key_assign(&key_b, op2);

    if (key_comp (&key_a, &key_b) < 0)
	{
    	// swap keys and do the calculation
    	key_assign(&key_tmp, &key_a);
    	key_assign(&key_a, &key_b);
    	key_assign(&key_b, &key_tmp);
    	// log_msg (LOG_KEY | LOG_DEBUG, "swapped input data (key_a < key_b");
    	swapped = TRUE;
	}

    for (uint8_t i = 3; i-- != 0; )
	{
	    a = key_a.t[i] - carry;
	    b = key_b.t[i];

	    if (b <= a)
		{
		    tmp = a - b;
		    carry = 0;
		}
	    else
		{
		    a = a + ULONG_MAX + 1;
		    tmp = a - b;
		    carry = 1;
		}
	    result->t[i] = (uint64_t) tmp;
	}

    if (TRUE == swapped) {
    	key_assign(&key_tmp, result);
    	key_sub(result, &Key_Max, &key_tmp);
    }

    result->valid = FALSE;

    log_msg (LOG_KEY | LOG_TRACE, ".end  .key_sub");
}


void key_init ()
{
    for (uint8_t i = 0; i < 4; i++)
	{
        Key_Max.t[i] = ULONG_MAX;
        Key_Half.t[i] = ULONG_MAX;
	}
    Key_Half.t[0] = Key_Half.t[0] / 2;

    key_to_str (&Key_Max);
    key_to_str (&Key_Half);
}

void key_distance (np_key_t* diff, const np_key_t* const k1, const np_key_t* const k2)
{
    key_sub (diff, k1, k2);
    diff->valid = FALSE;
}


np_bool key_between (const np_key_t* const test, const np_key_t* const left, const np_key_t* const right)
{
    int8_t complr = key_comp (left, right);
    int8_t complt = key_comp (left, test);
    int8_t comptr = key_comp (test, right);

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
}

// Return the string representation of key
// This function should be used instead of directly accessing the keystr field
unsigned char* key_get_as_string (np_key_t* key)
{
    if (FALSE == key->valid)
	{
	    key_to_str (key);
	}
    return key->keystr;
}

void key_midpoint (np_key_t* mid, np_key_t* key)
{

    if   (key_comp (key, &Key_Half) < 0) key_add (mid, key, &Key_Half);
    else  	                             key_sub (mid, key, &Key_Half);
    mid->valid = FALSE;
}

uint16_t key_index (np_key_t* mykey, np_key_t* k)
{
	uint16_t i, max_len = 64;
    unsigned char mystr[65];
    unsigned char kstr[65];
    memcpy (mystr, key_get_as_string (mykey), 64);
    memcpy (kstr, key_get_as_string (k), 64);

    for (i = 0; (mystr[i] == kstr[i]) && (i < max_len); i++);

    if (i == max_len) i = max_len - 1;

    // log_msg (LOG_KEY | LOG_DEBUG, "key_index:%d me:%s lookup_key:%s", i, mykey->keystr, k->keystr);
    return (i);
}

/** find_closest_key:
 ** finds the closest node in the array of #hosts# to #key# and put that in min.
 */
np_key_t* find_closest_key ( np_sll_t(np_key_t, list_of_keys), np_key_t* key)
{
    // int i;
    np_key_t dif, mindif;
    np_key_t *min;

    if (sll_size(list_of_keys) == 0)
	{
	    min = NULL;
	    // return;
	    // modified StSw 18.05.2014
	    log_msg(LOG_KEY | LOG_ERROR, "minimum size for closest key calculation not met !");
	    return min;
	}
    else
	{
	    min = sll_first(list_of_keys)->val;
	    key_distance (&mindif, min, key);
	}

	sll_iterator(np_key_t) iter = sll_first(list_of_keys);
    while (NULL != (sll_next(iter)))
	{
    	key_distance (&dif, iter->val, key);

    	if (key_comp (&dif, &mindif) < 0)
    	{
    		min = iter->val;
    		key_assign (&mindif, &dif);
		}
	}
    return (min);
}

/** sort_hosts:
 ** Sorts #hosts# based on common prefix match and key distance from #np_key_t*
 */
void sort_keys_cpm (np_sll_t(np_key_t, node_keys), np_key_t* key)
{
    np_key_t dif1, dif2;

    uint16_t pmatch1 = 0;
    uint16_t pmatch2 = 0;

    if (sll_size(node_keys) < 2) return;

    np_key_t* tmp;
    sll_iterator(np_key_t) iter1 = sll_first(node_keys);

    do
    {
        sll_iterator(np_key_t) iter2 = sll_get_next(iter1);

        if (NULL == iter2) break;

        do
        {
        	pmatch1 = key_index (key, iter1->val);
			pmatch2 = key_index (key, iter2->val);
			if (pmatch2 > pmatch1)
			{
				tmp = iter1->val;
				iter1->val = iter2->val;
				iter2->val = tmp;
			}
			else if (pmatch1 == pmatch2)
			{
			    key_distance (&dif1, iter1->val, key);
			    key_distance (&dif2, iter2->val, key);
			    if (key_comp (&dif2, &dif1) < 0)
				{
					tmp = iter1->val;
					iter1->val = iter2->val;
					iter2->val = tmp;
				}
			}
		} while (NULL != (sll_next(iter2)) );
	} while (NULL != (sll_next(iter1)) );
}


/** sort_hosts_key:
 ** Sorts #hosts# based on their key distance from #np_key_t*
 */
void sort_keys_kd (np_sll_t(np_key_t, list_of_keys), np_key_t* key)
{
    np_key_t dif1, dif2;

    // entry check for empty list
    if (NULL == sll_first(list_of_keys)) return;

    sll_iterator(np_key_t) curr = sll_first(list_of_keys);
    do {
        // Maintain pointers.
        sll_iterator(np_key_t) next = sll_get_next(curr);

        // Cannot swap last element with its next.
        while (NULL != next) {
        	// Swap if items in wrong order.
		    key_distance (&dif1, curr->val, key);
		    key_distance (&dif2, next->val, key);
		    if (key_comp (&dif2, &dif1) < 0)
			{
		    	np_key_t* tmp = curr->val;
		    	curr->val = next->val;
		    	next->val = tmp;
		    	// Notify loop to do one more pass.
                break;
			}
		    // continue with the loop
		    sll_next(next);
        }
	    sll_next(curr);

    } while (curr != sll_last(list_of_keys) && NULL != curr);

//    for (i = 0; i < size; i++)
//	{
//	    for (j = i + 1; j < size; j++)
//		{
//		    if (hosts[i] != NULL && hosts[j] != NULL)
//			{
//			    key_distance (&dif1, hosts[i], key);
//			    key_distance (&dif2, hosts[j], key);
//			    if (key_comp (&dif2, &dif1) < 0)
//				{
//				    tmp = hosts[i];
//				    hosts[i] = hosts[j];
//				    hosts[j] = tmp;
//				}
//			}
//		}
//	}
}



