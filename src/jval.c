#include <stdio.h>
#include <string.h>

#include "jval.h"
#include "jrb.h"
#include "log.h"

np_jval_t JNULL;

np_jval_t new_jval_i (int i)
{
    np_jval_t j;
    j.value.i = i;
    j.type = int_type;
    // log_msg(LOG_DEBUG, "size of int: %d", sizeof(int));
    return j;
}

np_jval_t new_jval_l (long l)
{
    np_jval_t j;
    j.value.l = l;
    j.type = long_type;
    return j;
}

np_jval_t new_jval_f (float f)
{
    np_jval_t j;
    j.value.f = f;
    j.type = float_type;
    return j;
}

np_jval_t new_jval_d (double d)
{
    np_jval_t j;
    j.value.d = d;
    j.type = double_type;
    // log_msg(LOG_DEBUG, "size of double: %d", sizeof(double));
    return j;
}

np_jval_t new_jval_v (void *v)
{
    np_jval_t j;
    j.value.v = v;
    j.type = void_type;
    return j;
}

np_jval_t new_jval_s (char *s)
{
    np_jval_t j;
    j.value.s = s;
    j.size = strlen(s);
    // log_msg(LOG_DEBUG, "setting string value %s (size: %d)", s, strlen(s));
    j.type = char_ptr_type;
    return j;
}

np_jval_t new_jval_c (char c)
{
    np_jval_t j;
    j.value.c = c;
    j.type = char_type;
    return j;
}

np_jval_t new_jval_uc (unsigned char uc)
{
    np_jval_t j;
    j.value.uc = uc;
    j.type = unsigned_char_type;
    return j;
}

np_jval_t new_jval_sh (short sh)
{
    np_jval_t j;
    j.value.sh = sh;
    j.type = short_type;
    return j;
}

np_jval_t new_jval_ush (unsigned short ush)
{
    np_jval_t j;
    j.value.ush = ush;
    j.type = unsigned_short_type;
    return j;
}

np_jval_t new_jval_ui (unsigned int i)
{
    np_jval_t j;
    j.value.ui = i;
    j.type = unsigned_int_type;
    return j;
}

np_jval_t new_jval_ul (unsigned long ul)
{
    np_jval_t j;
    j.value.ul = ul;
    j.type = unsigned_long_type;
    return j;
}

np_jval_t new_jval_bin (void* data, unsigned long ul)
{
    np_jval_t j;

    j.value.bin = data;
    j.size = ul;
    j.type = bin_type;

    return j;
}

np_jval_t new_jval_key (np_key_t* key)
{
    np_jval_t j;

    j.value.key = key;
    j.size = sizeof(key);
    j.type = key_type;

    return j;
}

np_jval_t new_jval_iarray (int i0, int i1)
{
    np_jval_t j;
    j.value.iarray[0] = i0;
    j.value.iarray[1] = i1;
    j.type = int_array_2_type;
    return j;
}

np_jval_t new_jval_farray (float f0, float f1)
{
    np_jval_t j;
    j.value.farray[0] = f0;
    j.value.farray[1] = f1;
    j.type = float_array_2_type;
    return j;
}

np_jval_t new_jval_carray_nt (char *carray)
{
    np_jval_t j;
    int i;

    for (i = 0; i < 8 && carray[i] != '\0'; i++)
	{
	    j.value.carray[i] = carray[i];
	}

    if (i < 8) j.value.carray[i] = carray[i];

    j.type = char_array_8_type;

    return j;
}

np_jval_t new_jval_carray_nnt (char *carray)
{
    np_jval_t j;
    memcpy (j.value.carray, carray, 8);
    j.type = unsigned_char_array_8_type;
	return j;
}

np_jval_t new_jval_tree(np_jrb_t* tree) {

	np_jval_t j;
    j.value.tree = tree;
    j.size = tree->size;
    j.type = jrb_tree_type;
	return j;
}

int jval_i (np_jval_t j)
{
    return j.value.i;
}

long jval_l (np_jval_t j)
{
    return j.value.l;
}

float jval_f (np_jval_t j)
{
    return j.value.f;
}

double jval_d (np_jval_t j)
{
    return j.value.d;
}

void *jval_v (np_jval_t j)
{
    return j.value.v;
}

char *jval_s (np_jval_t j)
{
    return j.value.s;
}

char jval_c (np_jval_t j)
{
    return j.value.c;
}

unsigned char jval_uc (np_jval_t j)
{
    return j.value.uc;
}

short jval_sh (np_jval_t j)
{
    return j.value.sh;
}

unsigned short jval_ush (np_jval_t j)
{
    return j.value.ush;
}

unsigned int jval_ui (np_jval_t j)
{
    return j.value.ui;
}

unsigned long jval_ul (np_jval_t j)
{
    return j.value.ul;
}

int* jval_iarray (np_jval_t j)
{
    return j.value.iarray;
}

float* jval_farray (np_jval_t j)
{
    return j.value.farray;
}

char* jval_carray (np_jval_t j)
{
    return j.value.carray;
}
