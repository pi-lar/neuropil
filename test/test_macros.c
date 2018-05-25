#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

#include <criterion/criterion.h>
#include <criterion/logging.h>

#include <np_interface.h>
#include <neuropil.h>


#ifndef _NP_TEST_MACROS_H_
#define _NP_TEST_MACROS_H_
#define MEASURE_TIME(array, pos, func)  {                    \
		clock_t begin = clock();                             \
		func;                                                \
		clock_t end = clock();                               \
		array[pos] = (double)(end - begin) / CLOCKS_PER_SEC; \
    }

#define CALC_AND_PRINT_STATISTICS(name, array, max_size)  {                                  \
		double min = 2.0, max = 0.0, avg = 0.0, stddev = 0.0;                                \
		for (uint16_t j = 0; j < max_size; j++)                                              \
		{                                                                                    \
			min = (min < array[j]) ? min : array[j];                                         \
			max = (max > array[j]) ? max : array[j];                                         \
			avg += array[j];                                                                 \
		}                                                                                    \
		avg = avg / max_size;                                                                \
		for (uint16_t j = 0; j < max_size; j++) {                                            \
		    stddev += pow(array[j] - avg, 2);                                                \
		}                                                                                    \
		stddev = sqrt(stddev/(max_size-1));                                                  \
		cr_log_warn("%s --> %.6f / %.6f / %.6f / %.6f \n", name, min, avg, max, stddev); \
}

np_state_t* _np_test_ctx(char* name, char* desc, char* porttype, int port);

#define TCTX(...) VFUNC(TCTX, __VA_ARGS__)
#define TCTX5(ID, NAME, DESC, PORTTYPE, PORT)  np_state_t* ID; for(uint8_t _CTX_i##__LINE__=0; (_CTX_i##__LINE__ < 1) && NULL != (ID = _np_test_ctx(NAME, DESC, PORTTYPE, PORT)); np_destroy(ID, false), _CTX_i##__LINE__++)
#define TCTX4(ID, DESC, PORTTYPE, PORT) TCTX5(ID, __func__, DESC, PORTTYPE, PORT)
#define TCTX2(ID, DESC) TCTX4(ID, DESC, "udp4", 3000)
#define TCTX1(DESC) TCTX2(context, DESC)
#define CTX() TCTX1("")

#endif // _NP_TEST_MACROS_H_
#ifndef _NP_TEST_MACROS_C_
#define _NP_TEST_MACROS_C_
np_state_t* _np_test_ctx(char* name, char* desc, char* porttype, int port) {
	np_state_t* ret;
	struct np_settings* settings = np_new_settings(NULL);

	if(desc != NULL && strlen(desc) > 0)
		sprintf(settings->log_file, "neuropil_test_%s_%s.log", name, desc);
	else
		sprintf(settings->log_file, "neuropil_test_%s.log", name);

	settings->log_level |= LOG_GLOBAL;
	ret = np_new_context(settings);
	assert(ret != NULL);
	assert(np_ok == np_listen(ret, porttype, "localhost", port));

	return ret;
}
#endif // _NP_TEST_MACROS_C_