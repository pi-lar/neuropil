#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <math.h>

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
		fprintf(stdout, "%s --> %.6f / %.6f / %.6f / %.6f \n", name, min, avg, max, stddev); \
}

