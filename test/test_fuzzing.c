// test_fuzzing.c
#include "neuropil.h"

#include "./test_macros.c"

#ifdef __cplusplus
extern "C" {
#endif

	int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

		CTX() {
			char* input_string = malloc(sizeof(char)*Size+1);
			memcpy(input_string, Data, Size);
			input_string[Size] = '\0';

			np_join(context, input_string);
		}
		return 0;  // Non-zero return values are reserved for future use.
	}
#ifdef __cplusplus
}
#endif
