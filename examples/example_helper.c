//
// neuropil is copyright 2017 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include "neuropil.h"
#include "np_types.h"
#include "np_memory.h"
#include "np_messagepart.h"

void __np_example_helper_run_loop(){
	uint32_t i = 0;
	while (TRUE) {
	    i +=1;
	    ev_sleep(0.01);
#ifdef DEBUG
  #if DEBUG == 1
	    if(i % 100 == 0) {
	    	// to output
	    	char* memory_str = np_mem_printpool(FALSE);
	    //	if(memory_str != NULL) printf("%s", memory_str);
	    	free(memory_str);

	    	memory_str = np_messagepart_printcache(FALSE);
	    	//if(memory_str != NULL) printf("%s", memory_str);
			free(memory_str);

	    	// to logfile
	    	memory_str = np_mem_printpool(TRUE);
	    	if(memory_str != NULL) log_msg(LOG_INFO, "%s", memory_str );
	    	free(memory_str);
	    }

	    //if((i == (35/*sec*/ * 10))){
		//	fprintf(stdout, "Renew bootstrap token");
		//	np_key_renew_token();
	    //}
  #endif
#endif
	}
}
