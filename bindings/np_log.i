//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_log

%{
#include "../include/np_log.h"
%}

%ignore _np_log_fflush;
%ignore np_log_message;

%include "../include/np_log.h"
