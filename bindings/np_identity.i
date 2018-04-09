//
// neuropil is copyright 2016 by pi-lar GmbH
// Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
//

%module(package="neuropil") np_identity

%include "carrays.i"
%include "cdata.i"

%{
#include "np_identity.h"
%}

%array_class(char, identity_bytes);
%cdata(char, identity_bytes) 

%include "np_identity.h"
