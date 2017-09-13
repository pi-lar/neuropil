#!/usr/bin/env python
import os
import re
import platform as p

rx = re.compile("#define NEUROPIL_RELEASE	[\"'](.*)[\"']")

def get_version():
    version = "could_not_detect_version"
    dir_path = os.path.dirname(os.path.realpath(__file__))        
    with open("%s/include/neuropil.h"%(dir_path)) as f:
        for line in f:
            ver = rx.search(line)
            if(ver):
                version = ver.group(1)
                break
            
    return version

def get_version_tag():
    version = "could_not_detect_tag"
    return ("%s_alpha"% (get_version()))

def get_build_name():
    return  ("%s %s %s %s %s" % (get_version_tag(), p.system(), p.release(), p.machine(), p.architecture()[0]))

if __name__ == "__main__":
    print get_build_name()
