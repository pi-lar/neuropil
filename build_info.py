#!/usr/bin/env python
import os
import re
import platform as p
import argparse
import tarfile

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
    return  ("%s__%s__%s__%s" % (get_version_tag(), p.system(), p.release(), p.machine()))

if __name__ == "__main__":
    if not os.path.isdir('release'):
        os.mkdir('release')
    parser = argparse.ArgumentParser(description='Build helper.')
    parser.add_argument('--build',help='build the tar file',action="store_true")
    parser.add_argument('--version',help='prints the current version',action="store_true")
    parser.add_argument('--versiontag',help='prints the current version tag',action="store_true")
    args = parser.parse_args()

    action = False
    if args.build:
        action = True
        with tarfile.open("release/%s.tar.gz" % (get_build_name()), "w:gz") as tar:
            tar.add("build/lib/", arcname=os.path.basename("build/lib/"))
            tar.add("bin/", arcname=os.path.basename("bin/"))
    if args.version:
        action = True
        print get_version()
    if args.versiontag:
        action = True
        print get_version_tag()
    if action != True:
        parser.print_help()
