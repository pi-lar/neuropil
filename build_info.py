#!/usr/bin/env python
import os
import re
import platform as p
import argparse
import tarfile
import subprocess
try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus

rx = re.compile("#define NEUROPIL_RELEASE	[\"'](.*)[\"']")

def sign_file(filepath,pw):
    data = {
        'pw':pw,
        'filepath':filepath
    }
    cmds = [        
            ["openssl","dgst","-sha256","-sign","build_sign.key","-passin","pass:%(pw)s"% data,"-out","%(filepath)s.sig.raw"% data,"%(filepath)s"% data],
            ["openssl","base64","-in","%(filepath)s.sig.raw"% data, "-out", "%(filepath)s.sha256.sig" % data],
            ["rm","%(filepath)s.sig.raw"% data] 
        ]
    for cmd in cmds:    
        subprocess.check_call(cmd)

def sign_folder(folder,pw):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    for root, dirs, files in os.walk("%s/%s"%(dir_path, folder)):
        for file in files:
            if not file.endswith(".sig"):
                sign_file("%s/%s%s"%(dir_path,folder,file ), pw)


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
    return quote_plus("%s__%s__%s__%s" % (get_version_tag(), p.system(), p.release(), p.machine()))

if __name__ == "__main__":
    if not os.path.isdir('release'):
        os.mkdir('release')
    parser = argparse.ArgumentParser(description='Build helper.')
    parser.add_argument('--build',help='build the tar file',action="store_true")
    parser.add_argument('--pw',help='provide the password in the build process')
    parser.add_argument('--version',help='prints the current version',action="store_true")
    parser.add_argument('--versiontag',help='prints the current version tag',action="store_true")
    args = parser.parse_args()
    action = False
    if args.build:
        if not args.pw:
            print "missing parameter -pw in build"
            action = False
        else:
            action = True        
            sign_folder("bin/",args.pw)
            sign_folder("build/lib/",args.pw)
            tarfilepath = "release/%s.tar.gz" % (get_build_name())
            with tarfile.open(tarfilepath, "w:gz") as tar:
                tar.add("build/lib/", arcname=os.path.basename("build/lib/"))
                tar.add("bin/", arcname=os.path.basename("bin/"))
                tar.add("README", arcname=os.path.basename(""))
                tar.add("LICENSE", arcname=os.path.basename(""))
            sign_file(tarfilepath,args.pw)
    if args.version:
        action = True
        print get_version()
    if args.versiontag:
        action = True
        print get_version_tag()
    if action != True:
        parser.print_help()
