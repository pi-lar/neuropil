#!/usr/bin/env python
import os
import re
import platform as p
import argparse
import tarfile
import subprocess
import getpass
import requests
import collections
import pathlib
from pprint import pprint

try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus

rx = re.compile(r'#define NEUROPIL_RELEASE	"(.*(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+).*)"')

dir_path = os.path.dirname(os.path.realpath(__file__))

def sign_file(filepath, sign_file, pw):   
    cmds = [
            ["openssl","dgst","-sha256","-sign",sign_file,"-passin",f"pass:{pw}","-out",f"{filepath}.sha256",f"{filepath}"],
            ["openssl","base64","-in",f"{filepath}.sha256", "-out", f"{filepath}.sha256.base64"],
            ["rm",f"{filepath}.sha256"]
        ]
    for cmd in cmds:
        #print("Calling: \""+" ".join(cmd)+"\"")
        subprocess.check_call(cmd)

def sign_folder(sign_file,folder,pw):    
    for root, dirs, files in os.walk(os.path.join(dir_path, folder)):
        for file in files:
            if not file.endswith(".base64"):
                sign_file("%s/%s%s"%(dir_path,folder,file ), sign_file, pw)

def get_semver():
    version = "could_not_detect_version"
    with open(os.path.join(dir_path,"include","neuropil.h"),'rb') as f:
        for line in f:
            ver = rx.search(line.decode('UTF-8'))
            if(ver):
                version = {
                    "major": ver.group("major"),
                    "minor": ver.group("minor"),
                    "patch": ver.group("patch"),
                }
                break
    return version
def get_semver_str():
    semver = get_semver()
    return f"{semver['major']}.{semver['minor']}.{semver['patch']}"
    
def get_version():
    version = "could_not_detect_version"
    with open(os.path.join(dir_path,"include","neuropil.h"),'rb') as f:
        for line in f:
            ver = rx.search(line.decode('UTF-8'))
            if(ver):
                version = ver.group(1)
                break

    return version

def get_version_tag():
    return ("%s_beta"% (get_version()))

def get_build_name():
    return quote_plus("%s__%s__%s__%s" % (get_version_tag(), p.system(), p.release(), p.machine()))

targets = [
    {
        'key':"freebsd",
        'tarfile_name': "{version_tag}_{target}.tar.gz",
    },
    {
        'key':"linux",
        'tarfile_name': "{version_tag}_{target}.tar.gz",
    },
]
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Build helper.')
    parser.add_argument('--package',help='build the tar file',action="store_true")
    parser.add_argument('--gitlab_release',help='Creates a gitlab release',action="store_true")
    parser.add_argument('--pw',help='provide the password in the build process')
    parser.add_argument('--sign_file', help='provide the key file used in the build process')
    parser.add_argument('--version',help='prints the current version',action="store_true")
    parser.add_argument('--versiontag',help='prints the current version tag',action="store_true")
    args = parser.parse_args()
    version = get_version()
    version_tag = get_version_tag()
        
    root_path = os.path.join("build","package")

    if args.version:
        print(version)
    elif args.versiontag:
        print(version_tag)
    elif args.package or args.gitlab_release:
        doc_tarfile_name = "{version_tag}_documentation.tar.gz".format(**locals())
        doc_tarfilepath = os.path.join(root_path, doc_tarfile_name)

        if args.package:
            if not args.pw:
                args.pw = os.environ.get("NEUROPIL_BUILD_PW")
                
            if not args.sign_file:
                args.sign_file = os.environ.get("NEUROPIL_BUILD_KEYFILE")
            if not args.sign_file:
                args.sign_file = input("Please insert file location for sign key: ")

            if not args.pw:
                args.pw = getpass.getpass("Please insert key password: ")            
                
            pathlib.Path(root_path).mkdir(parents=True, exist_ok=True)

            if not os.path.isfile(args.sign_file):    
                print("Creating DEV sign key. DO NOT USE FOR TEST OR PRODUCTION!")            
                #subprocess.check_call(("openssl genpkey -algorithm RSA -out "+args.sign_file+" -pkeyopt rsa_keygen_bits:4096 -des3 -pass pass:"+args.pw).split(" "))
                subprocess.check_call(["openssl", "genrsa", "-aes128", "-passout", f"pass:{args.pw}", "-out", f"{args.sign_file}", "4096"])
                subprocess.check_call(["openssl", "rsa", "-in", f"{args.sign_file}", "-passin", f"pass:{args.pw}", "-pubout", "-out", f"{args.sign_file}_public.pem"])
            
            
            with tarfile.open(doc_tarfilepath, "w:gz") as tar:                
                tar.add(os.path.join("build","doc","html"),         arcname=os.path.join(version_tag, "doc"))
            print("Created TAR file in {doc_tarfilepath}".format(**locals()))
            sign_file(doc_tarfilepath, args.sign_file,  args.pw)
            print("Signed  TAR file in {doc_tarfilepath}".format(**locals()))
            for target_conf in targets:
                target = target_conf['key']
                tarfile_name = target_conf['tarfile_name'].format(**locals())
                tarfilepath = os.path.join(root_path, tarfile_name)
                
                if not os.path.isdir(os.path.join("build",target)):
                    print(f"ignoring {target} as no directory is found")
                else:
                    with tarfile.open(tarfilepath, "w:gz") as tar:                
                        tar.add(os.path.join("build",target,"lib"),         arcname=os.path.join(version_tag, "lib"))
                        tar.add(os.path.join("build",target,"bin"),         arcname=os.path.join(version_tag, "bin"))
                        tar.add(os.path.join("build","doc","html"),         arcname=os.path.join(version_tag, "doc"))
                        tar.add(os.path.join("include","neuropil.h"),       arcname=os.path.join(version_tag, "include","neuropil.h"))
                        tar.add(os.path.join("README"),                     arcname=os.path.join(version_tag, "README"))
                        tar.add(os.path.join("LICENSE"),                    arcname=os.path.join(version_tag, "LICENSE"))
                    print("Created TAR file in {tarfilepath}".format(**locals()))
                    sign_file(tarfilepath, args.sign_file,  args.pw)
                    print("Signed  TAR file in {tarfilepath}".format(**locals()))

        if args.gitlab_release:
            GITLAB_API_TOKEN = os.environ.get("GITLAB_API_TOKEN")
            if not GITLAB_API_TOKEN:
                GITLAB_API_TOKEN = getpass.getpass("Please insert GITLAB_API_TOKEN: ")
            
            release_url = 'https://gitlab.com/api/v4/projects/14096230/releases'
            headers = {
                  'PRIVATE-TOKEN': GITLAB_API_TOKEN
            }
            
            release_payload = collections.OrderedDict({ 
                "name": version_tag,
                "tag_name": version,
                "ref": subprocess.check_output(['git','rev-parse','HEAD']).decode("utf-8")[:-1],
                "description": "Neuropil Release {version}".format(**locals()), 
                "assets": { 
                     "links": [] 
                }
            })
            url = 'https://gitlab.com/api/v4/projects/14096230/uploads'
            files = {'file': open(doc_tarfilepath,"rb") }
            r = requests.post(url, files=files, headers=headers)                
            try:
                r.raise_for_status()
            except:
                print("create asset response:")
                print(r.text)
                raise
            url = r.json()['url']             
            release_payload["assets"]["links"].append({
                "name": "{doc_tarfile_name}".format(**locals()),
                "url": "https://gitlab.com/pi-lar/neuropil{url}".format(**locals())
                })         

            for target_conf in targets:
                target = target_conf['key']
                if not os.path.isdir(os.path.join("build",target)):
                    print(f"ignoring {target} as no directory is found")
                else:
                    for ext in ["",".sha256.base64"]:
                        tarfile_name = target_conf['tarfile_name'].format(**locals())
                        tarfilepath = os.path.join(root_path, tarfile_name+ext)


                        url = 'https://gitlab.com/api/v4/projects/14096230/uploads'
                        files = {'file': open(tarfilepath,"rb") }
                        r = requests.post(url, files=files, headers=headers)                
                        try:
                            r.raise_for_status()
                        except:
                            print("create asset response:")
                            print(r.text)
                            raise
                        url = r.json()['url']                     
                        release_payload["assets"]["links"].append({
                            "name": "{tarfile_name}{ext}".format(**locals()),
                            "url": "https://gitlab.com/pi-lar/neuropil{url}".format(**locals())
                            })         

            r = requests.post(release_url, json=release_payload, headers=headers)
            try:
                r.raise_for_status()
            except:
                print("create release payload:")
                pprint(release_payload)
                print("")
                print("create release response:")
                print(r.text)
                print("")
                raise

  
    else:
        parser.print_help()