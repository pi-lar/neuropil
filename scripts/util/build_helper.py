#!/usr/bin/env python
import os
import re
import argparse
import subprocess
import getpass
import requests
import collections
import pathlib
from pprint import pprint
import platform as p

try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus

rx = re.compile(r'#define NEUROPIL_RELEASE	"(.*(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+).*)"')


dir_path = os.path.dirname(os.path.realpath(__file__))

def get_semver():
    version = "could_not_detect_version"
    with open(os.path.join(dir_path,"..","..","include","neuropil.h"),'rb') as f:
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
    with open(os.path.join(dir_path,"..","..","include","neuropil.h"),'rb') as f:
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Build helper.')
    parser.add_argument('--package',help='build the tar file',action="store_true")
    parser.add_argument('--gitlab_release',help='Creates a gitlab release',action="store_true")
    parser.add_argument('--pw',help='provide the password in the build process')
    parser.add_argument('--sign_file', help='provide the key file used in the build process')
    parser.add_argument('--version',help='prints the current version',action="store_true")
    parser.add_argument('--versiontag',help='prints the current version tag',action="store_true")
    parser.add_argument('--update_strings',help='update the version string in all dependend files',action="store_true")
    args = parser.parse_args()
    version = get_version()
    version_tag = get_version_tag()

    root_path = os.path.join("build","package")

    if args.update_strings:
        with open(os.path.join(dir_path, "..", "..", "bindings","python_cffi", "setup.py"),"r+") as f:
            txt = f.read()
            f.seek(0)
            f.write(re.sub(r"version.+,",f"version = '{get_semver_str()}',",txt))
    elif args.version:
        print(version)
    elif args.versiontag:
        print(version_tag)
    elif args.package or args.gitlab_release:
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

                import shutil
                os.makedirs(os.path.join('build', 'package', 'include'), exist_ok=True)
                shutil.copytree(os.path.join("build",'neuropil',"lib"),         os.path.join('build', 'package', "lib"))
                shutil.copytree(os.path.join("build",'neuropil',"bin"),         os.path.join('build', 'package', "bin"))
                shutil.copytree(os.path.join("build","doc","html"),             os.path.join('build', 'package', "doc"))
                shutil.copy(os.path.join("include","neuropil.h"),           os.path.join('build', 'package', "include","neuropil.h"))
                shutil.copy(os.path.join("include","neuropil_attributes.h"),os.path.join('build', 'package', "include","neuropil_attributes.h"))
                shutil.copy(os.path.join("include","neuropil_data.h"),      os.path.join('build', 'package', "include","neuropil_data.h"))
                shutil.copy(os.path.join("README"),                         os.path.join('build', 'package', "README"))
                shutil.copy(os.path.join("LICENSE"),                        os.path.join('build', 'package', "LICENSE"))

                for (dirpath, dirnames, filenames) in os.walk(os.path.join('build', 'package', "lib")):
                    for filename in filenames:
                        sign_file(os.path.join(dirpath,filename), args.sign_file,  args.pw)

        if args.gitlab_release:
            print(f"start gitlab release process")
            tag_ref = subprocess.check_output(['git','rev-parse','HEAD']).decode("utf-8")[:-1]
            GITLAB_API_TOKEN = os.environ.get("GITLAB_API_TOKEN")
            CI_PIPELINE_IID = os.environ.get("CI_PIPELINE_IID")
            project_id = os.getenv("CI_PROJECT_ID","14096230")
            base_url = os.environ.get("CI_SERVER_URL","https://gitlab.com")
            api_url = f"{base_url}/api/v4"

            if not GITLAB_API_TOKEN:
                GITLAB_API_TOKEN = getpass.getpass("Please insert GITLAB_API_TOKEN: ")

            headers = {
                  'PRIVATE-TOKEN': GITLAB_API_TOKEN
            }
            project_config = requests.get(f"{api_url}/projects/{project_id}", headers=headers).json()
            print(f"project_config: {project_config.text}")
            project_config = project_config.json()
            release_url = f"{api_url}/projects/{project_id}/releases"

            release_payload = collections.OrderedDict({
                "name": version_tag,
                "tag_name": version,
                "ref": tag_ref,
                "description": "Neuropil Release {version}".format(**locals()),
                "assets": {
                     "links": []
                }
            })

            targets = ['linux']
            # targets should contain all the build stages of the gitlab-ci build stage
            for target in targets:
                target_url = f"{base_url}/{project_config['path_with_namespace']}/-/jobs/artifacts/{version}/download?job=package%3A{target}"
                print(f"adding asset link for target {target} via {target_url")
                release_payload["assets"]["links"].append({
                    "name": f"{target}.zip",
                    "url": target_url
                })

            print(f"Create release")
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

            print(f"remove latest_release tag")
            tags_url = f"{api_url}/projects/{project_id}/repository/tags"

            r = requests.delete(f"{tags_url}/latest_release", headers=headers)
            try:
                r.raise_for_status()
            except:
                print("no \"latest_release\" git tag set")
                print(r.text)

            release_payload["ref"] = release_payload["tag_name"]
            release_payload["tag_name"] = "latest_release"
            release_payload["name"] = "Latest"

            print(f"recreate latest_release tag")
            r = requests.post(release_url, json=release_payload, headers=headers)
            try:
                r.raise_for_status()
            except:
                print("could not create \"latest_release\" release")
                print(r.text)
    else:
        parser.print_help()