#!/usr/bin/env python
# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0

import os
import re
import subprocess

try:
    from urllib.parse import quote_plus
except:
    from urllib import quote_plus

rx = re.compile(
    r'#define NEUROPIL_RELEASE\s+"(.*(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+).*)"'
)


dir_path = os.path.dirname(os.path.realpath(__file__))


def get_semver():
    version = "could_not_detect_version"
    with open(os.path.join(dir_path, "..", "..", "include", "neuropil.h"), "rb") as f:
        for line in f:
            ver = rx.search(line.decode("UTF-8"))
            if ver:
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
    with open(os.path.join(dir_path, "..", "..", "include", "neuropil.h"), "rb") as f:
        for line in f:
            ver = rx.search(line.decode("UTF-8"))
            if ver:
                version = ver.group(1)
                break

    return version


def get_version_tag():
    return "%s_beta" % (get_version())


def get_build_name():
    return quote_plus(
        "%s__%s__%s__%s" % (get_version_tag(), p.system(), p.release(), p.machine())
    )


def sign_file(filepath, sign_file, pw):
    cmds = [
        [
            "openssl",
            "dgst",
            "-sha256",
            "-sign",
            sign_file,
            "-passin",
            f"pass:{pw}",
            "-out",
            f"{filepath}.sha256",
            f"{filepath}",
        ],
        [
            "openssl",
            "base64",
            "-in",
            f"{filepath}.sha256",
            "-out",
            f"{filepath}.sha256.base64",
        ],
        ["rm", f"{filepath}.sha256"],
    ]
    for cmd in cmds:
        # print("Calling: \""+" ".join(cmd)+"\"")
        subprocess.check_call(cmd)


def sign_folder(sign_file, folder, pw):
    for root, dirs, files in os.walk(os.path.join(dir_path, folder)):
        for file in files:
            if not file.endswith(".base64"):
                sign_file("%s/%s%s" % (dir_path, folder, file), sign_file, pw)


if __name__ == "__main__":
    import argparse
    import datetime
    import getpass
    import requests
    import collections
    import pathlib
    import shutil
    import glob
    from pprint import pprint
    import platform as p
    import jinja2

    parser = argparse.ArgumentParser(description="Build helper.")
    parser.add_argument("--package", help="build the tar file", action="store_true")
    parser.add_argument(
        "--prepare_ci", help="Prepare CI file for dynamic runners", action="store_true"
    )
    parser.add_argument(
        "--gitlab_release", help="Creates a gitlab release", action="store_true"
    )
    parser.add_argument(
        "--gitlab_release_asset",
        help="Updates a gitlab release asset collection",
        action="store_true",
    )
    parser.add_argument(
        "--gitlab_latest_release",
        help="Updates the gitlab latest_release",
        action="store_true",
    )
    parser.add_argument(
        "--gitlab_pipeline_cleanup",
        help="Removes failed pipeline runs",
        action="store_true",
    )
    parser.add_argument("--pw", help="provide the password in the build process")
    parser.add_argument(
        "--sign_file", help="provide the key file used in the build process"
    )
    parser.add_argument(
        "--version", help="prints the current version", action="store_true"
    )
    parser.add_argument(
        "--versiontag", help="prints the current version tag", action="store_true"
    )
    parser.add_argument(
        "--update_strings",
        help="update the version string in all dependend files",
        action="store_true",
    )
    parser.add_argument("--asset_links", help="build the tar file", type=str, nargs="*")
    args = parser.parse_args()
    version = get_version()
    version_tag = get_version_tag()
    semver = get_semver()
    semver_str = get_semver_str()

    root_path = os.path.join("build", "package")

    if args.update_strings:
        with open(
            os.path.join(dir_path, "..", "..", "bindings", "python_cffi", "setup.py"),
            "r+",
        ) as f:
            txt = f.read()
            f.seek(0)
            f.write(re.sub(r"version.+,", f"version = '{semver_str}',", txt))
    elif args.version:
        print(version)
    elif args.versiontag:
        print(version_tag)
    elif args.package:
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
            # subprocess.check_call(("openssl genpkey -algorithm RSA -out "+args.sign_file+" -pkeyopt rsa_keygen_bits:4096 -des3 -pass pass:"+args.pw).split(" "))
            subprocess.check_call(
                [
                    "openssl",
                    "genrsa",
                    "-aes128",
                    "-passout",
                    f"pass:{args.pw}",
                    "-out",
                    f"{args.sign_file}",
                    "4096",
                ]
            )
            subprocess.check_call(
                [
                    "openssl",
                    "rsa",
                    "-in",
                    f"{args.sign_file}",
                    "-passin",
                    f"pass:{args.pw}",
                    "-pubout",
                    "-out",
                    f"{args.sign_file}_public.pem",
                ]
            )

        os.makedirs(os.path.join("build", "package", "include"), exist_ok=True)
        shutil.copytree(
            os.path.join("build", "neuropil", "bin"),
            os.path.join("build", "package", "bin"),
        )
        shutil.copytree(
            os.path.join("build", "neuropil", "lib"),
            os.path.join("build", "package", "lib"),
        )
        shutil.copytree(
            os.path.join("build", "doc", "html"),
            os.path.join("build", "package", "doc"),
        )
        shutil.copy(
            os.path.join("README.md"), os.path.join("build", "package", "README")
        )
        shutil.copy(
            os.path.join("LICENSE"), os.path.join("build", "package", "LICENSE")
        )
        for include_file in glob.glob(os.path.join("include", "neuropil*.h")):
            shutil.copy(
                include_file,
                os.path.join(
                    "build", "package", "include", os.path.basename(include_file)
                ),
            )
        neuropil_search = os.path.join("framework", "search", "neuropil_search.h")
        shutil.copy(
            neuropil_search,
            os.path.join(
                "build", "package", "include", os.path.basename(neuropil_search)
            ),
        )

        for (dirpath, dirnames, filenames) in os.walk(
            os.path.join("build", "package", "lib")
        ):
            for filename in filenames:
                sign_file(os.path.join(dirpath, filename), args.sign_file, args.pw)
        for (dirpath, dirnames, filenames) in os.walk(
            os.path.join("build", "package", "bin")
        ):
            for filename in filenames:
                sign_file(os.path.join(dirpath, filename), args.sign_file, args.pw)

    elif (
        args.gitlab_release
        or args.gitlab_release_asset
        or args.gitlab_latest_release
        or args.gitlab_pipeline_cleanup
    ):
        tag_ref = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode("utf-8")[
            :-1
        ]
        CI_JOB_TOKEN = os.environ.get("CI_JOB_TOKEN")
        GITLAB_API_TOKEN = os.environ.get("GITLAB_API_TOKEN")
        CI_PIPELINE_IID = os.environ.get("CI_PIPELINE_IID")
        CI_PROJECT_PATH = os.environ.get("CI_PROJECT_PATH", "pi-lar/neuropil")
        CI_PROJECT_ID = os.getenv("CI_PROJECT_ID", "14096230")
        CI_COMMIT_TAG = os.getenv("CI_COMMIT_TAG", "neuropil_test")
        CI_SERVER_URL = os.environ.get("CI_SERVER_URL", "https://gitlab.com")
        CI_API_V4_URL = os.environ.get("CI_API_V4_URL", f"{CI_SERVER_URL}/api/v4")

        if not CI_JOB_TOKEN and not GITLAB_API_TOKEN:
            GITLAB_API_TOKEN = getpass.getpass("Please insert GITLAB_API_TOKEN: ")

        if GITLAB_API_TOKEN:
            headers = {"PRIVATE-TOKEN": GITLAB_API_TOKEN}
        else:
            headers = {"JOB-TOKEN": CI_JOB_TOKEN}

        if args.gitlab_pipeline_cleanup:
            pipeline_infos = requests.get(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/pipelines", headers=headers
            ).json()
            for pipeline_info in pipeline_infos:
                if pipeline_info["status"] in [
                    "failed",
                    "canceled",
                ]:  # and pipeline_info['ref'] in ['main','master']:
                    del_res = requests.delete(
                        f"{CI_API_V4_URL}/projects/{pipeline_info['project_id']}/pipelines/{pipeline_info['id']}",
                        headers=headers,
                    )
                    if del_res.status_code >= 200 and del_res.status_code < 300:
                        print(
                            f"Deletion of Pipeline {pipeline_info['id']} Status: OK -> {del_res.status_code}/{del_res.text}"
                        )
                    else:
                        print(
                            f"Deletion of Pipeline {pipeline_info['id']} Status: NOK -> {del_res.status_code}/{del_res.text}"
                        )
                        break

        elif args.gitlab_release_asset:
            print(f"start gitlab release asset process")
            packages_infos = requests.get(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/packages?package_name=neuropil&&package_type=generic",
                headers=headers,
            ).json()

            for packages_info in packages_infos:
                if packages_info["version"] == semver_str:
                    package_id = packages_info["id"]

                    package_file_infos = requests.get(
                        f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/packages/{package_id}/package_files",
                        headers=headers,
                    ).json()

                    for package_file_info in package_file_infos:
                        pprint(package_file_info)
                        link = collections.OrderedDict(
                            {
                                "name": package_file_info["file_name"],
                                "url": f"{CI_SERVER_URL}/{CI_PROJECT_PATH}/-/package_files/{package_file_info['id']}/download",
                                "filepath": f"/{package_file_info['file_name']}",
                            }
                        )
                        pprint(link)

                        url = f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/releases/{version}/assets/links"
                        print(f">> {url}")
                        link_creation = requests.post(url, json=link, headers=headers)
                        pprint(link_creation.text)
                        link_creation.raise_for_status()

        if args.gitlab_release:
            print(f"start gitlab release process")
            project_config = requests.get(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}", headers=headers
            ).json()

            release_payload = collections.OrderedDict(
                {
                    "name": version_tag,
                    "tag_name": version,
                    "ref": tag_ref,
                    "description": "Neuropil Release {version}".format(**locals()),
                }
            )

            print(f"Create release")
            r = requests.post(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/releases",
                json=release_payload,
                headers=headers,
            )
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

        if args.gitlab_latest_release:
            print(f"gather release data")
            r = requests.get(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/releases?order_by=released_at&&sort=desc",
                headers=headers,
            )
            try:
                r.raise_for_status()
            except:
                print("could not gather release data")
                print(r.text)
            copy_release_config = r.json()[0]
            copy_release_config["name"] = "Latest"
            copy_release_config["ref"] = copy_release_config["tag_name"]
            copy_release_config["tag_name"] = "latest_release"

            print(f"unprotect latest_release tag")
            r = requests.delete(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/protected_tags/latest_release",
                headers=headers,
            )
            try:
                r.raise_for_status()
            except:
                print('could not unprotect "latest_release" tag')
                print(r.text)

            print(f"remove latest_release tag")
            r = requests.delete(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/repository/tags/latest_release",
                headers=headers,
            )
            try:
                r.raise_for_status()
            except:
                print('no "latest_release" git tag set')
                print(r.text)

            print(f"recreate latest_release tag")
            r = requests.post(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/releases",
                json=copy_release_config,
                headers=headers,
            )
            try:
                r.raise_for_status()
            except:
                print('could not create "latest_release" release')
                print(r.text)

            print(f"protect latest_release tag")
            r = requests.post(
                f"{CI_API_V4_URL}/projects/{CI_PROJECT_ID}/protected_tags?name=latest_release&create_access_level=40",
                headers=headers,
            )
            try:
                r.raise_for_status()
            except:
                print('could not protect "latest_release" tag')
                print(r.text)

    elif args.prepare_ci:

        DYNAMIC_BUILDERS = os.getenv("DYNAMIC_BUILDERS", "")
        tags = [
            (f"neuropil-{t.strip()}", t.strip()) for t in DYNAMIC_BUILDERS.splitlines()
        ]
        tags = list(set(tags))
        pprint(tags)

        templateLoader = jinja2.FileSystemLoader(searchpath="./")
        templateEnv = jinja2.Environment(loader=templateLoader)
        template = templateEnv.get_template(".gitlab-ci-build.yml.j2")
        template.globals["now"] = datetime.datetime.utcnow
        with open(".gitlab-ci-build.yml", "w+") as f:
            f.write(template.render(tags=tags, version=semver))

        template = templateEnv.get_template(".gitlab-ci-deployment.yml.j2")
        template.globals["now"] = datetime.datetime.utcnow

        with open(".gitlab-ci-deployment.yml", "w+") as f:
            f.write(template.render(tags=tags, version=semver))
    else:
        parser.print_help()
