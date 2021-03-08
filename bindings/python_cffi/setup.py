#!/usr/bin/env python3
#
# neuropil is copyright 2016-2021 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
"""
setup.py file for neuropil library
"""
import os
from distutils.core import Extension
from setuptools import find_packages, setup

PATH = os.path.dirname(__file__)
if PATH:
    os.chdir(PATH)

setup ( name = 'neuropil',
        version = '0.9.8',
        author      = "pi-lar GmbH",
        description = """neuropil python bindings""",
        packages=find_packages(exclude=["_cffi_build", "_cffi_build.*"]),
        include_package_data=True,
        setup_requires=["wheel","cffi>=1.0.0"],
        install_requires=["cffi>=1.0.0"],
        #ext_package="neuropil",
        cffi_modules=["neuropil_build.py:ffibuilder"],
        py_modules = ["neuropil"],
        classifiers=[
           'Development Status :: 4 - Beta',
           'Environment :: Console',
           'Intended Audience :: Developers',
           'License :: OSI Approved',
           'Operating System :: MacOS :: MacOS X',
           'Operating System :: POSIX :: Linux',
           'Operating System :: POSIX :: BSD :: FreeBSD',
           'Operating System :: POSIX',
           'Programming Language :: Python :: 3.7',
           'Topic :: Utilities',
           ],
       )
