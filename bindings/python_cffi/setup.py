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
from setuptools import setup

PATH = os.path.dirname(__file__)
if PATH:
    os.chdir(PATH)

setup (name = 'neuropil',
       version = '0.9.8',
       author      = "pi-lar GmbH",
       description = """neuropil python bindings""",
       setup_requires=["cffi>=1.0.0"],
       cffi_modules=["neuropil_build.py:ffibuilder"],
       install_requires=["cffi>=1.0.0"],
       py_modules = ["neuropil"],
       classifiers=[
           'Development Status :: 4 - Beta',
           'Environment :: Console',
           'Intended Audience :: Developers',
           'License :: OSI Approved :: Open Software Licence 3.0 (OSL-3)',
           'Operating System :: MacOS :: MacOS X',
           'Operating System :: Linux :: MacOS X',
           'Operating System :: BSD :: FreeBSD',
           'Operating System :: POSIX',
           'Programming Language :: Python :: 3.x',
           'Topic :: Utilities',
           ],
       )
