#!/usr/bin/env python3
#
# neuropil is copyright 2016-2017 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#
"""
setup.py file for neuropil library
"""

from distutils.core import Extension
from setuptools import setup 

setup (name = 'neuropil',
       version = '0.7.1',
       author      = "pi-lar GmbH",
       description = """initial neuropil python bindings""",
       setup_requires=["cffi>=1.0.0"],
       cffi_modules=["neuropil_build.py:ffibuilder"],
       install_requires=["cffi>=1.0.0"],
       py_modules = ["neuropil_obj"],
       classifiers=[
           'Development Status :: 3 - Alpha',
           'Environment :: Console',
           'Intended Audience :: Developers',
           'License :: OSI Approved :: Open Software Licence 3.0 (OSL-3)',
           'Operating System :: MacOS :: MacOS X',
           'Operating System :: Linux :: MacOS X',
           'Operating System :: BSD :: FreeBSD',
           'Operating System :: POSIX',
           'Programming Language :: Python :: 2.7',
           'Programming Language :: Python :: 3.x',
           'Topic :: Utilities',
           ],
       )
