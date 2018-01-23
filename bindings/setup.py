#!/usr/bin/env python
#
# neuropil is copyright 2016-2017 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#

"""
setup.py file for neuropil library
"""

from distutils.core import setup, Extension

neuropil_module = Extension('_neuropil',
                            sources = ['neuropil.i'],
                            swig_opts=['-modern', '-I../include'],
                            define_macros = [('MAJOR_VERSION', '0'), ('MINOR_VERSION', '5'), ('x64', None)],
                            extra_compile_args=['-O3', '-Wno-unsupported-visibility', '-std=c99', '-Dx64'],
                            libraries = ['neuropil', 'sodium'],
                            include_dirs=['../include'],
                            library_dirs=['../build/lib'],
                  )

setup (name = 'neuropil',
       version = '0.5.0',
       author      = "pi-lar GmbH",
       description = """experimental neuropil python bindings""",
       ext_modules = [neuropil_module],
       py_modules = ["neuropil"],
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
