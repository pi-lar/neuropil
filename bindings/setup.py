#!/usr/bin/env python

"""
setup.py file for neuropil
"""

from distutils.core import setup, Extension

neuropil_module = Extension('_neuropil',
                    define_macros = [('MAJOR_VERSION', '0'),
                                     ('MINOR_VERSION', '4')],
                    libraries = ['neuropil', 'sodium'],
                    sources=['neuropil_python.c',],
                  )

setup (name = 'neuropil',
       version = '0.4.1',
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
