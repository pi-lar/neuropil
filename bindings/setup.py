#!/usr/bin/env python

"""
setup.py file for neuropil
"""

from distutils.core import setup, Extension

neuropil_module = Extension('_neuropil',
                    define_macros = [('MAJOR_VERSION', '0'),
                                     ('MINOR_VERSION', '2')],
                    include_dirs = ['../../include'],
                    library_dirs = ['../../build/lib'],
                    libraries = ['neuropil'],
                    sources=['neuropil_wrap.c',],
                  )

setup (name = 'neuropil',
       version = '0.3',
       author      = "pi-lar GmbH",
       description = """neuropil python bindings""",
       ext_modules = [neuropil_module],
       py_modules = ["neuropil"],
       )
