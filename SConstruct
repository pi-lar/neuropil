#! /usr/bin/env python3

#
# neuropil is copyright 2016-2021 by pi-lar GmbH
# Licensed under the Open Software License (OSL 3.0), please see LICENSE file for details
#

import subprocess
import platform
import glob
import io
import os
import SCons.Util
import time
from pprint import pprint
from scripts.util.build_helper import get_semver

def exec_call(target):
    ret = subprocess.check_call(target)
    if ret != 0:
        #print("Error: cannot execute {target}".format(**locals()))
        pass
    return ret

try:
    import multiprocessing
    SetOption('num_jobs', multiprocessing.cpu_count())
except:
    pass

AddOption('--list',          help='List target aliase',          default=False,  action="store_true",    dest="list_aliase")
AddOption('--strict',        help='Enable strict build',         default=False,  action="store_true")
AddOption('--noverbose',     help='Disable verbose output',      default=True,   action="store_false")

AddOption('--DEBUG',         help='Build in debug optimisation level',   default=False, action="store_true",)
AddOption('--RELEASE',       help='Build in release optimisation level', default=False, action="store_true",)
AddOption('--CODE_COVERAGE', help='Build with code coverage flags',      default=False, action="store_true",)
AddOption('--INSTALL',       help='install files',                       default=False, action="store_true",)

import inspect
project_root_path = os.path.join(os.path.dirname(os.path.realpath(inspect.getfile(lambda: None))))

version = get_semver()
buildDir = os.path.join(project_root_path, 'build', 'neuropil')
default_env = Environment(
    LIBPATH=[
        os.path.join(os.sep ,"usr","lib"),
        os.path.join(os.sep , "usr","local","lib")
    ],
    CPPPATH = [
        os.path.join(os.sep ,"usr","include"),
        os.path.join(os.sep , "usr","local","include")
    ],
)
all_aliases_targets=[]

if 'IN_NIX_SHELL' in os.environ or 'NIX_CC' in os.environ:
    default_env['ENV'] = os.environ
if 'TERM' in os.environ:
    default_env['ENV']['TERM'] = os.environ['TERM']

default_env["CC"] = os.getenv("CC",'clang')
default_env["CXX"] = os.getenv("CXX")
default_env["ENV"].update(x for x in os.environ.items() if x[0].startswith("CCC_"))
default_env["ENV"].update(x for x in os.environ.items() if x[0].endswith("FLAGS"))
default_env.Append(ENV = {
    'PATH' : os.environ['PATH'],
    'CPPPATH' : os.getenv("CPPPATH",''),
    'LD_LIBRARY_PATH': os.getenv("LD_LIBRARY_PATH","") #f"{os.getenv('LD_LIBRARY_PATH','')}:{os.path.join(project_root_path,'ext_tools','libsodium','src','libsodium','.libs')}:{os.path.join(project_root_path,'ext_tools','Criterion','build','src')}"
})

variantDir = os.path.join(buildDir,'obj')

default_env.VariantDir(os.path.join(variantDir, 'src'),         os.path.join(project_root_path,'src'), duplicate=0)
default_env.VariantDir(os.path.join(variantDir, 'test'),        os.path.join(project_root_path,'test'), duplicate=0)
default_env.VariantDir(os.path.join(variantDir, 'examples'),    os.path.join(project_root_path,'examples'), duplicate=0)
default_env.VariantDir(os.path.join(variantDir, 'framework'),   os.path.join(project_root_path,'framework'), duplicate=0)
default_env.VariantDir(os.path.join(variantDir, 'ext_tools'),   os.path.join(project_root_path,'ext_tools'), duplicate=0)

#default_env.Decider('MD5')

# read in additional compile flags

if GetOption("CODE_COVERAGE"):
    default_env.Append(CCFLAGS = ['-fprofile-instr-generate','-fcoverage-mapping'])

if GetOption('strict'):
    default_env.Append(CCFLAGS = ['-DSTRICT'])

if "64" in str(platform.machine()):
    default_env.Append(CCFLAGS = ['-Dx64'])
default_env.Append(CCFLAGS = ['-std=c99'])
default_env.Append(LDFLAGS = ['-std=c99'])

# add release compilation options
if GetOption("RELEASE"):
    default_env.Append(CCFLAGS = ['-O3','-DRELEASE'])
elif GetOption("DEBUG"):
    default_env.Append(CCFLAGS = ['-g', '-Wall', '-Wextra', '-gdwarf-2',"-O0",'-DDEBUG'])
else:
    default_env.Append(CCFLAGS = ['-g', '-Wall', '-Wextra', '-gdwarf-2',"-O1"])

# platform specific compiler options

if 'FreeBSD' in platform.system():
    default_env.Append(LIBS = ['util', 'm'] )

if 'Darwin' in platform.system():
    # default_env.Append(CCFLAGS = ['-Wformat-security'])
    # default_env.Append(CCFLAGS = ['-fstack-protector-all'])
    # default_env.Append(CCFLAGS = ['-Wstrict-overflow'])
    default_env.Append(CCFLAGS = ['-fno-omit-frame-pointer'])
    default_env.Append(CCFLAGS = ['-Wno-nullability-completeness'])
    default_env.Append(CCFLAGS = ['-Wno-missing-field-initializers'])
    default_env.Append(CCFLAGS = ['-Wno-missing-braces'])
    default_env.Append(CCFLAGS = ['-Wno-unsupported-visibility'])
    default_env.Append(CCFLAGS = ['-mmacosx-version-min=10.11'])
    default_env.Append(CPPPATH = ['/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/usr/include'] )

if 'Linux' in platform.system():
    default_env.Append(LIBS = ['m'])
    default_env.Append(CCFLAGS = ['-D_GNU_SOURCE'])
    default_env.Append(LIBS = ['rt', 'pthread'] )

    if('arm' in platform.processor()):
        default_env.Append(LIBPATH = ['/usr/lib', '/usr/local/lib','/usr/lib/arm-linux-gnueabihf'] )
        default_env.Append(CPPPATH = ['/usr/include','/usr/local/include','/usr/include/arm-linux-gnueabihf'] )

if 'CYGWIN' in platform.system():
    # -std=gnu++0x doesn't work, so work around...
    default_env.Append(CCFLAGS = ['-U__STRICT_ANSI__'] )

if 'Windows' in platform.system() or 'OpenBSD' in platform.system():
        default_env.Append(LIBS = ['rt'] )
        default_env.Append(CCFLAGS = ['-x c'])

# env.Append(CCFLAGS = '-march='+platform.processor())
# env.Append(CCFLAGS = '-arch='+platform.machine())
# env.Append(CCFLAGS = '-target ' + platform.machine() + '-' + platform.system().lower() )
# env.Append(CCFLAGS = '-target ' + platform.machine())

if not GetOption('noverbose'):
    default_env.Append(LINKFLAGS = ['-v']) # shows linker invokation

default_env.Append(CPPPATH = [
        os.path.join(project_root_path,'include'),
        os.path.join(project_root_path,'framework'),
        os.path.join(project_root_path,"ext_tools"),
        os.path.join(project_root_path,'build','ext_tools','libsodium','include')
])
default_env.Append(LIBPATH = [os.path.join(project_root_path, 'build','ext_tools','libsodium','lib')])
default_env.Append(LIBPATH = [os.path.join(project_root_path, buildDir,'lib')])


default_env_conf = Configure(default_env)
libsodium_build = None
if not default_env_conf.CheckLib('sodium'):
    libsodium_build = default_env.Command (
        os.path.join(project_root_path,'build','ext_tools','libsodium','include','sodium.h'),
        os.path.join(project_root_path,'ext_tools','libsodium'),
        f'mkdir -p \'{os.path.join(project_root_path,"build","ext_tools","libsodium")}\' && cd \'{os.path.join(project_root_path,"ext_tools","libsodium")}\' && bash configure --prefix=\'{os.path.join(project_root_path,"build","ext_tools","libsodium")}\' && make && make install'
    )
    libsodium_alias = default_env.Alias(f'libsodium', [libsodium_build])


default_env = default_env_conf.Finish()



#print ("continuing with CCFLAGS set to: {dump}".format(dump=default_env.Dump(key='CCFLAGS')) )
#print ("continuing with LDFLAGS set to: {dump}".format(dump=default_env.Dump(key='LDFLAGS')) )

#print ('####')
#print ('#### detecting 3rd party libraries')
#print ('####')
neuropil_env = default_env.Clone()

# add 3rd party library path info here
neuropil_env.Append(LIBS = ['sodium'])

neuropil_conf = Configure(neuropil_env)


# add libev flags to the compilation
neuropil_env.Append(CCFLAGS = ['-DEV_STANDALONE'])
# env.Append(CCFLAGS = ['-DEV_PERIODIC_ENABLE'])
#neuropil_env.Append(CCFLAGS = ['-DEV_USE_SELECT=1'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_SELECT'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_KQUEUE'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_POLL'])
neuropil_env.Append(CCFLAGS = ['-DHAVE_EPOLL_CTL'])
neuropil_env.Append(CCFLAGS = ['-DEV_COMPAT3=0'])
neuropil_env.Append(CCFLAGS = ['-DEV_USE_FLOOR=1'])
neuropil_env.Append(CCFLAGS = ['-DEV_USE_4HEAP=1'])
if neuropil_conf.CheckFunc('nanosleep'):
    neuropil_env.Append(CCFLAGS = ['-DEV_USE_NANOSLEEP=1'])
# neuropil_env.Append(CCFLAGS = ['-DEV_USE_REALTIME=0'])
# neuropil_env.Append(CCFLAGS = ['-DEV_NO_THREADS'])

# sources for neuropil
SOURCES  = ['neuropil.c',              'neuropil_data.c',            'neuropil_attributes.c']
SOURCES += ['dtime.c',                 'np_time.c',                  'np_aaatoken.c',          'np_axon.c',           'np_dendrit.c'                                 ]
SOURCES += ['np_glia.c',               'np_jobqueue.c',              'np_dhkey.c',             'np_key.c',            'np_keycache.c',       'np_bootstrap.c'        ]
SOURCES += ['np_threads.c',            'np_log.c',                   'np_memory.c',            'np_message.c',        'np_network.c',        'np_node.c'             ]
SOURCES += ['np_util.c',               'util/np_scache.c',           'util/np_statemachine.c', 'util/np_tree.c',      'util/np_treeval.c',   'util/np_bloom.c'       ]
SOURCES += ['core/np_comp_identity.c', 'core/np_comp_msgproperty.c', 'core/np_comp_intent.c',  'core/np_comp_node.c', 'core/np_comp_alias.c', 'util/np_minhash.c'    ]
SOURCES += ['np_pheromones.c',         'np_route.c',                 'np_event.c',             'np_messagepart.c',    'np_statistics.c',     'np_responsecontainer.c']
SOURCES += ['np_legacy.c',             'np_serialization.c',         'np_shutdown.c',          'np_token_factory.c',  'np_crypto.c' ]

SOURCES += ['../framework/prometheus/prometheus.c', '../framework/sysinfo/np_sysinfo.c', '../framework/http/np_http.c']

SOURCES = [os.path.join(variantDir, "src" , s) for s in SOURCES]

# source code 3rd party libraries
neuropil_conf = Configure(neuropil_conf.Finish())
if not neuropil_conf.CheckLib("parson"):
    DEPENDENCIES  = [os.path.join(variantDir,"ext_tools","parson","parson.c")]

if not neuropil_conf.CheckLib("cmp"):
    DEPENDENCIES += [os.path.join(variantDir,"ext_tools","msgpack","cmp.c")]

DEPENDENCIES += [os.path.join(variantDir,"ext_tools","event","ev.c")]

SOURCES += DEPENDENCIES

neuropil_env = neuropil_conf.Finish()

# build the neuropil library as static and shared library
np_stlib = neuropil_env.Library(os.path.join(buildDir, 'lib','neuropil'), SOURCES)
np_stlib_alias = neuropil_env.Alias(f'static_neuropil', [np_stlib])
Default(np_stlib_alias)
all_aliases_targets+=[np_stlib_alias]

np_dylib = neuropil_env.SharedLibrary(os.path.join(buildDir,'lib','neuropil'), SOURCES, SHLIBVERSION=f"{version['major']}.{version['minor']}.{version['patch']}")
np_dylib_alias = neuropil_env.Alias(f'shared_neuropil', [np_dylib])
Default(np_dylib_alias)
all_aliases_targets+=[np_dylib_alias]

if GetOption("INSTALL"):
    install_env = Environment()
    Default(install_env.InstallVersionedLib(os.path.join(os.sep,"usr","local","lib"), np_dylib))
    [ Default(install_env.Install(os.path.join(os.sep,"usr","local","include"), inc)) for inc in glob.glob(os.path.join("..","include","neuropil*.h"))]

bindings_lua_env = default_env.Clone()
bindings_lua_build= bindings_lua_env.Command ("build.binding_lua", None, lambda target,source,env: exec_call([os.path.join(project_root_path,'bindings','luajit','build.sh')]))
Depends(bindings_lua_build, np_dylib)
lua_alias = bindings_lua_env.Alias(f'lua', [bindings_lua_build])

bindings_py_env = default_env.Clone()

h_in_file_path = os.path.join(project_root_path,'bindings','python_cffi','include', "neuropil_comb_in.h")
tmp_h_file_path = os.path.join(project_root_path,'bindings','python_cffi','include', "neuropil_comb_in.h.tmp")
neuropil_comb_path = os.path.join(project_root_path,'bindings','python_cffi','include', "neuropil_comb.h")
#import pycparser_fake_libc
cmd =[
    "-E", h_in_file_path,
    "-o", tmp_h_file_path,
    "-std=c99",
    #"-m32",
    "-D__extension__=",
    "-D_NP_DO_NOT_USE_DEFAULT_H_FILES",
    #f"-I{pycparser_fake_libc.directory}",
    f"-I{os.path.join(project_root_path,'include')}",
    "-D__CLANG_MAX_ALIGN_T_DEFINED",
    "-DNP_PACKED(x)=","-DNP_API_EXPORT=", "-DNP_ENUM=", "-DNP_CONST_ENUM="
]
if platform.system() == 'Darwin':
    cmd += ["-D__signed=", "-D__builtin_va_list=void*"]

cmd = "' '".join(cmd)
bindings_python_h= bindings_py_env.Command (
    tmp_h_file_path,
    h_in_file_path,
    f"clang '{cmd}'"
)
Depends(bindings_python_h, np_dylib)

bindings_python_cleanup= bindings_py_env.Command (
    neuropil_comb_path,
    tmp_h_file_path,
    f"egrep -v '^#.*' {tmp_h_file_path} | egrep -v '^\s*$' > {neuropil_comb_path}"
)

python_build_path = os.path.join(project_root_path,'build','bindings','python')
python_dist_path  = os.path.join(project_root_path,'build','bindings','python','dist')
setup_py_path = os.path.join(project_root_path,'bindings','python_cffi','setup.py')

bindings_python_build= bindings_py_env.Command (
    "build.binding_python.setup",
    [setup_py_path, neuropil_comb_path],
    f"python3 {setup_py_path} build --build-base={python_build_path}"
)

bindings_python_sdist= bindings_py_env.Command (
    python_dist_path,
    [setup_py_path],
    f"python3 {setup_py_path} sdist --formats=gztar,zip --dist-dir={python_dist_path}"
)
Depends(bindings_python_sdist, bindings_python_build)

#if 'Darwin' in platform.system():

# Trying to use name tool to link into build library in _neuropil.abi3.so
#sudo install_name_tool -change build/neuropil/lib/libneuropil.dylib ${base_dir}/build/neuropil/lib/libneuropil.dylib ./_neuropil.abi3.so
# py_install = bindings_py_env.Command(
#     "install.binding_python",
#     None,
#     'sudo install_name_tool -change build/neuropil/lib/libneuropil.dylib ${base_dir}/build/neuropil/lib/libneuropil.dylib ./_neuropil.abi3.so'
# )
python_alias = bindings_py_env.Alias(f'python', [bindings_python_sdist])
bindings_alias = neuropil_env.Alias(f'bindings', [bindings_python_sdist, bindings_lua_build])
all_aliases_targets+=[bindings_alias]

test_env = default_env.Clone()
test_env.Append(LIBPATH = [glob.glob(os.path.join(project_root_path,'build','ext_tools','Criterion','usr','local','lib','*'))] )
test_env.Append(CPPPATH = [os.path.join(project_root_path,'build','ext_tools','Criterion','usr','local','include')])

test_env_conf = Configure(test_env)
criterion_build = None
if not test_env_conf.CheckLib('criterion'):
    criterion_build = test_env.Command (
        [
            "criterion",
            os.path.join('criterion','criterion.h'),
            os.path.join(project_root_path,'build','ext_tools','Criterion','build','src')
        ],
        os.path.join(project_root_path,'ext_tools','Criterion'),
              f'cd \'{os.path.join(project_root_path,"ext_tools","Criterion")}\' && '+
        f'mkdir -p \'{os.path.join(project_root_path,"build","ext_tools","Criterion","build")}\' && '+
           f'meson \'{os.path.join(project_root_path,"build","ext_tools","Criterion","build")}\' && '+
        f'ninja -C \'{os.path.join(project_root_path,"build","ext_tools","Criterion","build")}\' && '+
              f'cd \'{os.path.join(project_root_path,"build","ext_tools","Criterion","build")}\' && '+
          f'export DESTDIR=\'{os.path.join(project_root_path,"build","ext_tools","Criterion")}\' && '+
          f'export MESON_INSTALL_PREFIX=\'a\' && '+
                f'ninja install'
    )

test_env = test_env_conf.Finish()
criterion_alias = test_env.Alias(f'criterion', [criterion_build])

# build test executable
# include the neuropil build path library infos

if GetOption("CODE_COVERAGE"):
    default_env.Append(CCFLAGS = ['-fprofile-instr-generate','-fcoverage-mapping'])

test_env.Append(LIBS = [ 'sodium', 'neuropil'])
test_suite = test_env.Program(
                    os.path.join(buildDir,'bin','neuropil_test_suite'),
                    os.path.join(variantDir,'test','test_suite.c'),
)
Depends(test_suite, np_dylib)
if criterion_build:
    Depends(test_suite, criterion_build)
test_unit = test_env.Program(os.path.join(buildDir,'bin','neuropil_test_units'),     os.path.join(variantDir,'test','test_units.c'))
Depends(test_unit, np_dylib)
if criterion_build:
    Depends(test_unit, criterion_build)
tests_alias = test_env.Alias('tests', [test_suite, test_unit])
all_aliases_targets+=[tests_alias]


# build example programs
programs = [
#    (InDefaultBuild, PROGRAM_NAME (w/o neuropil_ prefix), DEPENDENCIES)
    (True,  'controller',     ['neuropil']),
    (True,  'receiver',       ['neuropil']),
    (True,  'sender',         ['neuropil']),
    (True,  'node',           ['neuropil','ncurses','sodium']),
    (True,  'receiver_lb',    ['neuropil','ncurses','sodium']),
    (True,  'cloud',          ['neuropil','ncurses','sodium']),
    (True,  'hydra',          ['neuropil','ncurses','sodium']),
    (True,  'receiver_cb',    ['neuropil','ncurses','sodium']),
    (False, 'pingpong',       ['neuropil','ncurses','sodium']),
    (False, 'echo_server',    ['neuropil','ncurses','sodium']),
    (False, 'echo_client',    ['neuropil','ncurses','sodium']),
    (False, 'raspberry',      ['neuropil','ncurses','sodium']),
    (False, 'demo_service',   ['neuropil','ncurses','sodium']),
    (False, 'raffle',         ['neuropil','ncurses','sodium','sqlite3']),
]

for default, program, libs in programs:
    program_env = default_env.Clone()
    program_env.Append(LIBS = libs)

    target = os.path.join(buildDir, 'bin',f'neuropil_{program}')
    prg_np = program_env.Program(target, os.path.join(variantDir,'examples',f'neuropil_{program}.c'))
    Depends(prg_np, np_dylib)
    program_alias = program_env.Alias(f'neuropil_{program}', [prg_np])
    all_aliases_targets+=[program_alias]
    if default:
        Default(program_alias)

dependency_obj = [neuropil_env.Object(s) for s in DEPENDENCIES]
if criterion_build and not 'BSD' in platform.system():
    dependency_obj += [criterion_build]
if libsodium_build:
    dependency_obj += [libsodium_build]
dependencies_alias = neuropil_env.Alias(f'dependencies', dependency_obj)
all_aliases_targets+=[dependencies_alias]

all_alias = default_env.Alias('all', all_aliases_targets)

if GetOption('list_aliase'):
    print( 'Available Build Aliases:')
    aliases = SCons.Node.Alias.default_ans.keys()
    for x in aliases:
        print(f"- {x}")
    exit(0)