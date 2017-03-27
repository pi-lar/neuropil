
import platform


print '####'
print '#### starting neuropil build'
print '####'
print 'building on : ' + str(platform.machine()) + '/' + str(platform.processor()) + '/' + str(platform.system())

# building on : x86_64/i386/Darwin
# TARGET=x86_64-apple-darwin-macho

# use clang to compile the source code
env = Environment(CC = 'clang')
env.VariantDir('build/obj', 'src', duplicate=0)

# read in additional compile flags
analyze = ARGUMENTS.get('analyze', 0)
build_tests = ARGUMENTS.get('test', 1)
build_doc = ARGUMENTS.get('doc', 0)
debug = ARGUMENTS.get('debug', 0)
release = ARGUMENTS.get('release', 0)


print '####'
print '#### adding compiler options and flags'
print '####'

# add libev flags to the compilation
env.Append(CCFLAGS = ['-DEV_STANDALONE'])
env.Append(CCFLAGS = ['-DHAVE_SELECT'])
env.Append(CCFLAGS = ['-DHAVE_KQUEUE'])
env.Append(CCFLAGS = ['-DHAVE_POLL'])

env.Append(CCFLAGS = ['-std=c99'])
env.Append(LDFLAGS = ['-std=c99'])

# add release compilation options
release_flags = ['-O3',]
if int(release):
    env.Append(CCFLAGS = release_flags)

# add debug compilation options
debug_flags = ['-g', '-Wall', '-Wextra', '-gdwarf-2']
if int(debug):
    env.Append(CCFLAGS = debug_flags)

# platform specific compiler options
if 'FreeBSD' in platform.system():
  env.Append(LIBS = ['util','m'] )
if 'Darwin' in platform.system():
  env.Append(CCFLAGS = ['-Wno-deprecated'] )
  env.Append(CCFLAGS = ['-mmacosx-version-min=10.11'] )
  env.Append(CCFLAGS = ['-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include'] )
  tpl_library_target = 'ios'
if 'Linux' in platform.system():
  env.Append(CCFLAGS = ['-D_GNU_SOURCE'])
  env.Append(LIBS = ['rt', 'pthread'] )
if 'CYGWIN' in platform.system():
  # -std=gnu++0x doesn't work, so work around...
  env.Append(CCFLAGS = ['-U__STRICT_ANSI__'] )
if 'Windows' in platform.system() or 'OpenBSD' in platform.system():
  env.Append(LIBS = ['rt'] )

# env.Append(CCFLAGS = '-march='+platform.processor())
# env.Append(CCFLAGS = '-arch='+platform.machine())
env.Append(CCFLAGS = '-target ' + platform.machine() + '-' + platform.system().lower() )
# env.Append(CCFLAGS = '-target ' + platform.machine())

print 'continuing with CCFLAGS set to: ' + env.Dump(key='CCFLAGS')
print 'continuing with LDFLAGS set to: ' + env.Dump(key='LDFLAGS')

print '####'
print '#### detecting 3rd party libraries'
print '####'

# add 3rd party library path info here
tpl_library_list = ['sodium']
env.Append(LIBS = tpl_library_list)

conf = Configure(env)

# Checks for libraries, header files, etc.
if not conf.CheckLibWithHeader('sodium', 'sodium.h', 'c'):
    print 'Did not find libsodium.a or sodium.lib ...'
    Exit(0)

if int(release) < 1 and int(build_tests) > 0 and conf.CheckLibWithHeader('criterion', 'criterion/criterion.h', 'c'):
    print 'Test cases included'
    tpl_library_list += ['criterion']
    env.Append(LIBS = tpl_library_list)
else:
    print 'Test cases not included'
    build_tests = 0

print '####'
print '#### adding neuropil specific build path informations'
print '####'

# include the neuropil build path library infos
np_library     = ['neuropil']
np_include_dir = ['./include']
np_library_dir = ['./build/lib']

env.Append(CPPPATH = np_include_dir)
env.Append(LIBPATH = np_library_dir)
env.Append(LIBS = np_library)

scan_build_exe = env.WhereIs('scan-build')
if int(analyze) and not scan_build_exe:
    print '---'
    print 'did not find clang checker executable in the path, skipping build of static code analysis'
    print 'please consider to install the additional clang static code analysis tool checker (version 278 as of this writing)'
    print '---'
    Exit(0)

sphinx_exe = env.WhereIs('sphinx-build')
if int(build_doc) and not sphinx_exe:
    print '---'
    print 'did not find sphinx executable in the path, skipping build of documentation'
    print '---'
    Exit(0)

env = conf.Finish()

# create an own builder to do clang static source code analyisis
# TODO: not yet working
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-config', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
# analyzer_flags = ['--analyze', '-Xanalyzer', '-analyzer-checker=alpha.security', '-analyzer-checker=alpha.core', '-analyzer-output=html']
def analyze_source_code(source, target, env, for_signature):
           return 'scan-build make -o %s' % ( target[0] )
analyze_builder = Builder(generator = analyze_source_code)
env.Append(BUILDERS = {'Analyzer' : analyze_builder})

# create sphinx builder, hopefully sphinx-build will be on the path
def build_sphinx_doc(source, target, env, for_signature):
    return 'sphinx-build %s %s' % (source[0], target[0])
sphinx_builder = Builder(generator = build_sphinx_doc, target_factory=Dir, source_factory=Dir)
env.Append(BUILDERS = {'Sphinx' : sphinx_builder})


if int(build_doc) and sphinx_exe:
    env.Sphinx('./build/html', './doc/source')

if int(analyze) and scan_build_exe:
    env.Analyzer('build/sca')

# if int(analyze):
#     env.Append(CCFLAGS='-I/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.11.sdk/usr/include')

# sources for neuropil
SOURCES =  ['build/obj/dtime.c','build/obj/neuropil.c','build/obj/np_aaatoken.c','build/obj/np_axon.c','build/obj/np_dendrit.c']
SOURCES += ['build/obj/np_glia.c','build/obj/np_http.c','build/obj/np_jobqueue.c','build/obj/np_key.c','build/obj/np_keycache.c']
SOURCES += ['build/obj/np_log.c','build/obj/np_memory.c','build/obj/np_message.c','build/obj/np_msgproperty.c','build/obj/np_network.c','build/obj/np_node.c']
SOURCES += ['build/obj/np_route.c','build/obj/np_tree.c','build/obj/np_util.c','build/obj/np_val.c']
# source code 3rd party libraries
SOURCES += ['build/obj/event/ev.c','build/obj/http/htparse.c','build/obj/json/parson.c','build/obj/msgpack/cmp.c']

# test cases for neuropil
TESTS = ['test/test_suites.c']

print '####'
print '#### building neuropil libraries/testsuite/example programs:'
print '####'
# build the neuropil library as static and shared library

np_stlib = env.Library('build/lib/neuropil', SOURCES, LIBS=tpl_library_list)
np_dylib = env.SharedLibrary('build/lib/neuropil', SOURCES, LIBS=tpl_library_list)

# build test executable
if int(build_tests):
    test_suite = env.Program('bin/neuropil_test_suite', TESTS)
    Depends(test_suite, np_dylib)
    AlwaysBuild(test_suite)

# build example programs
prg_np_ctrl = env.Program('bin/neuropil_controller', 'test/neuropil_controller.c')
Depends(prg_np_ctrl, np_dylib)

prg_np_node = env.Program('bin/neuropil_node', 'test/neuropil_node.c')
Depends(prg_np_node, np_dylib)

prg_np_recv = env.Program('bin/neuropil_receiver', 'test/neuropil_receiver.c')
Depends(prg_np_recv, np_dylib)

prg_np_send = env.Program('bin/neuropil_sender', 'test/neuropil_sender.c')
Depends(prg_np_send, np_dylib)

prg_np_rccb = env.Program('bin/neuropil_receiver_cb', 'test/neuropil_receiver_cb.c')
Depends(prg_np_rccb, np_dylib)

prg_np_rccb = env.Program('bin/neuropil_pingpong', 'test/neuropil_pingpong.c')
Depends(prg_np_rccb, np_dylib)

prg_np_hydra = env.Program('bin/neuropil_hydra', 'test/neuropil_hydra.c')
Depends(prg_np_hydra, np_dylib)

# clean up
Clean('.', 'build')
Clean('.', 'bin')
