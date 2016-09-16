
import platform
print '####'
print '#### starting neuropil build'
print '####'
print 'building on : ' + str(platform.machine()) + '/' + str(platform.processor()) + '/' + str(platform.system())

# add 3rd party library path infor here
tpl_library_list = ['sodium', 'criterion']
tpl_include_path = ['/usr/local/include', '#/lib/criterion-v2.2.1/include']
tpl_library_path = ['/usr/local/lib', '#/lib/criterion-v2.2.1/lib']

# include the neuropil build path library infos
np_library     = ['neuropil']
np_include_dir = ['#/include']
np_library_dir = ['#/lib']

# use clang to compile the source code
env = Environment(CC = 'clang')

env.Append(CPPPATH = np_include_dir)
env.Append(CPPPATH = tpl_include_path)

env.Append(LIBPATH = np_library_dir)
env.Append(LIBPATH = tpl_library_path)

env.Append(LIBS = np_library)
env.Append(LIBS = tpl_library_list)

print '####'
print '#### detecting 3rd party libraries'
print '####'
conf = Configure(env)
# Checks for libraries, header files, etc.
if not conf.CheckLibWithHeader('sodium', 'sodium.h', 'c'):
    print 'Did not find libsodium.a or sodium.lib ...'

if not conf.CheckLibWithHeader('criterion', 'criterion.h', 'c'):
    print 'Did not find libcriterion.a or criterion.lib !'
    print '... Test cases cannot be compiled'

env = conf.Finish()

# add libev flags to the compilation
env.Append(CCFLAGS = ['-DEV_STANDALONE']) 
env.Append(CCFLAGS = ['-DHAVE_SELECT']) 
env.Append(CCFLAGS = ['-DHAVE_KQUEUE']) 
env.Append(CCFLAGS = ['-DHAVE_POLL']) 

env_dbg = env.Clone()
# add debug compilation option
env_dbg.Prepend(CCFLAGS = ['-g'])
env_dbg.Prepend(CCFLAGS = ['-Wall'])
env_dbg.Prepend(CCFLAGS = ['-Wextra'])
env_dbg.Prepend(CCFLAGS = ['-gdwarf-2'])
env_dbg.Prepend(CCFLAGS = ['-std=c99'])

# sources for neuropil
SOURCES =  ['src/dtime.c','src/neuropil.c','src/np_aaatoken.c','src/np_axon.c','src/np_dendrit.c']
SOURCES += ['src/np_glia.c','src/np_http.c','src/np_jobqueue.c','src/np_key.c','src/np_keycache.c']
SOURCES += ['src/np_log.c','src/np_memory.c','src/np_message.c','src/np_msgproperty.c','src/np_network.c','src/np_node.c']
SOURCES += ['src/np_route.c','src/np_tree.c','src/np_util.c','src/np_val.c']
# source code 3rd party libraries
SOURCES += ['src/event/ev.c','src/http/htparse.c','src/json/parson.c','src/msgpack/cmp.c']

# test cases for neuropil
TESTS = ['test/test_suites.c']

print '####'
print '#### building neuropil libraries/testsuite/example programs:'
print '####'
# build the neuropil library as static and shared library 
np_stlib = env_dbg.Library('lib/neuropil', SOURCES, LIBS=tpl_library_list)
np_dylib = env_dbg.SharedLibrary('lib/neuropil', SOURCES, LIBS=tpl_library_list)

# build test executable
test_suite = env_dbg.Program('bin/neuropil_test_suite', TESTS, LIBS=[tpl_library_list, np_library]) 
Depends(test_suite, np_dylib)

# build example programs
prg_np_ctrl = env_dbg.Program('bin/neuropil_controller', 'test/neuropil_controller.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_ctrl, np_dylib)

prg_np_node = env_dbg.Program('bin/neuropil_node', 'test/neuropil_node.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_node, np_dylib)

prg_np_recv = env_dbg.Program('bin/neuropil_receiver', 'test/neuropil_receiver.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_recv, np_dylib)

prg_np_send = env_dbg.Program('bin/neuropil_sender', 'test/neuropil_sender.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_send, np_dylib)

prg_np_rccb = env_dbg.Program('bin/neuropil_receiver_cb', 'test/neuropil_receiver_cb.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_rccb, np_dylib)

prg_np_hydr = env_dbg.Program('bin/neuropil_hydra', 'test/neuropil_hydra.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_hydr, np_dylib)

prg_np_rema = env_dbg.Program('bin/neuropil_realmmaster', 'test/neuropil_realmmaster.c', LIBS=[tpl_library_list, np_library]) 
Depends(prg_np_rema, np_dylib)






