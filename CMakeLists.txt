# SPDX-FileCopyrightText: 2016-2024 by pi-lar GmbH
# SPDX-License-Identifier: OSL-3.0
# WIP DRAFT
# TODO:
# - add criterion testing
# - add cross platform capabilities
# - add ncurses
# - add convenient find modules for criterion, sodium and ncurses
# - add compilation for example projects
cmake_minimum_required(VERSION 3.0.0)
project(neuropil VERSION 0.1.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_SYS_EVENT_H -DHAVE_POLL -DHAVE_LINUX_AIO_ABI_H -DEV_USE_FLOOR=1 -DEV_USE_4HEAP=1 -D_GNU_SOURCE")

include(CTest)
enable_testing()

include_directories("/opt/homebrew/opt/libsodium/include")
link_directories("/opt/homebrew/opt/libsodium/lib")

add_library(libneuropil SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/src/neuropil.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/neuropil_data.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/neuropil_attributes.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/dtime.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_time.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_aaatoken.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_axon.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_dendrit.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_glia.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_jobqueue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_dhkey.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_key.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_keycache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_bootstrap.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_log.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_memory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_message.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_network.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_pheromones.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_route.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_util.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_threads.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_evqueue.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_evloop.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_messagepart.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_statistics.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_responsecontainer.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_legacy.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_serialization.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_shutdown.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_token_factory.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_crypto.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/np_comp_identity.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/np_comp_msgproperty.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/np_comp_intent.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/np_comp_node.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/core/np_comp_alias.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_bloom.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_minhash.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_tree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_treeval.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_scache.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_skiplist.c
    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_statemachine.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/prometheus/prometheus.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/sysinfo/np_sysinfo.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/http/np_http.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/http/urldecode.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/files/file.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/search/np_bktree.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/search/np_index.c
    ${CMAKE_CURRENT_SOURCE_DIR}/framework/search/np_search.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_tools/event/ev.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_tools/parson/parson.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_tools/msgpack/cmp.c
    ${CMAKE_CURRENT_SOURCE_DIR}/ext_tools/gpio/bcm2835.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

add_executable(neuropil_node examples/neuropil_node.c)
add_executable(neuropil_cloud examples/neuropil_cloud.c)
add_executable(neuropil_hydra examples/neuropil_hydra.c)
add_executable(neuropil_controller examples/neuropil_controller.c)
add_executable(neuropil_sender examples/neuropil_sender.c)
add_executable(neuropil_receiver examples/neuropil_receiver.c)
add_executable(neuropil_search_node examples/neuropil_search_node.c)
add_executable(neuropil_search_nlnet examples/neuropil_search_nlnet.c)
add_executable(neuropil_search_nlnet_2 examples/neuropil_search_nlnet_2.c)

target_link_libraries(neuropil sodium pthread m)

target_link_libraries(neuropil_node neuropil sodium ncurses)
target_link_libraries(neuropil_cloud neuropil sodium ncurses)
target_link_libraries(neuropil_hydra neuropil sodium ncurses)
target_link_libraries(neuropil_search_nlnet neuropil sodium ncurses)
target_link_libraries(neuropil_search_nlnet_2 neuropil sodium ncurses yajl)

target_link_libraries(neuropil_controller neuropil sodium)
target_link_libraries(neuropil_sender neuropil sodium)
target_link_libraries(neuropil_receiver neuropil sodium)
target_link_libraries(neuropil_search_node neuropil sodium)

target_include_directories(neuropil PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(neuropil PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/framework")
target_include_directories(neuropil PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/ext_tools")
