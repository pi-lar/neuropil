# WIP DRAFT
# TODO:
# - add criterion testing
# - add cross platform capabilities
# - add ncurses
# - add convenient find modules for criterion, sodium and ncurses
# - add compilation for example projects
cmake_minimum_required(VERSION 3.0.0)
project(neuropil VERSION 0.1.0)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DEV_STANDALONE -DHAVE_SELECT -DHAVE_KQUEUE -DHAVE_POLL -DHAVE_EPOLL_CTL -DEV_COMPAT3=0 -DEV_USE_FLOOR=1 -DEV_USE_4HEAP=1")

include(CTest)
enable_testing()

add_library(neuropil SHARED
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
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_bloom.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_log.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_memory.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_message.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_network.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_node.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_pheromones.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_route.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_tree.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_util.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_treeval.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_threads.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_scache.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/np_event.c
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
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/util/np_statemachine.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/framework/prometheus/prometheus.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/framework/sysinfo/np_sysinfo.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/framework/http/np_http.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/event/ev.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/json/parson.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/msgpack/cmp.c
                    ${CMAKE_CURRENT_SOURCE_DIR}/src/gpio/bcm2835.c)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

target_link_libraries(neuropil sodium)

target_include_directories(neuropil PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_include_directories(neuropil PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/framework")
