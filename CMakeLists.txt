cmake_minimum_required(VERSION 3.10)

project(sipdump VERSION 1.1.0)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

set(CORE_SRC_DIR src/core/src)
set(CORE_INC_DIR src/core/include)
set(CLIENT_SRC_DIR src/client/src)
set(CLIENT_INC_DIR src/client/include)
set(AICSA_SRC_DIR src/aicsa/src)
set(AICSA_INC_DIR src/aicsa/include)
set(CTI_SRC_DIR src/cti/src)
set(CTI_INC_DIR src/cti/include)
set(TEST_SRC_DIR src/tests/src)
set(TEST_INC_DIR src/tests/include)

set(INSTALL_DIR /usr/local/sipdump)

option(BUILD_TESTS "Build tests" OFF)
option(BUILD_SIP "Build standard sip" ON)
option(BUILD_MRCP "Build standard mrcp" ON)

# core sip src list
set(CORE_SRCS
    ${CORE_SRC_DIR}/sipdump_util.c
    ${CORE_SRC_DIR}/sipdump_log.c
    ${CORE_SRC_DIR}/sipdump_opt.c
    ${CORE_SRC_DIR}/sipdump_network.c
    ${CORE_SRC_DIR}/sipdump_fragment.c
    ${CORE_SRC_DIR}/sipdump_pcap.c
    ${CORE_SRC_DIR}/sipdump_session.c
    ${CORE_SRC_DIR}/sipdump_sdp.c
    ${CORE_SRC_DIR}/sipdump_sip_hdr.c
    ${CORE_SRC_DIR}/sipdump_sip.c
    ${CORE_SRC_DIR}/sipdump_mrcp.c
    ${CORE_SRC_DIR}/sipdump_text.c
    ${CORE_SRC_DIR}/sipdump_plugins.c
    ${CORE_SRC_DIR}/sipdump_hook.c
)

# client list
set(CLIENT_SRCS
    ${CLIENT_SRC_DIR}/sipdump_client.c
)

# test list
set(TEST_SRCS
    ${TEST_SRC_DIR}/test_sipdump_sip_hdr.c
    ${TEST_SRC_DIR}/test_sipdump_util.c
    ${TEST_SRC_DIR}/test.c
)

find_package(PkgConfig)

# add 3th-party lib apr
pkg_search_module(APR REQUIRED apr-1)
include_directories(${APR_INCLUDE_DIRS})
link_directories(${APR_LIBRARY_DIRS})

# add 3th-party lib apr-util
pkg_search_module(APRUTIL REQUIRED apr-util-1)
include_directories(${APRUTIL_INCLUDE_DIRS})
link_directories(${APRUTIL_LIBRARY_DIRS})

# add 3th-party lib pcap
pkg_search_module(LIBPCAP REQUIRED libpcap)
include_directories(${LIBPCAP_INCLUDE_DIRS})
link_directories(${LIBPCAP_LIBRARY_DIRS})

file(GLOB HEADERS "src/core/include/*.h")

# add sipdump 标准SIP
if (BUILD_SIP)
  include_directories(${CORE_INC_DIR})
  add_library(sipdumpcore SHARED ${CORE_SRCS})
  target_compile_options(sipdumpcore PRIVATE -g)
  target_link_options(sipdumpcore PRIVATE -g)
  target_link_libraries(sipdumpcore ${APR_LIBRARIES} ${APRUTIL_LIBRARIES} ${LIBPCAP_LIBRARIES})

  add_executable(sipdump ${CLIENT_SRCS})
  target_compile_options(sipdump PRIVATE -g)
  target_link_options(sipdump PRIVATE -g)
  target_link_libraries(sipdump PRIVATE sipdumpcore)

endif()

# add mrcpdump 标准MRCP
if (BUILD_MRCP)
include_directories(${CORE_INC_DIR})
add_library(mrcpdumpcore SHARED ${CORE_SRCS})
target_compile_options(mrcpdumpcore PRIVATE -g)
target_compile_options(mrcpdumpcore PRIVATE -DSIPDUMP_MRCP)
target_link_options(mrcpdumpcore PRIVATE -g)
target_link_libraries(mrcpdumpcore ${APR_LIBRARIES} ${APRUTIL_LIBRARIES} ${LIBPCAP_LIBRARIES})

add_executable(mrcpdump ${CLIENT_SRCS})
target_compile_options(mrcpdump PRIVATE -g)
target_compile_options(mrcpdumpcore PRIVATE -DSIPDUMP_MRCP)
target_link_options(mrcpdump PRIVATE -g)
target_link_libraries(mrcpdump PRIVATE mrcpdumpcore)
endif()

# add tests
if (BUILD_TESTS)
  include_directories(${TEST_INC_DIR})
  add_executable(testsipdump ${TEST_SRCS})
  target_compile_options(testsipdump PRIVATE -g)
  target_link_options(testsipdump PRIVATE -g)
  target_link_libraries(testsipdump PRIVATE sipdumpcore)
  enable_testing()
  add_test(NAME testsipdump COMMAND test)
  set_tests_properties(testsipdump PROPERTIES LABELS "test")
  set_target_properties(testsipdump PROPERTIES OUTPUT_NAME "test")
endif()

# install 
include(GNUInstallDirs)
install(FILES ${HEADERS} DESTINATION ${INSTALL_DIR}/include)

if (BUILD_SIP)
install(TARGETS sipdumpcore DESTINATION ${INSTALL_DIR}/lib)
install(TARGETS sipdump DESTINATION ${INSTALL_DIR}/bin)
endif()

if (BUILD_MRCP)
install(TARGETS mrcpdumpcore DESTINATION ${INSTALL_DIR}/lib)
install(TARGETS mrcpdump DESTINATION ${INSTALL_DIR}/bin)
endif()

# uninstalls
if(NOT TARGET uninstall)
  configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

  add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
endif()