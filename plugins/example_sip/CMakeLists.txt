cmake_minimum_required(VERSION 3.10)

project(example_sip VERSION 1.1.0)

set(CMAKE_VERBOSE_MAKEFILE OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

set(SRC_DIR src)
set(INC_DIR include)
set(CORE_INC_DIR /usr/local/sipdump/include)

# core sip src list
set(SRCS
    ${SRC_DIR}/example_sip.c
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

# add 
include_directories(${INC_DIR} ${CORE_INC_DIR})
add_library(example_sip SHARED ${SRCS})
target_compile_options(example_sip PRIVATE -g)
target_link_options(example_sip PRIVATE -g)
find_library(CORE_LIB NAMES sipdumpcore PATHS /usr/local/sipdump/lib/)
target_link_libraries(example_sip ${APR_LIBRARIES} ${APRUTIL_LIBRARIES} ${CORE_LIB} )
set_target_properties(example_sip PROPERTIES PREFIX "")
set_target_properties(example_sip PROPERTIES OUTPUT_NAME "example_sip")
install(TARGETS example_sip DESTINATION /usr/local/sipdump/plugins)
