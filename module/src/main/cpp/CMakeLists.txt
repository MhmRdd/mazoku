cmake_minimum_required(VERSION 3.22.1)
project(mazoku)

set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")

set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

add_library(${MODULE_NAME} SHARED mazoku.cpp And64InlineHook.cpp)

add_subdirectory(external)

target_link_libraries(${MODULE_NAME} cxx log)