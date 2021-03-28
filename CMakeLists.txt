cmake_minimum_required(VERSION 3.13)

project(rlbox_wamr
        VERSION 0.1
        DESCRIPTION "RLBox integration with WASM modules compiled with wamr")

# Project Settings ###################

# set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(DEV "Use settings suitable for dev contributions to rlbox" OFF)

file(GLOB_RECURSE
     ALL_CXX_SOURCE_FILES
     ${CMAKE_SOURCE_DIR}/include/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/include/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/include/*.cc
     ${CMAKE_SOURCE_DIR}/include/*.hh
     ${CMAKE_SOURCE_DIR}/include/*.ii
     ${CMAKE_SOURCE_DIR}/include/*.[CHI]
     ${CMAKE_SOURCE_DIR}/test/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/test/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/test/*.cc
     ${CMAKE_SOURCE_DIR}/test/*.hh
     ${CMAKE_SOURCE_DIR}/test/*.ii
     ${CMAKE_SOURCE_DIR}/test/*.[CHI]
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]pp
     ${CMAKE_SOURCE_DIR}/c_src/*.[chi]xx
     ${CMAKE_SOURCE_DIR}/c_src/*.cc
     ${CMAKE_SOURCE_DIR}/c_src/*.hh
     ${CMAKE_SOURCE_DIR}/c_src/*.ii
     ${CMAKE_SOURCE_DIR}/c_src/*.[CHI])

# Dev Tools ###################

if(DEV)
  find_program(CLANG_TIDY "clang-tidy")
  if(CLANG_TIDY)
    # Config in .clang-tidy
    set(CMAKE_CXX_CLANG_TIDY clang-tidy)
  endif()

  find_program(CLANG_FORMAT "clang-format")
  if(CLANG_FORMAT)
    # Config in .clang-format
    add_custom_target(format-source
                      COMMAND clang-format
                              -i
                              -style=file
                              ${ALL_CXX_SOURCE_FILES})
  endif()

endif()

# Dependencies ###################

find_program(CARGO "cargo")
if(!CARGO)
  message(
    FATAL_ERROR
      "Could not find cargo. Please install cargo as it is needed to build rust libraries."
    )
endif()

include(FetchContent)

FetchContent_Declare(
  rlbox
  GIT_REPOSITORY https://github.com/PLSysSec/rlbox_api_cpp17.git)
FetchContent_GetProperties(rlbox)
if(NOT rlbox_POPULATED)
  FetchContent_Populate(rlbox)
endif()

FetchContent_Declare(catch2
                     GIT_REPOSITORY https://github.com/catchorg/Catch2.git
                     GIT_TAG v2.9.1)
FetchContent_GetProperties(catch2)
if(NOT catch2_POPULATED)
  FetchContent_Populate(catch2)
endif()

add_subdirectory("${catch2_SOURCE_DIR}")
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/contrib")

if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  FetchContent_Declare(
    wasiclang
    URL
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-11/wasi-sdk-11.0-macos.tar.gz
    )
else()
  FetchContent_Declare(
    wasiclang
    URL
      https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-11/wasi-sdk-11.0-linux.tar.gz
    )
endif()
FetchContent_GetProperties(wasiclang)
if(NOT wasiclang_POPULATED)
  FetchContent_Populate(wasiclang)
endif()

FetchContent_Declare(
  mod_wamr
  GIT_REPOSITORY https://github.com/PLSysSec/wamr_sandbox_compiler
  GIT_TAG main)
FetchContent_GetProperties(mod_wamr)
if(NOT mod_wamr_POPULATED)
  FetchContent_Populate(mod_wamr)
endif()

# set(mod_wamr_SOURCE_DIR "/home/shr/Code/Code/wamr_sandbox_compiler")

# Wamr compiler and runtime ###################

set(WAMR_DIR "${mod_wamr_SOURCE_DIR}/wamr-compiler/build/")
set(WAMR_PATH "${WAMR_DIR}/wamrc")

if(UNIX AND (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  set(WAMR_PARAM "-DWAMR_BUILD_TARGET=darwin")
else()
  set(WAMR_PARAM "")
endif()

add_custom_command(OUTPUT "${WAMR_PATH}"
                   WORKING_DIRECTORY "${mod_wamr_SOURCE_DIR}/wamr-compiler"
                   COMMAND ./build_llvm.sh
                   COMMAND ${CMAKE_COMMAND}
                           ${WAMR_PARAM}
                           -S
                           .
                           -B
                           ./build
                   COMMAND VERBOSE=1
                           ${CMAKE_COMMAND}
                           --build
                           ./build
                           --target
                           all
                   COMMENT "Building wamrc compiler and runtime")

add_custom_target(wamr_release ALL DEPENDS ${WAMR_PATH})

# Wamr Lib ###################

set (WAMR_ROOT_DIR ${mod_wamr_SOURCE_DIR})
set (WAMR_BUILD_AOT 1)
set (WAMR_BUILD_PLATFORM "linux")
set (WAMR_BUILD_LIBC_WASI 1)
set (WASM_ENABLE_LIBC_WASI 1)
include (${WAMR_ROOT_DIR}/build-scripts/runtime_lib.cmake)
add_library(wamr_sandbox ${WAMR_RUNTIME_LIB_SOURCE}
                         ${CMAKE_SOURCE_DIR}/c_src/wamr_sandbox_runtime.cpp)
target_include_directories(wamr_sandbox
                         PUBLIC ${mod_wamr_SOURCE_DIR}/core/iwasm/include/)
target_include_directories(wamr_sandbox
                         PUBLIC ${CMAKE_SOURCE_DIR}/include)

# Tests ###################

if(DEV)
  if(MSVC)
    add_compile_options(/W4) # warnings
    add_compile_options(/WX) # warnings as errors
  else()
    add_compile_options(-Wall -Wextra -pedantic) # warnings
    add_compile_options(-Werror) # warnings as errors
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
    add_compile_options(-fsanitize=undefined)
    add_link_options(-fsanitize=undefined)
  endif()
endif()

include(CTest)
include(Catch)

find_program(WASMCLANG "clang")

if(!WASMCLANG)
  message(
    FATAL_ERROR
      "Require clang with support for target 'wasm32-wasi' to build the WASM module"
    )
endif()

set(C_SOURCE_FILES "${CMAKE_SOURCE_DIR}/c_src/wamr_sandbox_wrapper.c")
set(GLUE_LIB_WASM "${CMAKE_BINARY_DIR}/wasm/glue_lib_wamr.wasm")
set(GLUE_LIB_SO "${CMAKE_BINARY_DIR}/wasm/glue_lib_wamr.aot")

add_custom_command(OUTPUT ${GLUE_LIB_WASM} ${GLUE_LIB_SO}
                   DEPENDS ${C_SOURCE_FILES}
                   WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/c_src
                   COMMAND rlbox_SOURCE_DIR=${rlbox_SOURCE_DIR}
                           wasiclang_SOURCE_DIR=${wasiclang_SOURCE_DIR}
                           WAMR_DIR=${WAMR_DIR}
                           ${CMAKE_COMMAND}
                           -S
                           .
                           -B
                           ${CMAKE_BINARY_DIR}/wasm
                   COMMAND VERBOSE=1
                           ${CMAKE_COMMAND}
                           --build
                           ${CMAKE_BINARY_DIR}/wasm
                           --target
                           all
                   COMMENT "Building wasm library")

add_custom_target(glue_lib_wasm ALL DEPENDS wamr_release ${GLUE_LIB_WASM} ${GLUE_LIB_SO})

find_package(Threads REQUIRED)

# Tests executables ###################

add_executable(test_rlbox_glue test/test_wamr_sandbox_glue_main.cpp
                               test/test_wamr_sandbox_glue.cpp)
target_include_directories(test_rlbox_glue PUBLIC include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)

target_compile_definitions(test_rlbox_glue PUBLIC
                           GLUE_LIB_WAMR_PATH="${GLUE_LIB_SO}")

target_link_libraries(test_rlbox_glue
                      Catch2::Catch2
                      ${LINK_WAMR_LIB}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      wamr_sandbox
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue rt)
endif()
catch_discover_tests(test_rlbox_glue)

####

add_executable(test_rlbox_glue_embed test/test_wamr_sandbox_glue_main.cpp
                                     test/test_wamr_sandbox_glue_embedder_vars.cpp)
target_include_directories(test_rlbox_glue_embed PUBLIC include)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/include)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue)
target_include_directories(test_rlbox_glue_embed
                           PUBLIC ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib)

target_compile_definitions(test_rlbox_glue_embed PUBLIC
                           GLUE_LIB_WAMR_PATH="${GLUE_LIB_SO}")

target_link_libraries(test_rlbox_glue_embed
                      Catch2::Catch2
                      ${LINK_WAMR_LIB}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS}
                      wamr_sandbox
                      )

if(UNIX AND NOT (${CMAKE_SYSTEM_NAME} MATCHES "Darwin"))
  target_link_libraries(test_rlbox_glue_embed rt)
endif()
catch_discover_tests(test_rlbox_glue_embed)

# Shortcuts ###################

add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} -V)
add_dependencies(check test_rlbox_glue test_rlbox_glue_embed glue_lib_wasm)
