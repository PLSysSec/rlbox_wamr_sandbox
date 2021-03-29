cmake_minimum_required(VERSION 3.13)

# Mac adds extra flags 
set(HAVE_FLAG_SEARCH_PATHS_FIRST 0)

project(rlbox_wamr_testlib
        VERSION 0.1
        DESCRIPTION "RLBox integration with WASM modules compiled with wamr")

if(NOT DEFINED ENV{rlbox_SOURCE_DIR})
  message(FATAL_ERROR "Set rlbox_SOURCE_DIR environment variable")
endif()

if(NOT DEFINED ENV{wasiclang_SOURCE_DIR})
  message(FATAL_ERROR "Set wasiclang_SOURCE_DIR environment variable")
endif()

if(NOT DEFINED ENV{WAMR_COMPILER_DIR})
  message(FATAL_ERROR "Set WAMR_COMPILER_DIR environment variable")
endif()

set(rlbox_SOURCE_DIR $ENV{rlbox_SOURCE_DIR})
set(wasiclang_SOURCE_DIR $ENV{wasiclang_SOURCE_DIR})
set(WAMR_COMPILER_DIR $ENV{WAMR_COMPILER_DIR})

set(CMAKE_C_COMPILER ${wasiclang_SOURCE_DIR}/bin/clang)
set(CMAKE_CXX_COMPILER ${wasiclang_SOURCE_DIR}/bin/clang++)
set(CMAKE_BUILD_TYPE Release)

# Apply settings suitable for wasm module compilation
set(CMAKE_C_FLAGS
    "--sysroot ${wasiclang_SOURCE_DIR}/share/wasi-sysroot/")
# Link flags are set by default on Mac - clearing this
set(CMAKE_C_LINK_FLAGS "")
set(CMAKE_EXE_LINKER_FLAGS "-Wl,--export-all")

add_executable(glue_lib_wamr.wasm
               wamr_sandbox_wrapper.c
               ${rlbox_SOURCE_DIR}/code/tests/rlbox_glue/lib/libtest.c)

set(GLUE_LIB_PATH "${CMAKE_BINARY_DIR}/glue_lib_wamr.aot")
# For debuggging only
set(GLUE_LIB_OBJ_PATH "${CMAKE_BINARY_DIR}/glue_lib_wamr.o")

add_custom_command(OUTPUT ${GLUE_LIB_PATH}
                   DEPENDS glue_lib_wamr.wasm
                   COMMAND ${WAMR_COMPILER_DIR}/wamrc
                           --target=x86_64
                           --disable-simd
                           -o
                           ${GLUE_LIB_PATH}
                           glue_lib_wamr.wasm
                    COMMAND ${WAMR_COMPILER_DIR}/wamrc
                           --format=object
                           -o
                           ${GLUE_LIB_OBJ_PATH}
                           glue_lib_wamr.wasm
                   COMMENT "Compiling wasm file to native")

add_custom_target(glue_lib_so ALL DEPENDS ${GLUE_LIB_PATH})
