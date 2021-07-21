cmake_minimum_required(VERSION 3.0.0)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

file(GLOB_RECURSE lib_sources RELATIVE ${CMAKE_SOURCE_DIR}
  ../external/crypto/*.c
)

add_library(crypto
  SHARED
    ${lib_sources}
    cpp-adapter.cpp
)

include_directories(
  ../external/crypto
)

target_compile_options(crypto
  PRIVATE
    -W
    -Wall
    -Wextra
    -Wimplicit-function-declaration
    -Wredundant-decls
    -Wstrict-prototypes
    -Wundef
    -Wshadow
    -Wpointer-arith
    -Wformat
    -Wreturn-type
    -Wsign-compare
    -Wmultichar
    -Wformat-nonliteral
    -Winit-self
    -Wuninitialized
    -Wformat-security
    -Wno-missing-braces
    -Werror
)
