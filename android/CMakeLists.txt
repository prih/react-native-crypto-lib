cmake_minimum_required(VERSION 3.4.1)

project(CryptoLib)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

file(GLOB_RECURSE lib_sources RELATIVE ${CMAKE_SOURCE_DIR}
        ../crypto/*.c
)

add_library(cryptolib
            SHARED
            ${lib_sources}
            ../cpp/react-native-crypto-lib.cpp
            cpp-adapter.cpp
)

# Specifies a path to native header files.
include_directories(
            ../cpp
            ../crypto
            ../crypto/aes
)

target_compile_options(cryptolib
  PRIVATE
    -std=gnu99
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

    -DUSE_MONERO=0
)
