cmake_minimum_required(VERSION 3.4.1)

project(CryptoLib)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

file(GLOB lib_sources RELATIVE ${CMAKE_SOURCE_DIR}
        ../crypto/*.c
        ../crypto/aes/*.c
        ../crypto/chacha20poly1305/*.c
        ../crypto/ed25519-donna/*.c
)

file(GLOB lib_secp256k1 RELATIVE ${CMAKE_SOURCE_DIR}
        ../crypto/secp256k1/src/precomputed_ecmult.c
        ../crypto/secp256k1/src/precomputed_ecmult_gen.c
        ../crypto/secp256k1/src/secp256k1.c
)

add_library(cryptolib
            SHARED
            ${lib_sources}
            ${lib_secp256k1}
            ../cpp/react-native-crypto-lib.cpp
            cpp-adapter.cpp
)

# Specifies a path to native header files.
include_directories(
            ../cpp
            ../crypto
            ../crypto/aes
            ../crypto/secp256k1/include
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
    -Wno-unused-function

    -DUSE_MONERO=0

    -DECMULT_GEN_PREC_BITS=4
    -DECMULT_WINDOW_SIZE=8
    -DENABLE_MODULE_GENERATOR
    -DENABLE_MODULE_RECOVERY
    -DENABLE_MODULE_SCHNORRSIG
    -DENABLE_MODULE_EXTRAKEYS
    -DSECP256K1_CONTEXT_SIZE=208
    
    -DSECP256K1_BUILD_BENCHMARK=OFF
    -DSECP256K1_BUILD_TESTS=OFF
    -DSECP256K1_BUILD_EXHAUSTIVE_TESTS=OFF
    -DSECP256K1_BUILD_CTIME_TESTS=OFF
    -DSECP256K1_BUILD_EXAMPLES=OFF
)
