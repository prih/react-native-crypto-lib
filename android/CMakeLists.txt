cmake_minimum_required(VERSION 3.0.0)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

add_library(crypto
  SHARED
    ../external/crypto/bip39.c
    ../external/crypto/hmac.c
    ../external/crypto/memzero.c
    ../external/crypto/pbkdf2.c
    ../external/crypto/rand.c
    ../external/crypto/ripemd160.c
    ../external/crypto/sha2.c
    ../external/crypto/sha3.c
    cpp-adapter.cpp
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

include_directories(
  ../external/crypto
)
