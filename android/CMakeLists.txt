cmake_minimum_required(VERSION 3.0.0)

set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 11)

add_library(crypto SHARED
  ../external/crypto/rand.c
  cpp-adapter.cpp
)

include_directories(
  ../external/crypto
)
