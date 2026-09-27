cmake_minimum_required(VERSION 3.16)
project(hierastream LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(HIERASTREAM_BUILD_TESTS "Enable CTest integration" ON)
option(HIERASTREAM_BUILD_PYTHON "Build pybind11 module" ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/core/crypto/cmake")

find_package(OpenSSL REQUIRED)
find_package(PBC REQUIRED)

add_subdirectory(core/crypto)

if(HIERASTREAM_BUILD_TESTS)
  enable_testing()
endif()
