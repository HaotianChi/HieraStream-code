cmake_minimum_required(VERSION 3.16)

add_library(hierastream_crypto
  src/pairing.cpp
  src/crypto_engine.cpp
  src/aead_kdf.cpp
)
add_library(hierastream::crypto ALIAS hierastream_crypto)

target_include_directories(hierastream_crypto
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_link_libraries(hierastream_crypto
  PUBLIC
    PBC::PBC
    OpenSSL::Crypto
)

target_compile_features(hierastream_crypto PUBLIC cxx_std_17)

# Silence unused-result noise on some Ubuntu toolchains
if(MSVC)
  target_compile_options(hierastream_crypto PRIVATE /W3)
else()
  target_compile_options(hierastream_crypto PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

if(HIERASTREAM_BUILD_PYTHON)
  find_package(Python3 COMPONENTS Interpreter Development REQUIRED)
  find_package(pybind11 CONFIG QUIET)
  if(NOT pybind11_FOUND)
    # Fallback: use pip-installed pybind11 headers via python
    execute_process(
      COMMAND "${Python3_EXECUTABLE}" -m pybind11 --cmakedir
      OUTPUT_VARIABLE _pybind11_dir
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    if(_pybind11_dir)
      list(APPEND CMAKE_PREFIX_PATH "${_pybind11_dir}")
      find_package(pybind11 CONFIG REQUIRED)
    endif()
  endif()
  if(pybind11_FOUND)
    pybind11_add_module(hierastream_native bindings/module.cpp)
    target_link_libraries(hierastream_native PRIVATE hierastream_crypto)
    target_compile_definitions(hierastream_native PRIVATE HIERASTREAM_HAS_PBC=1)
  else()
    message(WARNING "pybind11 not found — Python native module skipped")
  endif()
endif()

if(HIERASTREAM_BUILD_TESTS)
  enable_testing()
endif()
