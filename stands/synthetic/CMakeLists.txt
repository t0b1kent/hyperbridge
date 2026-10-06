# SPDX-License-Identifier: MIT
# Copyright (c) 2026 HyperBridge contributors
cmake_minimum_required(VERSION 3.20)
project(HyperBridgeStand C CXX ASM)

if (NOT FEXSRC)
  set(FEXSRC ${CMAKE_CURRENT_SOURCE_DIR}/../../build/stand-fex/src)
endif()
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin)
if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

set(MINGW FALSE)
set(ARCHITECTURE_arm64 1)
set(ENABLE_FEX_ALLOCATOR OFF)
set(ENABLE_JEMALLOC_GLIBC_ALLOC OFF)
set(ENABLE_VIXL_DISASSEMBLER OFF)
set(ENABLE_VIXL_SIMULATOR OFF)
set(ENABLE_ZYDIS OFF)
set(ENABLE_FEXCORE_PROFILER OFF)
set(ENABLE_GLIBC_ALLOCATOR_HOOK_FAULT OFF)
set(BUILD_TESTING OFF)
set(BUILD_STEAM_SUPPORT OFF)
set(FEX_TUNE_COMPILE_FLAGS "")
set(BUILD_SHARED_LIBS OFF)

add_compile_definitions(ARCHITECTURE_arm64=1 _LARGEFILE64_SOURCE FEX_DISABLE_TELEMETRY=1
  GLOBAL_DATA_DIRECTORY="/nonexistent-fex-data/" HAS_PROGRAM_INVOCATION_NAME=0 FEX_MACOS_ORACLE=1
  HB_REPLAY_WIN_TABLES=1)
add_compile_options(-Wno-trigraphs -Wno-deprecated-enum-enum-conversion)


include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-std=c++11 -Wattributes -Werror=attributes")
check_cxx_source_compiles("
  __attribute__((preserve_all))
  int Testy(int a, int b, int c, int d, int e, int f) { return a + b + c + d + e + f; }
  int main() { return Testy(0, 1, 2, 3, 4, 5); }" HAS_CLANG_PRESERVE_ALL)
unset(CMAKE_REQUIRED_FLAGS)
if (HAS_CLANG_PRESERVE_ALL)
  add_compile_definitions("FEX_PRESERVE_ALL_ATTR=__attribute__((preserve_all))" "FEX_HAS_PRESERVE_ALL_ATTR=1")
else()
  add_compile_definitions("FEX_PRESERVE_ALL_ATTR=" "FEX_HAS_PRESERVE_ALL_ATTR=0")
endif()

function(LinkerGC Target)
endfunction()

set(GIT_DESCRIBE_STRING "FEX-macos-oracle")
set(GIT_HASH_ARRAY "0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0")

find_package(Python 3.9 REQUIRED COMPONENTS Interpreter)

add_subdirectory(${FEXSRC}/External/unordered_dense unordered_dense)
set(XXHASH_BUNDLED_MODE TRUE)
set(XXHASH_BUILD_XXHSUM FALSE)
add_subdirectory(${FEXSRC}/External/xxhash/cmake_unofficial xxhash)
set(FMT_INSTALL OFF)
add_subdirectory(${FEXSRC}/External/fmt fmt)
add_subdirectory(${FEXSRC}/External/SoftFloat-3e softfloat)
add_subdirectory(${FEXSRC}/External/cephes cephes)

include_directories(${FEXSRC}/Source/)
include_directories(${CMAKE_BINARY_DIR}/Source/)

add_subdirectory(${FEXSRC}/FEXHeaderUtils FEXHeaderUtils)
add_subdirectory(${FEXSRC}/CodeEmitter CodeEmitter)
add_subdirectory(${FEXSRC}/FEXCore FEXCore)

if (NOT STAND_RUNNER_SOURCE)
  set(STAND_RUNNER_SOURCE ${CMAKE_CURRENT_SOURCE_DIR}/runner.cpp)
endif()
add_executable(stand_runner
  ${STAND_RUNNER_SOURCE}
  ${CMAKE_CURRENT_SOURCE_DIR}/MacHostFeatures.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/MacAllocatorHooks.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/MacFrontendStubs.cpp
  ${FEXSRC}/Source/Common/HostFeatures.cpp)
if (EXISTS "${FEXSRC}/FEXCore/Source/Interface/Core/hb_native_impl.h")
  target_sources(stand_runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/ReplaySpansStub.cpp)
endif()
target_include_directories(stand_runner PRIVATE ${FEXSRC}/Source ${FEXSRC}/FEXCore/Source
  ${CMAKE_BINARY_DIR}/generated ${FEXSRC}/FEXCore/include ${CMAKE_BINARY_DIR}/include ${FEXSRC}/External/range-v3/include)
target_compile_options(stand_runner PRIVATE -Wno-unused-variable -Wno-unused-parameter)
target_link_libraries(stand_runner PRIVATE FEXCore FEXCore_Base fmt::fmt xxHash::xxhash cephes_128bit)
target_link_options(stand_runner PRIVATE -Wl,-dead_strip)
if (STAND_HARDWARE_TSO)
  add_library(stand_hwtso SHARED ${FEXSRC}/Source/Windows/UnixLib/MacRunnerHardwareTSO.cpp)
  target_compile_options(stand_hwtso PRIVATE -fno-exceptions -fno-rtti)
  set_target_properties(stand_hwtso PROPERTIES OUTPUT_NAME macrunner-hwtso
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/Bin
    INSTALL_NAME_DIR "@rpath" BUILD_WITH_INSTALL_NAME_DIR ON)
  target_link_libraries(stand_runner PRIVATE stand_hwtso)
  set_target_properties(stand_runner PROPERTIES BUILD_WITH_INSTALL_RPATH ON INSTALL_RPATH "@loader_path")
endif()
set_source_files_properties(${FEXSRC}/Source/Common/HostFeatures.cpp PROPERTIES COMPILE_DEFINITIONS "_LIBCPP_TEMPLATE_VIS=")
