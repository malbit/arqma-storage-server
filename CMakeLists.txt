set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
  foreach(lang C CXX)
    if (NOT DEFINED CMAKE_${lang}_COMPILER_LAUNCHER AND NOT CMAKE_${lang}_COMPILER MATCHES ".*/ccache")
      message(STATUS "Enabling ccache for ${lang}")
      set(CMAKE_${lang}_COMPILER_LAUNCHER ${CCACHE_PROGRAM} CACHE STRING "")
    endif()
  endforeach()
endif()

cmake_minimum_required(VERSION 3.10)

project(storage_server
  VERSION 1.0.0
  LANGUAGES CXX C)

option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED TRUE)
set(CMAKE_CXX_EXTENSIONS FALSE)

cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
option(USE_LTO "Use Link-Time Optimization" ON)
if(USE_LTO AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO Enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO Disabled")
  set(IPO_ENABLED OFF)
endif()

if(DISABLE_SNODE_SIGNATURE)
  add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(BUILD_STATIC_DEPS "Download, build and statically link against core dependencies" OFF)
if(BUILD_STATIC_DEPS)
  include(StaticBuild)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.17)
  add_library(sodium INTERFACE)
  target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
  find_package(Boost REQUIRED system program_options)
  find_package(OpenSSL REQUIRED)
endif()

include(cmake/check_for_std_filesystem.cmake)

if(NOT BUILD_STATIC_DEPS)
endif()

add_subdirectory(common)
add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(httpserver)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries")
add_subdirectory(vendors/arqmamq)
