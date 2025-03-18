cmake_minimum_required(VERSION 3.18)

project(storage_server)

if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
  set(CMAKE_POLICY_DEFAULT_CMP0135 NEW)
endif()

cmake_policy(SET CMP0079 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0079 NEW)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()


option(INTEGRATION_TEST "build for integration test" OFF)
option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

cmake_policy(SET CMP0069 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0069 NEW)
option(USE_LTO "Use Link-Time Optimization" ON)
if(USE_LTO AND NOT DEFINED CMAKE_INTERPROCEDURAL_OPTIMIZATION)
  include(CheckIPOSupported)
  check_ipo_supported(RESULT IPO_ENABLED OUTPUT ipo_error)
  if(IPO_ENABLED)
    message(STATUS "LTO enabled")
    set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
  else()
    message(WARNING "LTO not supported by compiler: ${ipo_error}")
  endif()
else()
  message(STATUS "LTO disabled")
  set(IPO_ENABLED OFF)
endif()

if (INTEGRATION_TEST)
    add_definitions(-DINTEGRATION_TEST)
endif()

if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

option(BUILD_TESTS "tests off" OFF)

list (APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

option(BUILD_STATIC_DEPS "Static" ON)
if(BUILD_STATIC_DEPS)
  include(StaticBuild)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium>=1.0.18)
  add_library(sodium INTERFACE)
  target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)

  find_package(Boost 1.68.0 QUIET REQUIRED COMPONENTS system program_options filesystem thread chrono)
  find_package(OpenSSL REQUIRED)
endif()

add_subdirectory(common)
add_subdirectory(utils)
add_subdirectory(crypto)
add_subdirectory(storage)
add_subdirectory(httpserver)
add_subdirectory(vendors)

if (BUILD_TESTS)
    add_subdirectory(unit_test)
endif ()
