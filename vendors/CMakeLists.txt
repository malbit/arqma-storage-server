
if(BUILD_STATIC_DEPS)
  set(DEFAULT_STATIC ON)
else()
  set(DEFAULT_STATIC OFF)
endif()
option(STATIC "Try to link external dependencies statically where possible" ${DEFAULT_STATIC})

if(NOT STATIC AND NOT BUILD_STATIC_DEPS)
  find_package(PkgConfig REQUIRED)
endif()

option(FORCE_SPDLOG_SUBMODULE "force using spdlog submodule" OFF)
if(NOT STATIC AND NOT FORCE_SPDLOG_SUBMODULE)
  pkg_check_modules(SPDLOG spdlog>=1.8 IMPORTED_TARGET)
endif()
if(SPDLOG_FOUND)
  add_library(spdlog INTERFACE)
  target_link_libraries(spdlog INTERFACE PkgConfig::SPDLOG)
  add_library(spdlog::spdlog ALIAS spdlog)
else()
  add_subdirectory(spdlog)
endif()

add_library(arqma-crypto-ops STATIC
  arqma/crypto-ops/keccak.c
  arqma/crypto-ops/hash-ops.c
  arqma/crypto-ops/crypto-ops.c
  arqma/crypto-ops/crypto-ops-data.c)
target_include_directories(arqma-crypto-ops PUBLIC .)
