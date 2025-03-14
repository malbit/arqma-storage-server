
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

if(NOT TARGET sodium)
  # Allow -D DOWNLOAD_SODIUM=FORCE to download without even checking for a local libsodium
  option(DOWNLOAD_SODIUM "Allow libsodium to be downloaded and built locally if not found on the system" OFF)
  if(NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM libsodium>=1.0.18 IMPORTED_TARGET)
  endif()

  add_library(sodium INTERFACE)
  if(SODIUM_FOUND AND NOT DOWNLOAD_SODIUM STREQUAL "FORCE" AND NOT BUILD_STATIC_DEPS)
    target_link_libraries(sodium INTERFACE PkgConfig::SODIUM)
  else()
    if(NOT DOWNLOAD_SODIUM AND NOT BUILD_STATIC_DEPS)
      message(FATAL_ERROR "Could not find libsodium >= 1.0.18; either install it on your system or use -DDOWNLOAD_SODIUM=ON to download and build an internal copy")
    endif()
    message(STATUS "Sodium >= 1.0.18 not found, but DOWNLOAD_SODIUM is specified so downloading it")
    include(DownloadLibSodium)
    target_link_libraries(sodium INTERFACE sodium_vendor)
  endif()

  export(TARGETS sodium NAMESPACE sodium:: FILE sodium-exports.cmake)
endif()

option(FORCE_ARQMAMQ_SUBMODULE "force using arqmamq submodule" OFF)
if(NOT STATIC AND NOT FORCE_ARQMAMQ_SUBMODULE)
  pkg_check_modules(ARQMAMQ libarqmamq>=1.0.0 IMPORTED_TARGET)
endif()
if(ARQMAMQ_FOUND)
  add_library(arqmamq INTERFACE)
  target_link_libraries(arqmamq INTERFACE PkgConfig::ARQMAMQ)
  add_library(arqmamq::arqmamq ALIAS arqmamq)
  message(STATUS "Found system libarqmamq ${ARQMAMQ_VERSION}")
else()
  message(STATUS "using arqmamq submodule")
  set(BUILD_SHARED_LIBS OFF CACHE BOOL "disable shared libraries")
  add_subdirectory(arqma-mq)
endif()

set(JSON_MultipleHeaders ON CACHE BOOL "")
add_subdirectory(nlohmann_json)

add_library(arqma-crypto-ops STATIC
  arqma/crypto-ops/keccak.c
  arqma/crypto-ops/hash-ops.c)
target_include_directories(arqma-crypto-ops PUBLIC .)

if(NOT CMAKE_VERSION VERSION_LESS 3.12)
  set(conf_depends "CONFIGURE_DEPENDS")
else()
  set(conf_depends "")
endif()
file(GLOB usockets_src ${conf_depends}
  uWebSockets/uSockets/src/*.c
  uWebSockets/uSockets/src/eventing/*.c
  uWebSockets/uSockets/src/crypto/*.c
  uWebSockets/uSockets/src/crypto/*.cpp)
file(COPY uWebSockets/uSockets/src/libusockets.h DESTINATION uWebSockets)
add_library(uSockets STATIC EXCLUDE_FROM_ALL ${usockets_src})
target_include_directories(uSockets PRIVATE uWebSockets/uSockets/src)
target_compile_definitions(uSockets PRIVATE LIBUS_USE_OPENSSL)
target_compile_features(uSockets PRIVATE c_std_11 cxx_std_17)
target_link_libraries(uSockets OpenSSL:SSL OpenSSL::Crypto)

if(WIN32 OR (APPLE AND NOT IOS))
  if(BUILD_STATIC_DEPS)
    target_link_libraries(uSockets libuv)
  else()
    if(STATIC)
      pkg_check_modules(LIBUV libuv-static REQUIRED IMPORTED_TARGET)
    else()
      pkg_check_modules(LIBUV libuv REQUIRED IMPORTED_TARGET)
    endif()
    target_link_libraries(uSockets PkgConfig::LIBUV)
  endif()
endif()

file(COPY uWebSockets/src/ DESTINATION uWebSockets/uWebSockets FILES_MATCHING PATTERN "*.h" PATTERN "*.hpp")
add_library(uWebSockets INTERFACE)
target_include_directories(uWebSockets SYSTEM INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/uWebSockets)
target_link_libraries(uWebSockets INTERFACE uSockets)
target_compile_definitions(uWebSockets INTERFACE UWS_HTTPRESPONSE_NO_WRITEMARK UWS_NO_ZLIB)

if(NOT BUILD_STATIC_DEPS)
  find_package(CURL REQUIRED COMPONENTS HTTP HTTPS SSL)

  if(CMAKE_VERSION VERSION_LESS 3.12 AND NOT TARGET CURL::libcurl)
    add_library(libcurl UNKNOWN IMPORTED GLOBAL)
    set_target_properties(libcurl PROPERTIES
      IMPORTED_LOCATION ${CURL_LIBRARIES}
      INTERFACE_INCLUDE_DIRECTORIES "${CURL_INCLUDE_DIRS}")
    add_library(CURL_libcurl INTERFACE)
    target_link_libraries(CURL_libcurl INTERFACE libcurl)
    add_library(CURL::libcurl ALIAS CURL_libcurl)
  endif()
endif()

file(GLOB cpr_sources ${conf_depends} cpr/cpr/*.cpp)

add_library(cpr STATIC EXCLUDE_FROM_ALL ${cpr_sources})
target_link_libraries(cpr PUBLIC CURL::libcurl)
target_include_directories(cpr PUBLIC cpr/include)
target_compile_definitions(cpr PUBLIC CPR_CURL_NOSIGNAL)
add_library(cpr::cpr ALIAS cpr)
