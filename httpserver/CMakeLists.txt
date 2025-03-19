add_library(httpserver_lib STATIC
    main.cpp
    http_connection.cpp
    swarm.cpp
    service_node.cpp
    serialization.cpp
    rate_limiter.cpp
    https_client.cpp
    stats.cpp
    security.cpp
    command_line.cpp
    dns_text_records.cpp
    reachability_testing.cpp
    server_certificates.cpp
    )

target_link_libraries(httpserver_lib
  PUBLIC
    common
    storage
    utils
    crypto
    spdlog::spdlog
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Boost::program_options
)

find_library(RESOLV resolv)
if(RESOLV)
  target_link_libraries(httpserver_lib PUBLIC ${RESOLV})
endif()

target_compile_definitions(httpserver_lib PUBLIC SPDLOG_COMPILED_LIB DISABLE_ENCRYPTION)

set(BIN_NAME arqma-storage)

add_executable(httpserver main.cpp)
set_property(TARGET httpserver PROPERTY RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/binaries")
set_target_properties(httpserver PROPERTIES OUTPUT_NAME ${BIN_NAME})
target_link_libraries(httpserver PRIVATE httpserver_lib)
install(TARGETS httpserver DESTINATION bin)
# Build Info
execute_process(
    COMMAND
        git rev-parse --short HEAD
    OUTPUT_VARIABLE
        SHORT_HASH
    OUTPUT_STRIP_TRAILING_WHITESPACE)
string(TIMESTAMP BUILD_TIME UTC)
message(STATUS "using git commit hash ${SHORT_HASH}")
message(STATUS "using UTC build time ${BUILD_TIME}")
target_compile_definitions(httpserver PRIVATE -DSTORAGE_SERVER_GIT_HASH_STRING="${SHORT_HASH}")
target_compile_definitions(httpserver PRIVATE -DSTORAGE_SERVER_BUILD_TIME="${BUILD_TIME}")
#
