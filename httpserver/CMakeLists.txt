add_definitions(-DDISABLE_ENCRYPTION)
add_definitions(-DSPDLOG_COMPILED_LIB)

set(HEADER_FILES
    http_connection.h
    swarm.h
    service_node.h
    serialization.h
    rate_limiter.h
    ../external/json.hpp
    https_client.h
    server_certificates.h
    stats.h
    security.h
    command_line.h
    net_stats.h
    dns_text_records.h
    reachability_testing.h
    )

set(SRC_FILES
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
    )

add_library(httpserver_lib STATIC ${HEADER_FILES} ${SRC_FILES})

target_link_libraries(httpserver_lib PUBLIC common)
target_link_libraries(httpserver_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(httpserver_lib PUBLIC storage)
target_link_libraries(httpserver_lib PUBLIC utils)
target_link_libraries(httpserver_lib PUBLIC resolv)
target_link_libraries(httpserver_lib PUBLIC crypto spdlog::spdlog)
target_link_libraries(httpserver_lib PUBLIC Boost::boost Boost::program_options)

set(BIN_NAME arqma-storage)

add_executable(httpserver main.cpp)
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
