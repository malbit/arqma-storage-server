cmake_minimum_required(VERSION 3.10)

add_definitions(-DSPDLOG_COMPILED_LIB)

add_library(common STATIC
    src/arqma_logger.cpp
)

target_link_libraries(common PUBLIC spdlog::spdlog filesystemm arqmamq::arqmamq)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
