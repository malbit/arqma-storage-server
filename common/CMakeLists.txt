add_library(common STATIC
  src/arqma_logger.cpp)

target_link_libraries(common PUBLIC spdlog::spdlog filesystem)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_compile_definitions(common PUBLIC SPDLOG_COMPILED_LIB)
