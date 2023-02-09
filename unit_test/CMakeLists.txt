cmake_minimum_required (VERSION 3.10)

add_executable (Test
    main.cpp
    storage.cpp
    serialization.cpp
    signature.cpp
    rate_limiter.cpp
    command_line.cpp
)

# library under test

arqma_add_subdirectory(../common common)
arqma_add_subdirectory(../storage storage)
arqma_add_subdirectory(../utils utils)
arqma_add_subdirectory(../crypto crypto)
arqma_add_subdirectory(../httpserver httpserver)

target_link_libraries(Test PRIVATE common storage utils crypto httpserver_lib)

# boost
find_package(Boost REQUIRED
    system
    filesystem
    chrono
    thread
    unit_test_framework
)

set_property(TARGET Test PROPERTY CXX_STANDARD 17)

target_include_directories(Test PRIVATE ${Boost_INCLUDE_DIRS})
target_link_libraries(Test PRIVATE ${Boost_LIBRARIES})
