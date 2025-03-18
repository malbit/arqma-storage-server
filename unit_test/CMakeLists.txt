cmake_minimum_required (VERSION 3.10)

add_executable (Test
    main.cpp
    storage.cpp
    serialization.cpp
    signature.cpp
    rate_limiter.cpp
    command_line.cpp
)

target_link_libraries(Test PRIVATE common storage utils crypto httpserver_lib)
target_include_directories(Test PRIVATE ../httpserver)

if(NOT BUILD_STATIC_DEPS)
  find_package(Boost REQUIRED
    system
    filesystem
    chrono
    thread
    unit_test_framework
  )
endif()

target_link_libraries(Test PRIVATE Boost::unit_test_framework Boost::system Boost::filesystem Boost::chrono Boost::thread)