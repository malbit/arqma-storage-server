cmake_minimum_required(VERSION 3.10)

function(ARQMA_ADD_SUBDIRECTORY SRC)
    get_filename_component(target ${SRC} NAME)
    if (TARGET ${target})
        return()
    endif ()
    add_subdirectory(${SRC} ${ARGN})
endfunction()

project(storage_server)

option(INTEGRATION_TEST "build for integration test" OFF)
option(DISABLE_SNODE_SIGNATURE "Generate and verify signatures for inter-snode communication"
    OFF)

if (INTEGRATION_TEST)
    add_definitions(-DDISABLE_POW)
    add_definitions(-DINTEGRATION_TEST)
endif()


if (DISABLE_SNODE_SIGNATURE)
    add_definitions(-DDISABLE_SNODE_SIGNATURE)
endif()

arqma_add_subdirectory(common)
arqma_add_subdirectory(utils)
arqma_add_subdirectory(crypto)
arqma_add_subdirectory(pow)
arqma_add_subdirectory(storage)
arqma_add_subdirectory(httpserver)
arqma_add_subdirectory(vendors/spdlog)


if (BUILD_TESTS)
    arqma_add_subdirectory(unit_test)
endif ()
