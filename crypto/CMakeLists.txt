add_library(crypto STATIC
    src/arqmad_key.cpp
    src/channel_encryption.cpp
    src/signature.cpp
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/arqma/crypto-ops/keccak.c
    ${CMAKE_CURRENT_LIST_DIR}/../vendors/arqma/crypto-ops/hash-ops.c)

target_link_libraries(crypto PRIVATE OpenSSL::SSL)

target_include_directories(crypto
    PUBLIC
      ${CMAKE_CURRENT_LIST_DIR}/include
    PRIVATE
      ${CMAKE_CURRENT_LIST_DIR}/../vendors)

target_link_libraries(crypto PUBLIC utils)

find_package(Threads)

target_link_libraries(crypto
  PUBLIC
    common
  PRIVATE
    sodium
    Boost::boost
    Threads::Threads
    ${CMAKE_DL_LIBS})
