add_library(crypto STATIC
    src/arqmad_key.cpp
    src/channel_encryption.cpp
    src/signature.cpp
)

target_include_directories(crypto PUBLIC include)


add_executable(crypto_test src/test_main.cpp)
target_link_libraries(crypto_test PRIVATE crypto)

find_package(Threads)

target_link_libraries(crypto
  PUBLIC
    common
    utils
  PRIVATE
    arqma-crypto-ops
    OpenSSL::SSL
    sodium
    Boost::boost
    Threads::Threads
    ${CMAKE_DL_LIBS})
