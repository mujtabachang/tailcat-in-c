cmake_minimum_required(VERSION 3.24)
project(tailcat_cpp VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TAILCAT_BUILD_TESTS "Build tailcat tests" ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium libsodium)
if(NOT SODIUM_LIBRARY AND UNIX)
  find_file(SODIUM_LIBRARY NAMES libsodium.so.23 PATHS /lib /usr/lib /lib/x86_64-linux-gnu /usr/lib/x86_64-linux-gnu NO_DEFAULT_PATH)
endif()
if(NOT SODIUM_LIBRARY)
  message(FATAL_ERROR "libsodium library not found")
endif()

add_library(tailcat_lib
  src/address.cpp
  src/crypto.cpp
  src/derp.cpp
  src/http.cpp
  src/protocol.cpp
  src/session.cpp
)
target_include_directories(tailcat_lib PUBLIC include)
if(SODIUM_INCLUDE_DIR)
  target_include_directories(tailcat_lib PRIVATE ${SODIUM_INCLUDE_DIR})
endif()
target_compile_definitions(tailcat_lib PUBLIC BOOST_ERROR_CODE_HEADER_ONLY BOOST_SYSTEM_NO_DEPRECATED)
target_link_libraries(tailcat_lib PUBLIC OpenSSL::SSL OpenSSL::Crypto Threads::Threads ${SODIUM_LIBRARY})
if(WIN32)
  target_link_libraries(tailcat_lib PUBLIC ws2_32 crypt32)
endif()

add_executable(tailcat src/main.cpp)
target_link_libraries(tailcat PRIVATE tailcat_lib)

install(TARGETS tailcat RUNTIME DESTINATION bin)

if(TAILCAT_BUILD_TESTS)
  enable_testing()
  add_executable(tailcat_tests tests/tailcat_tests.cpp)
  target_link_libraries(tailcat_tests PRIVATE tailcat_lib)
  add_test(NAME tailcat_tests COMMAND tailcat_tests)
endif()
