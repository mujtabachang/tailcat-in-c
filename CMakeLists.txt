cmake_minimum_required(VERSION 3.24)

set(TAILCAT_VERSION "0.1.0" CACHE STRING "Tailcat semantic version")
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" TAILCAT_PROJECT_VERSION "${TAILCAT_VERSION}")
if(NOT TAILCAT_PROJECT_VERSION)
  message(FATAL_ERROR "TAILCAT_VERSION must start with MAJOR.MINOR.PATCH")
endif()
project(tailcat VERSION ${TAILCAT_PROJECT_VERSION} LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(TAILCAT_BUILD_TESTS "Build tailcat tests" ON)

find_package(unofficial-sodium CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(tailcat_core
    src/cli.cpp
    src/platform.cpp
    src/protocol.cpp
    src/crypto.cpp
)
target_include_directories(tailcat_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(tailcat_core PUBLIC cxx_std_20)
target_compile_definitions(tailcat_core PRIVATE TAILCAT_VERSION="${TAILCAT_VERSION}")
target_link_libraries(tailcat_core PUBLIC unofficial-sodium::sodium OpenSSL::SSL OpenSSL::Crypto)

if(MSVC)
  target_compile_options(tailcat_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(tailcat_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if(WIN32)
  target_compile_definitions(tailcat_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(tailcat_core PUBLIC ws2_32)
endif()

add_executable(tailcat src/main.cpp)
target_link_libraries(tailcat PRIVATE tailcat_core)

install(TARGETS tailcat RUNTIME DESTINATION bin)

if(TAILCAT_BUILD_TESTS)
  include(CTest)
  if(BUILD_TESTING)
    add_executable(tailcat_tests tests/cli_test.cpp)
    target_link_libraries(tailcat_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_cli COMMAND tailcat_tests)

    add_executable(tailcat_protocol_tests tests/protocol_test.cpp)
    target_link_libraries(tailcat_protocol_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_protocol COMMAND tailcat_protocol_tests)

    add_executable(tailcat_crypto_tests tests/crypto_test.cpp)
    target_link_libraries(tailcat_crypto_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_crypto COMMAND tailcat_crypto_tests)
  endif()
endif()
