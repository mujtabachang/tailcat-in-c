cmake_minimum_required(VERSION 3.24)

set(TAILCAT_VERSION "0.1.0" CACHE STRING "Tailcat semantic version")
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" TAILCAT_PROJECT_VERSION "${TAILCAT_VERSION}")
if(NOT TAILCAT_PROJECT_VERSION)
  message(FATAL_ERROR "TAILCAT_VERSION must start with MAJOR.MINOR.PATCH")
endif()
project(tailcat VERSION ${TAILCAT_PROJECT_VERSION} LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build dependencies as static libraries" FORCE)

option(TAILCAT_BUILD_TESTS "Build tailcat tests" ON)

include(FetchContent)
find_package(Threads REQUIRED)

set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  tailcat_sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(tailcat_sodium)

FetchContent_Declare(
  tailcat_lwip
  GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
  GIT_TAG 77dcd25a72509eb83f72b033d219b1d40cd8eb95
  GIT_SHALLOW FALSE
  SOURCE_SUBDIR _tailcat_source_only
)
FetchContent_MakeAvailable(tailcat_lwip)

set(LWIP_DIR ${tailcat_lwip_SOURCE_DIR})
set(LWIP_EXCLUDE_SLIPIF TRUE)
include(${LWIP_DIR}/src/Filelists.cmake)
add_library(tailcat_lwip_stack STATIC
    ${lwipcore_SRCS}
    ${lwipcore6_SRCS}
    src/lwip_platform.cpp
)
set_target_properties(tailcat_lwip_stack PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tailcat_lwip_stack PRIVATE c_std_11)
target_include_directories(tailcat_lwip_stack
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip_port
    ${LWIP_DIR}/src/include
)
target_link_libraries(tailcat_lwip_stack PUBLIC sodium)

FetchContent_Declare(
  tailcat_wireguard_src
  GIT_REPOSITORY https://github.com/smartalock/wireguard-lwip.git
  GIT_TAG c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d
  GIT_SHALLOW FALSE
  SOURCE_SUBDIR _tailcat_source_only
)
FetchContent_MakeAvailable(tailcat_wireguard_src)

add_library(tailcat_wireguard STATIC
    ${tailcat_wireguard_src_SOURCE_DIR}/src/wireguard.c
    ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/blake2s.c
    ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/chacha20.c
    ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/chacha20poly1305.c
    ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/poly1305-donna.c
    ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/x25519.c
    src/wireguard_crypto_port.c
    src/wireguard_platform.cpp
)
set_target_properties(tailcat_wireguard PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tailcat_wireguard PRIVATE c_std_11 cxx_std_20)
target_include_directories(tailcat_wireguard
  PUBLIC
    ${tailcat_wireguard_src_SOURCE_DIR}/src
    ${tailcat_lwip_SOURCE_DIR}/src/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip_port
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(tailcat_wireguard PUBLIC sodium)
if(MSVC)
  target_compile_options(tailcat_wireguard PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/include/tailcat/wireguard_compat.h")
endif()

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  tailcat_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG c41152e62092c16cf4fc4625becacc3eb9d9319f
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(tailcat_json)

find_package(CURL QUIET)
if(NOT CURL_FOUND)
  set(BUILD_CURL_EXE OFF CACHE BOOL "" FORCE)
  set(BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(BUILD_STATIC_LIBS ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_TESTS ON CACHE BOOL "" FORCE)
  set(CURL_DISABLE_INSTALL ON CACHE BOOL "" FORCE)
  set(CURL_USE_LIBPSL OFF CACHE BOOL "" FORCE)
  set(CURL_ZLIB OFF CACHE BOOL "" FORCE)
  set(CURL_BROTLI OFF CACHE BOOL "" FORCE)
  set(CURL_ZSTD OFF CACHE BOOL "" FORCE)
  set(CURL_USE_LIBSSH2 OFF CACHE BOOL "" FORCE)
  set(CURL_USE_GSSAPI OFF CACHE BOOL "" FORCE)
  if(WIN32)
    set(CURL_USE_SCHANNEL ON CACHE BOOL "" FORCE)
  else()
    set(CURL_USE_OPENSSL ON CACHE BOOL "" FORCE)
  endif()
  FetchContent_Declare(
    tailcat_curl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG c427e91ddea7c1d4b2f5c54ab4b6810f61483928
    GIT_SHALLOW FALSE
  )
  FetchContent_MakeAvailable(tailcat_curl)
endif()

add_library(tailcat_core STATIC
    src/cli.cpp
    src/forward_command.cpp
    src/platform.cpp
    src/protocol.cpp
    src/ip.cpp
    src/crypto.cpp
    src/derp.cpp
    src/derp_http.cpp
    src/derp_map.cpp
    src/rendezvous.cpp
    src/wireguard_engine.cpp
    src/wireguard_derp.cpp
    src/lwip_stack.cpp
    src/data_plane.cpp
    src/host_tcp.cpp
    src/port_forward.cpp
    src/local_forward.cpp
)
target_include_directories(tailcat_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(tailcat_core PUBLIC cxx_std_20)
target_compile_definitions(tailcat_core PRIVATE TAILCAT_VERSION="${TAILCAT_VERSION}")
target_link_libraries(tailcat_core PUBLIC sodium CURL::libcurl nlohmann_json::nlohmann_json tailcat_wireguard tailcat_lwip_stack)

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

    add_executable(tailcat_ip_tests tests/ip_test.cpp)
    target_link_libraries(tailcat_ip_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_ip COMMAND tailcat_ip_tests)

    add_executable(tailcat_lwip_tests tests/lwip_test.cpp)
    target_link_libraries(tailcat_lwip_tests PRIVATE tailcat_lwip_stack)
    add_test(NAME tailcat_lwip COMMAND tailcat_lwip_tests)

    add_executable(tailcat_lwip_tcp_tests tests/lwip_stack_test.cpp)
    target_link_libraries(tailcat_lwip_tcp_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_lwip_tcp COMMAND tailcat_lwip_tcp_tests)

    add_executable(tailcat_derp_tests tests/derp_test.cpp)
    target_link_libraries(tailcat_derp_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_derp COMMAND tailcat_derp_tests)

    add_executable(tailcat_rendezvous_tests tests/rendezvous_test.cpp)
    target_link_libraries(tailcat_rendezvous_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_rendezvous COMMAND tailcat_rendezvous_tests)

    add_executable(tailcat_wireguard_tests tests/wireguard_test.cpp)
    target_link_libraries(tailcat_wireguard_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_wireguard COMMAND tailcat_wireguard_tests)

    add_executable(tailcat_wireguard_derp_tests tests/wireguard_derp_test.cpp)
    target_link_libraries(tailcat_wireguard_derp_tests PRIVATE tailcat_core Threads::Threads)
    add_test(NAME tailcat_wireguard_derp COMMAND tailcat_wireguard_derp_tests)

    add_executable(tailcat_data_plane_tests tests/data_plane_test.cpp)
    target_link_libraries(tailcat_data_plane_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_data_plane COMMAND tailcat_data_plane_tests)

    add_executable(tailcat_host_tcp_tests tests/host_tcp_test.cpp)
    target_link_libraries(tailcat_host_tcp_tests PRIVATE tailcat_core Threads::Threads)
    add_test(NAME tailcat_host_tcp COMMAND tailcat_host_tcp_tests)

    set(TAILCAT_TEST_TARGETS
      tailcat_tests
      tailcat_protocol_tests
      tailcat_ip_tests
      tailcat_lwip_tests
      tailcat_lwip_tcp_tests
      tailcat_derp_tests
      tailcat_rendezvous_tests
      tailcat_wireguard_tests
      tailcat_wireguard_derp_tests
      tailcat_data_plane_tests
      tailcat_host_tcp_tests
    )
    foreach(test_target IN LISTS TAILCAT_TEST_TARGETS)
      if(MSVC)
        target_compile_options(${test_target} PRIVATE /UNDEBUG)
      else()
        target_compile_options(${test_target} PRIVATE -UNDEBUG)
      endif()
    endforeach()
  endif()
endif()
