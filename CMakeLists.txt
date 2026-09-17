cmake_minimum_required(VERSION 3.24)

set(TAILCAT_VERSION "0.1.0" CACHE STRING "Tailcat semantic version")
string(REGEX MATCH "^[0-9]+\.[0-9]+\.[0-9]+" TAILCAT_PROJECT_VERSION "${TAILCAT_VERSION}")
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
FetchContent_Declare(tailcat_sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
  GIT_SHALLOW FALSE)
FetchContent_MakeAvailable(tailcat_sodium)

FetchContent_Declare(tailcat_lwip
  GIT_REPOSITORY https://github.com/lwip-tcpip/lwip.git
  GIT_TAG 77dcd25a72509eb83f72b033d219b1d40cd8eb95
  GIT_SHALLOW FALSE
  SOURCE_SUBDIR _tailcat_source_only)
FetchContent_MakeAvailable(tailcat_lwip)

set(LWIP_DIR ${tailcat_lwip_SOURCE_DIR})
set(LWIP_EXCLUDE_SLIPIF TRUE)
include(${LWIP_DIR}/src/Filelists.cmake)
add_library(tailcat_lwip_stack STATIC ${lwipcore_SRCS} ${lwipcore6_SRCS} src/lwip_platform.cpp)
set_target_properties(tailcat_lwip_stack PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tailcat_lwip_stack PRIVATE c_std_11)
target_include_directories(tailcat_lwip_stack PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip_port
  ${LWIP_DIR}/src/include)
target_link_libraries(tailcat_lwip_stack PUBLIC sodium)

FetchContent_Declare(tailcat_wireguard_src
  GIT_REPOSITORY https://github.com/smartalock/wireguard-lwip.git
  GIT_TAG c54f20dbe76ac8b3411ad21e0ed7deea6f0cfd4d
  GIT_SHALLOW FALSE
  SOURCE_SUBDIR _tailcat_source_only)
FetchContent_MakeAvailable(tailcat_wireguard_src)

add_library(tailcat_wireguard STATIC
  ${tailcat_wireguard_src_SOURCE_DIR}/src/wireguard.c
  ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/blake2s.c
  ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/chacha20.c
  ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/chacha20poly1305.c
  ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/poly1305-donna.c
  ${tailcat_wireguard_src_SOURCE_DIR}/src/crypto/refc/x25519.c
  src/wireguard_crypto_port.c
  src/wireguard_platform.cpp)
set_target_properties(tailcat_wireguard PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_compile_features(tailcat_wireguard PRIVATE c_std_11 cxx_std_20)
target_include_directories(tailcat_wireguard PUBLIC
  ${tailcat_wireguard_src_SOURCE_DIR}/src
  ${tailcat_lwip_SOURCE_DIR}/src/include
  ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwip_port
  ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(tailcat_wireguard PUBLIC sodium)
if(MSVC)
  target_compile_options(tailcat_wireguard PRIVATE "/FI${CMAKE_CURRENT_SOURCE_DIR}/include/tailcat/wireguard_compat.h")
endif()

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(tailcat_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG c41152e62092c16cf4fc4625becacc3eb9d9319f
  GIT_SHALLOW FALSE)
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
  FetchContent_Declare(tailcat_curl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG c427e91ddea7c1d4b2f5c54ab4b6810f61483928
    GIT_SHALLOW FALSE)
  FetchContent_MakeAvailable(tailcat_curl)
endif()

set(WITH_GSSAPI OFF CACHE BOOL "" FORCE)
set(WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(WITH_SFTP ON CACHE BOOL "" FORCE)
set(WITH_SERVER ON CACHE BOOL "" FORCE)
set(WITH_PCAP OFF CACHE BOOL "" FORCE)
set(WITH_EXAMPLES OFF CACHE BOOL "" FORCE)
set(WITH_NACL OFF CACHE BOOL "" FORCE)
set(WITH_FIDO2 OFF CACHE BOOL "" FORCE)
set(WITH_PKCS11_URI OFF CACHE BOOL "" FORCE)
set(WITH_PKCS11_PROVIDER OFF CACHE BOOL "" FORCE)
set(WITH_SYMBOL_VERSIONING OFF CACHE BOOL "" FORCE)
set(WITH_EXEC OFF CACHE BOOL "" FORCE)
set(UNIT_TESTING OFF CACHE BOOL "" FORCE)
set(CLIENT_TESTING OFF CACHE BOOL "" FORCE)
set(SERVER_TESTING OFF CACHE BOOL "" FORCE)
set(GSSAPI_TESTING OFF CACHE BOOL "" FORCE)
set(WITH_BENCHMARKS OFF CACHE BOOL "" FORCE)
set(PICKY_DEVELOPER OFF CACHE BOOL "" FORCE)

if(WIN32)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  set(USE_STATIC_MBEDTLS_LIBRARY ON CACHE BOOL "" FORCE)
  set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "" FORCE)
  set(DISABLE_PACKAGE_CONFIG_AND_INSTALL ON CACHE BOOL "" FORCE)
  set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(tailcat_mbedtls
    GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
    GIT_TAG 068ff080b369adfac81509f9b57b2afabaf82dc5
    GIT_SHALLOW FALSE)
  FetchContent_MakeAvailable(tailcat_mbedtls)
  set(WITH_MBEDTLS ON CACHE BOOL "" FORCE)
  set(MBEDTLS_INCLUDE_DIR "${tailcat_mbedtls_SOURCE_DIR}/include" CACHE PATH "" FORCE)
  set(MBEDTLS_SSL_LIBRARY mbedtls CACHE STRING "" FORCE)
  set(MBEDTLS_CRYPTO_LIBRARY mbedcrypto CACHE STRING "" FORCE)
  set(MBEDTLS_X509_LIBRARY mbedx509 CACHE STRING "" FORCE)
else()
  set(WITH_MBEDTLS OFF CACHE BOOL "" FORCE)
endif()

FetchContent_Declare(tailcat_libssh
  GIT_REPOSITORY https://github.com/libssh/libssh-mirror.git
  GIT_TAG 07430deb9b97b751ec5ea5a7fc307f40bf042e0a
  GIT_SHALLOW FALSE)
FetchContent_GetProperties(tailcat_libssh)
if(NOT tailcat_libssh_POPULATED)
  FetchContent_Populate(tailcat_libssh)
  set(CMAKE_SKIP_INSTALL_RULES TRUE)
  add_subdirectory(${tailcat_libssh_SOURCE_DIR} ${tailcat_libssh_BINARY_DIR} EXCLUDE_FROM_ALL)
  set(CMAKE_SKIP_INSTALL_RULES FALSE)
endif()

add_library(tailcat_core STATIC
  src/address_resolver.cpp
  src/cli.cpp
  src/embedded_ssh.cpp
  src/extra_commands.cpp
  src/forward_command.cpp
  src/socks_command.cpp
  src/ssh_authorized_keys.cpp
  src/ssh_command.cpp
  src/platform.cpp
  src/protocol.cpp
  src/ip.cpp
  src/crypto.cpp
  src/saved_key.cpp
  src/derp.cpp
  src/derp_http.cpp
  src/derp_map.cpp
  src/rendezvous.cpp
  src/wireguard_engine.cpp
  src/wireguard_derp.cpp
  src/lwip_stack.cpp
  src/lwip_udp.cpp
  src/data_plane.cpp
  src/host_tcp.cpp
  src/port_forward.cpp
  src/local_forward.cpp)
target_include_directories(tailcat_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(tailcat_core PUBLIC cxx_std_20)
target_compile_definitions(tailcat_core PRIVATE TAILCAT_VERSION="${TAILCAT_VERSION}")
target_link_libraries(tailcat_core PUBLIC sodium CURL::libcurl nlohmann_json::nlohmann_json tailcat_wireguard tailcat_lwip_stack ssh::ssh)
if(UNIX AND NOT APPLE)
  target_link_libraries(tailcat_core PUBLIC util)
endif()

if(MSVC)
  target_compile_options(tailcat_core PRIVATE /W4 /permissive-)
else()
  target_compile_options(tailcat_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
endif()

if(WIN32)
  target_compile_definitions(tailcat_core PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_link_libraries(tailcat_core PUBLIC ws2_32 shell32 dnsapi)
else()
  target_link_libraries(tailcat_core PUBLIC resolv)
endif()

add_executable(tailcat src/main.cpp)
target_link_libraries(tailcat PRIVATE tailcat_core)
if(MINGW)
  target_link_options(tailcat PRIVATE -static -static-libgcc -static-libstdc++)
endif()
install(TARGETS tailcat RUNTIME DESTINATION bin)

if(TAILCAT_BUILD_TESTS)
  include(CTest)
  if(BUILD_TESTING)
    add_executable(tailcat_tests tests/cli_test.cpp)
    target_link_libraries(tailcat_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_cli COMMAND tailcat_tests)

    add_executable(tailcat_address_resolver_tests tests/address_resolver_test.cpp)
    target_link_libraries(tailcat_address_resolver_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_address_resolver COMMAND tailcat_address_resolver_tests)

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

    add_executable(tailcat_lwip_udp_tests tests/lwip_udp_test.cpp)
    target_link_libraries(tailcat_lwip_udp_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_lwip_udp COMMAND tailcat_lwip_udp_tests)

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

    add_executable(tailcat_ssh_command_tests tests/ssh_command_test.cpp)
    target_link_libraries(tailcat_ssh_command_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_ssh_command COMMAND tailcat_ssh_command_tests)

    add_executable(tailcat_ssh_authorized_keys_tests tests/ssh_authorized_keys_test.cpp)
    target_link_libraries(tailcat_ssh_authorized_keys_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_ssh_authorized_keys COMMAND tailcat_ssh_authorized_keys_tests)

    add_executable(tailcat_saved_key_tests tests/saved_key_test.cpp)
    target_link_libraries(tailcat_saved_key_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_saved_key COMMAND tailcat_saved_key_tests)

    add_executable(tailcat_socks_command_tests tests/socks_command_test.cpp)
    target_link_libraries(tailcat_socks_command_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_socks_command COMMAND tailcat_socks_command_tests)

    set(TAILCAT_TEST_TARGETS
      tailcat_tests tailcat_address_resolver_tests tailcat_protocol_tests
      tailcat_ip_tests tailcat_lwip_tests tailcat_lwip_tcp_tests
      tailcat_lwip_udp_tests tailcat_derp_tests tailcat_rendezvous_tests
      tailcat_wireguard_tests tailcat_wireguard_derp_tests
      tailcat_data_plane_tests tailcat_host_tcp_tests tailcat_ssh_command_tests
      tailcat_ssh_authorized_keys_tests tailcat_saved_key_tests
      tailcat_socks_command_tests)
    foreach(test_target IN LISTS TAILCAT_TEST_TARGETS)
      if(MSVC)
        target_compile_options(${test_target} PRIVATE /UNDEBUG)
      else()
        target_compile_options(${test_target} PRIVATE -UNDEBUG)
      endif()
    endforeach()
  endif()
endif()
