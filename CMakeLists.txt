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

option(TAILCAT_BUILD_TESTS "Build tailcat tests" ON)

include(FetchContent)

# DERP authentication uses the same X25519 + XSalsa20-Poly1305 NaCl box
# construction as tailscale/types/key. Build libsodium natively on every OS.
set(SODIUM_DISABLE_TESTS ON CACHE BOOL "" FORCE)
FetchContent_Declare(
  tailcat_sodium
  GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
  GIT_TAG e5b985ad0dd235d8c4307ea3a385b45e76c74c6a
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(tailcat_sodium)

# DERP map parsing only; header-only and pinned for reproducible builds.
set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)
FetchContent_Declare(
  tailcat_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG c41152e62092c16cf4fc4625becacc3eb9d9319f
  GIT_SHALLOW FALSE
)
FetchContent_MakeAvailable(tailcat_json)

# libcurl is used only as a verified TLS carrier in CONNECT_ONLY mode and for
# fetching the public DERP map. Tailcat itself writes the HTTP upgrade bytes
# and implements the DERP protocol.
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

add_library(tailcat_core
    src/cli.cpp
    src/platform.cpp
    src/protocol.cpp
    src/crypto.cpp
    src/derp.cpp
    src/derp_http.cpp
    src/derp_map.cpp
)
target_include_directories(tailcat_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(tailcat_core PUBLIC cxx_std_20)
target_compile_definitions(tailcat_core PRIVATE TAILCAT_VERSION="${TAILCAT_VERSION}")
target_link_libraries(tailcat_core PUBLIC sodium CURL::libcurl nlohmann_json::nlohmann_json)

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

    add_executable(tailcat_derp_tests tests/derp_test.cpp)
    target_link_libraries(tailcat_derp_tests PRIVATE tailcat_core)
    add_test(NAME tailcat_derp COMMAND tailcat_derp_tests)
  endif()
endif()
