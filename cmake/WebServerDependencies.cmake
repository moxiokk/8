option(
    WEBSERVER_ENABLE_DEPENDENCIES
    "Resolve and link the production dependency set"
    ON
)
option(
    WEBSERVER_VALIDATE_TARGET_GRAPH
    "Configure source and test targets without resolving production libraries"
    OFF
)

add_library(webserver_dependencies INTERFACE)
find_package(Threads REQUIRED)

if(WEBSERVER_VALIDATE_TARGET_GRAPH)
    message(STATUS "Validating the target graph without production dependencies")
    return()
endif()

if(NOT WEBSERVER_ENABLE_DEPENDENCIES)
    message(FATAL_ERROR "The HTTP server requires Boost.Asio and Boost.Beast; enable production dependencies")
endif()

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
endif()

find_package(Boost REQUIRED COMPONENTS system)
find_package(OpenSSL REQUIRED)
find_package(unofficial-sqlite3 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(re2 CONFIG REQUIRED)

target_link_libraries(webserver_dependencies INTERFACE
    Boost::system
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
    unofficial::sqlite3::sqlite3
    nlohmann_json::nlohmann_json
    re2::re2
)

target_compile_definitions(webserver_dependencies INTERFACE
    BOOST_ASIO_NO_DEPRECATED
)
