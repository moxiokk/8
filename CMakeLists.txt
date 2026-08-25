cmake_minimum_required(VERSION 3.25)

project(
    WebServer
    VERSION 1.0.0
    DESCRIPTION "Lightweight Windows origin web server and reverse proxy"
    LANGUAGES CXX
)

include(CTest)
include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(WebServerDependencies)
include(WebServerWarnings)

if(NOT CMAKE_CONFIGURATION_TYPES AND NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS Debug Release RelWithDebInfo MinSizeRel)
endif()

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/app/BuildInfo.hpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/BuildInfo.hpp"
    @ONLY
)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/dist/index.html")
    message(FATAL_ERROR "Built Vue admin assets are missing; run npm ci and npm run build in admin-ui")
endif()

find_program(WEBSERVER_NPM_EXECUTABLE NAMES npm.cmd npm)
if(WEBSERVER_NPM_EXECUTABLE)
    add_custom_target(AdminUiBuild
        COMMAND "${WEBSERVER_NPM_EXECUTABLE}" ci
        COMMAND "${WEBSERVER_NPM_EXECUTABLE}" run build
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/admin-ui"
        COMMENT "Type-checking and building the Vue admin panel"
    )
endif()

add_library(webserver_logging STATIC
    src/logging/LogManager.cpp
    src/logging/LogManager.hpp
)
target_compile_features(webserver_logging PUBLIC cxx_std_20)
set_target_properties(webserver_logging PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(webserver_logging PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(webserver_logging PUBLIC Threads::Threads)
webserver_enable_warnings(webserver_logging)

add_library(webserver_core STATIC
    src/admin/AdminApi.cpp
    src/admin/AdminApi.hpp
    src/admin/AdminServer.cpp
    src/admin/AdminServer.hpp
    src/admin/AuthService.cpp
    src/admin/AuthService.hpp
    src/config/ConfigService.cpp
    src/config/ConfigService.hpp
    src/config/RuntimeConfig.cpp
    src/config/RuntimeConfig.hpp
    src/core/ServerCore.cpp
    src/core/ServerCore.hpp
    src/core/ConnectionRegistry.cpp
    src/core/ConnectionRegistry.hpp
    src/database/ConfigRepository.cpp
    src/database/ConfigRepository.hpp
    src/database/Database.cpp
    src/database/Database.hpp
    src/http/HttpSession.cpp
    src/http/HttpSession.hpp
    src/http/RequestDispatcher.cpp
    src/http/RequestDispatcher.hpp
    src/http/TlsHttpSession.cpp
    src/http/TlsHttpSession.hpp
    src/network/HttpListener.cpp
    src/network/HttpListener.hpp
    src/network/ClientIpResolver.cpp
    src/network/ClientIpResolver.hpp
    src/network/ConnectionAdmission.cpp
    src/network/ConnectionAdmission.hpp
    src/network/TlsListener.cpp
    src/network/TlsListener.hpp
    src/policy/RequestPolicy.cpp
    src/policy/RequestPolicy.hpp
    src/policy/UrlAuthenticator.cpp
    src/policy/UrlAuthenticator.hpp
    src/proxy/BackendConnectionPool.cpp
    src/proxy/BackendConnectionPool.hpp
    src/proxy/BackendProbe.cpp
    src/proxy/BackendProbe.hpp
    src/proxy/BackendConcurrencyLimiter.cpp
    src/proxy/BackendConcurrencyLimiter.hpp
    src/proxy/ProxyTransaction.hpp
    src/routing/HostNormalizer.cpp
    src/routing/HostNormalizer.hpp
    src/routing/VirtualHostRouter.cpp
    src/routing/VirtualHostRouter.hpp
    src/tls/TlsContextManager.cpp
    src/tls/TlsContextManager.hpp
)

target_compile_features(webserver_core PUBLIC cxx_std_20)
set_target_properties(webserver_core PROPERTIES CXX_EXTENSIONS OFF)
target_include_directories(webserver_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)
target_link_libraries(webserver_core PUBLIC webserver_logging webserver_dependencies)
webserver_enable_warnings(webserver_core)

add_executable(WebServer
    src/main.cpp
    src/app/Application.cpp
    src/app/Application.hpp
    src/service/WindowsService.cpp
    src/service/WindowsService.hpp
    "${CMAKE_CURRENT_BINARY_DIR}/generated/BuildInfo.hpp"
)

target_compile_features(WebServer PRIVATE cxx_std_20)
set_target_properties(WebServer PROPERTIES CXX_EXTENSIONS OFF OUTPUT_NAME "WebServer")
target_include_directories(WebServer PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_link_libraries(WebServer PRIVATE webserver_core)
webserver_enable_warnings(WebServer)

add_custom_command(TARGET WebServer POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/certs"
        "$<TARGET_FILE_DIR:WebServer>/certs"
    COMMENT "Copying development TLS certificate"
)

add_custom_command(TARGET WebServer POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/dist"
        "$<TARGET_FILE_DIR:WebServer>/admin-ui"
    COMMENT "Copying Vue admin panel"
)

if(WIN32)
    target_link_libraries(WebServer PRIVATE Advapi32)
    target_link_libraries(webserver_core PUBLIC Crypt32)

    target_compile_definitions(WebServer PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
        _WIN32_WINNT=0x0603
        WINVER=0x0603
    )

    target_compile_definitions(webserver_core PUBLIC
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        UNICODE
        _UNICODE
        _WIN32_WINNT=0x0603
        WINVER=0x0603
    )
endif()

install(TARGETS WebServer
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/certs/"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/certs"
)
install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/dist/"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/admin-ui"
)
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/install-service.ps1"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/uninstall-service.ps1"
    "${CMAKE_CURRENT_SOURCE_DIR}/scripts/run-soak-tests.ps1"
    DESTINATION "${CMAKE_INSTALL_BINDIR}/scripts"
)

if(BUILD_TESTING)
    add_test(NAME WebServer.Version COMMAND WebServer --version)
    set_tests_properties(WebServer.Version PROPERTIES
        PASS_REGULAR_EXPRESSION "WebServer ${PROJECT_VERSION}"
    )

    add_executable(HttpServerIntegration tests/HttpServerIntegration.cpp)
    target_compile_features(HttpServerIntegration PRIVATE cxx_std_20)
    set_target_properties(HttpServerIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(HttpServerIntegration PRIVATE webserver_core)
    webserver_enable_warnings(HttpServerIntegration)

    add_executable(ClientIpResolverTests tests/ClientIpResolverTests.cpp)
    target_compile_features(ClientIpResolverTests PRIVATE cxx_std_20)
    set_target_properties(ClientIpResolverTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(ClientIpResolverTests PRIVATE webserver_core)
    webserver_enable_warnings(ClientIpResolverTests)
    add_test(NAME WebServer.ClientIpResolverTests COMMAND ClientIpResolverTests)

    add_executable(WebSocketIntegration tests/WebSocketIntegration.cpp)
    target_compile_features(WebSocketIntegration PRIVATE cxx_std_20)
    set_target_properties(WebSocketIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(WebSocketIntegration PRIVATE webserver_core)
    webserver_enable_warnings(WebSocketIntegration)
    add_test(
        NAME WebServer.WebSocketIntegration
        COMMAND WebSocketIntegration
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.key"
    )
    set_tests_properties(WebServer.WebSocketIntegration PROPERTIES TIMEOUT 15)

    add_executable(StreamingProxyIntegration tests/StreamingProxyIntegration.cpp)
    target_compile_features(StreamingProxyIntegration PRIVATE cxx_std_20)
    set_target_properties(StreamingProxyIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(StreamingProxyIntegration PRIVATE webserver_core)
    webserver_enable_warnings(StreamingProxyIntegration)
    add_test(NAME WebServer.StreamingProxyIntegration COMMAND StreamingProxyIntegration)
    set_tests_properties(WebServer.StreamingProxyIntegration PROPERTIES TIMEOUT 45)

    add_executable(BackendTlsProxyIntegration tests/BackendTlsProxyIntegration.cpp)
    target_compile_features(BackendTlsProxyIntegration PRIVATE cxx_std_20)
    set_target_properties(BackendTlsProxyIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(BackendTlsProxyIntegration PRIVATE webserver_core)
    webserver_enable_warnings(BackendTlsProxyIntegration)

    add_test(NAME WebServer.HttpIntegration COMMAND HttpServerIntegration)
    set_tests_properties(WebServer.HttpIntegration PROPERTIES TIMEOUT 15)

    add_executable(VirtualHostTests tests/VirtualHostTests.cpp)
    target_compile_features(VirtualHostTests PRIVATE cxx_std_20)
    set_target_properties(VirtualHostTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(VirtualHostTests PRIVATE webserver_core)
    webserver_enable_warnings(VirtualHostTests)

    add_test(NAME WebServer.VirtualHostTests COMMAND VirtualHostTests)

    add_executable(ConfigDatabaseTests tests/ConfigDatabaseTests.cpp)
    target_compile_features(ConfigDatabaseTests PRIVATE cxx_std_20)
    set_target_properties(ConfigDatabaseTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(ConfigDatabaseTests PRIVATE webserver_core)
    webserver_enable_warnings(ConfigDatabaseTests)

    add_test(
        NAME WebServer.ConfigDatabaseTests
        COMMAND ConfigDatabaseTests
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/example.com.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/example.com.key"
    )

    add_executable(AuthServiceTests tests/AuthServiceTests.cpp)
    target_compile_features(AuthServiceTests PRIVATE cxx_std_20)
    set_target_properties(AuthServiceTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(AuthServiceTests PRIVATE webserver_core)
    webserver_enable_warnings(AuthServiceTests)
    add_test(NAME WebServer.AuthServiceTests COMMAND AuthServiceTests)

    add_executable(RuntimeConfigTests tests/RuntimeConfigTests.cpp)
    target_compile_features(RuntimeConfigTests PRIVATE cxx_std_20)
    set_target_properties(RuntimeConfigTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(RuntimeConfigTests PRIVATE webserver_core)
    webserver_enable_warnings(RuntimeConfigTests)

    add_test(NAME WebServer.RuntimeConfigTests COMMAND RuntimeConfigTests)

    add_executable(BackendConcurrencyLimiterTests tests/BackendConcurrencyLimiterTests.cpp)
    target_compile_features(BackendConcurrencyLimiterTests PRIVATE cxx_std_20)
    set_target_properties(BackendConcurrencyLimiterTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(BackendConcurrencyLimiterTests PRIVATE webserver_core)
    webserver_enable_warnings(BackendConcurrencyLimiterTests)
    add_test(NAME WebServer.BackendConcurrencyLimiterTests COMMAND BackendConcurrencyLimiterTests)

    add_executable(BackendConnectionPoolTests tests/BackendConnectionPoolTests.cpp)
    target_compile_features(BackendConnectionPoolTests PRIVATE cxx_std_20)
    set_target_properties(BackendConnectionPoolTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(BackendConnectionPoolTests PRIVATE webserver_core)
    webserver_enable_warnings(BackendConnectionPoolTests)
    add_test(NAME WebServer.BackendConnectionPoolTests COMMAND BackendConnectionPoolTests)
    set_tests_properties(WebServer.BackendConnectionPoolTests PROPERTIES TIMEOUT 10)

    add_executable(ProxyTransactionMemoryTests tests/ProxyTransactionMemoryTests.cpp)
    target_compile_features(ProxyTransactionMemoryTests PRIVATE cxx_std_20)
    set_target_properties(ProxyTransactionMemoryTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(ProxyTransactionMemoryTests PRIVATE webserver_core)
    webserver_enable_warnings(ProxyTransactionMemoryTests)
    add_test(NAME WebServer.ProxyTransactionMemoryTests COMMAND ProxyTransactionMemoryTests)

    add_executable(
        ConnectionRegistryTests
        tests/ConnectionRegistryTests.cpp
        src/core/ConnectionRegistry.cpp
    )
    target_compile_features(ConnectionRegistryTests PRIVATE cxx_std_20)
    set_target_properties(ConnectionRegistryTests PROPERTIES CXX_EXTENSIONS OFF)
    target_include_directories(ConnectionRegistryTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(ConnectionRegistryTests PRIVATE Threads::Threads)
    webserver_enable_warnings(ConnectionRegistryTests)
    add_test(NAME WebServer.ConnectionRegistryTests COMMAND ConnectionRegistryTests)

    add_executable(ServerResilienceTests tests/ServerResilienceTests.cpp)
    target_compile_features(ServerResilienceTests PRIVATE cxx_std_20)
    set_target_properties(ServerResilienceTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(ServerResilienceTests PRIVATE webserver_core)
    webserver_enable_warnings(ServerResilienceTests)
    add_test(NAME WebServer.ServerResilienceTests COMMAND ServerResilienceTests)
    set_tests_properties(WebServer.ServerResilienceTests PROPERTIES TIMEOUT 15)

    add_executable(RequestPolicyTests tests/RequestPolicyTests.cpp)
    target_compile_features(RequestPolicyTests PRIVATE cxx_std_20)
    set_target_properties(RequestPolicyTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(RequestPolicyTests PRIVATE webserver_core)
    webserver_enable_warnings(RequestPolicyTests)

    add_test(NAME WebServer.RequestPolicyTests COMMAND RequestPolicyTests)

    add_executable(UrlAuthenticatorTests tests/UrlAuthenticatorTests.cpp)
    target_compile_features(UrlAuthenticatorTests PRIVATE cxx_std_20)
    set_target_properties(UrlAuthenticatorTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(UrlAuthenticatorTests PRIVATE webserver_core)
    webserver_enable_warnings(UrlAuthenticatorTests)

    add_test(NAME WebServer.UrlAuthenticatorTests COMMAND UrlAuthenticatorTests)

    add_executable(UrlAuthIntegration tests/UrlAuthIntegration.cpp)
    target_compile_features(UrlAuthIntegration PRIVATE cxx_std_20)
    set_target_properties(UrlAuthIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(UrlAuthIntegration PRIVATE webserver_core)
    webserver_enable_warnings(UrlAuthIntegration)

    add_test(NAME WebServer.UrlAuthIntegration COMMAND UrlAuthIntegration)
    set_tests_properties(WebServer.UrlAuthIntegration PROPERTIES TIMEOUT 15)

    add_executable(LoggingTests tests/LoggingTests.cpp)
    target_compile_features(LoggingTests PRIVATE cxx_std_20)
    set_target_properties(LoggingTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(LoggingTests PRIVATE webserver_logging)
    webserver_enable_warnings(LoggingTests)

    add_test(NAME WebServer.LoggingTests COMMAND LoggingTests)

    add_executable(
        WindowsServiceTests
        tests/WindowsServiceTests.cpp
        src/service/WindowsService.cpp
        src/service/WindowsService.hpp
    )
    target_compile_features(WindowsServiceTests PRIVATE cxx_std_20)
    set_target_properties(WindowsServiceTests PROPERTIES CXX_EXTENSIONS OFF)
    target_include_directories(WindowsServiceTests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    webserver_enable_warnings(WindowsServiceTests)
    if(WIN32)
        target_compile_definitions(WindowsServiceTests PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
            _WIN32_WINNT=0x0603
            WINVER=0x0603
        )
        target_link_libraries(WindowsServiceTests PRIVATE Advapi32)
    endif()

    add_test(NAME WebServer.WindowsServiceTests COMMAND WindowsServiceTests)

    add_executable(PolicyIntegration tests/PolicyIntegration.cpp)
    target_compile_features(PolicyIntegration PRIVATE cxx_std_20)
    set_target_properties(PolicyIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(PolicyIntegration PRIVATE webserver_core)
    webserver_enable_warnings(PolicyIntegration)

    add_test(NAME WebServer.PolicyIntegration COMMAND PolicyIntegration)
    set_tests_properties(WebServer.PolicyIntegration PROPERTIES TIMEOUT 20)

    add_executable(HotReloadIntegration tests/HotReloadIntegration.cpp)
    target_compile_features(HotReloadIntegration PRIVATE cxx_std_20)
    set_target_properties(HotReloadIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(HotReloadIntegration PRIVATE webserver_core)
    webserver_enable_warnings(HotReloadIntegration)

    add_test(NAME WebServer.HotReloadIntegration COMMAND HotReloadIntegration)
    set_tests_properties(WebServer.HotReloadIntegration PROPERTIES TIMEOUT 20)

    add_executable(StabilityIntegration tests/StabilityIntegration.cpp)
    target_compile_features(StabilityIntegration PRIVATE cxx_std_20)
    set_target_properties(StabilityIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(StabilityIntegration PRIVATE webserver_core)
    webserver_enable_warnings(StabilityIntegration)

    add_test(NAME WebServer.StabilityIntegration COMMAND StabilityIntegration)
    set_tests_properties(WebServer.StabilityIntegration PROPERTIES TIMEOUT 90)

    add_executable(AdminApiIntegration tests/AdminApiIntegration.cpp)
    target_compile_features(AdminApiIntegration PRIVATE cxx_std_20)
    set_target_properties(AdminApiIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(AdminApiIntegration PRIVATE webserver_core)
    webserver_enable_warnings(AdminApiIntegration)

    add_test(
        NAME WebServer.AdminApiIntegration
        COMMAND AdminApiIntegration
            "${CMAKE_CURRENT_SOURCE_DIR}/admin-ui/dist"
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/example.com.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/certs/example.com.key"
    )
    set_tests_properties(WebServer.AdminApiIntegration PROPERTIES TIMEOUT 30)

    set(WEBSERVER_TEST_CERTIFICATE_ARGUMENTS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.crt"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.key"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/b.test.crt"
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/b.test.key"
    )
    add_test(
        NAME WebServer.BackendTlsProxyIntegration
        COMMAND BackendTlsProxyIntegration ${WEBSERVER_TEST_CERTIFICATE_ARGUMENTS}
    )
    set_tests_properties(WebServer.BackendTlsProxyIntegration PROPERTIES TIMEOUT 20)

    add_executable(TlsContextTests tests/TlsContextTests.cpp)
    target_compile_features(TlsContextTests PRIVATE cxx_std_20)
    set_target_properties(TlsContextTests PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(TlsContextTests PRIVATE webserver_core)
    webserver_enable_warnings(TlsContextTests)

    add_test(
        NAME WebServer.TlsContextTests
        COMMAND TlsContextTests ${WEBSERVER_TEST_CERTIFICATE_ARGUMENTS}
    )

    add_executable(HttpsServerIntegration tests/HttpsServerIntegration.cpp)
    target_compile_features(HttpsServerIntegration PRIVATE cxx_std_20)
    set_target_properties(HttpsServerIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(HttpsServerIntegration PRIVATE webserver_core)
    webserver_enable_warnings(HttpsServerIntegration)

    add_test(
        NAME WebServer.HttpsIntegration
        COMMAND HttpsServerIntegration ${WEBSERVER_TEST_CERTIFICATE_ARGUMENTS}
    )
    set_tests_properties(WebServer.HttpsIntegration PROPERTIES TIMEOUT 20)

    add_executable(
        HttpRealtimeAndUploadLimitIntegration
        tests/HttpRealtimeAndUploadLimitIntegration.cpp
    )
    target_compile_features(HttpRealtimeAndUploadLimitIntegration PRIVATE cxx_std_20)
    set_target_properties(HttpRealtimeAndUploadLimitIntegration PROPERTIES CXX_EXTENSIONS OFF)
    target_link_libraries(HttpRealtimeAndUploadLimitIntegration PRIVATE webserver_core)
    webserver_enable_warnings(HttpRealtimeAndUploadLimitIntegration)
    add_test(
        NAME WebServer.HttpRealtimeAndUploadLimitIntegration
        COMMAND HttpRealtimeAndUploadLimitIntegration
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.crt"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/certs/a.test.key"
    )
    set_tests_properties(
        WebServer.HttpRealtimeAndUploadLimitIntegration PROPERTIES TIMEOUT 20)
endif()
