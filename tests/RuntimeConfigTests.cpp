#include "config/RuntimeConfig.hpp"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

webserver::config::RuntimeSiteConfig site(
    std::string name,
    std::string domain,
    std::uint16_t listener_port,
    std::uint16_t backend_port) {
    webserver::config::RuntimeSiteConfig result;
    result.virtual_host = webserver::routing::VirtualHostConfig{
        std::move(name),
        {std::move(domain)},
        webserver::routing::BackendConfig{"127.0.0.1", backend_port}};
    result.http_enabled = true;
    result.http_port = listener_port;
    return result;
}

std::shared_ptr<const webserver::config::RuntimeConfig> snapshot(
    std::uint64_t revision,
    std::uint16_t backend_port) {
    webserver::config::RuntimeConfigSpec spec;
    spec.revision = revision;
    spec.sites = {
        site("primary", "example.test", 8080, backend_port),
        site("admin-origin", "other.test", 8081, 9099),
    };
    return webserver::config::build_runtime_config(std::move(spec));
}

void run_test() {
    auto first = snapshot(7, 8090);
    webserver::config::RuntimeConfigStore store{first};

    const auto first_router = first->router(webserver::config::ListenerProtocol::http, 8080);
    require(first_router != nullptr, "HTTP listener router was not built");
    require(
        first_router->find("example.test")->backend().port == 8090,
        "initial backend is incorrect");
    require(
        first->router(webserver::config::ListenerProtocol::http, 8081)->find("other.test") !=
            nullptr,
        "routing was not indexed by listener port");
    require(
        first->router(webserver::config::ListenerProtocol::http, 8080)->find("other.test") ==
            nullptr,
        "host leaked across listener ports");

    std::weak_ptr<const webserver::config::RuntimeConfig> old_lifetime = first;
    auto in_flight = store.load();
    first.reset();
    store.publish(snapshot(8, 8091));

    require(store.load()->revision() == 8, "atomic store did not publish the new revision");
    require(
        store.load()
                ->router(webserver::config::ListenerProtocol::http, 8080)
                ->find("example.test")
                ->backend()
                .port == 8091,
        "new request did not see the new backend");
    require(
        in_flight->router(webserver::config::ListenerProtocol::http, 8080)
                ->find("example.test")
                ->backend()
                .port == 8090,
        "in-flight request lost its old snapshot");
    require(!old_lifetime.expired(), "old snapshot was released while still in use");
    in_flight.reset();
    require(old_lifetime.expired(), "old snapshot was not released after its last user");

    bool conflicting_listener_rejected = false;
    try {
        auto http_site = site("http", "http.test", 8080, 9000);
        auto https_site = site("https", "https.test", 8080, 9001);
        https_site.http_enabled = false;
        https_site.https_enabled = true;
        https_site.https_port = 8080;
        webserver::config::RuntimeConfigSpec invalid;
        invalid.sites = {std::move(http_site), std::move(https_site)};
        static_cast<void>(webserver::config::build_runtime_config(std::move(invalid)));
    } catch (const std::invalid_argument&) {
        conflicting_listener_rejected = true;
    }
    require(conflicting_listener_rejected, "HTTP/HTTPS listener collision was accepted");

    bool missing_certificate_rejected = false;
    try {
        auto https_site = site("secure", "secure.test", 8443, 9443);
        https_site.http_enabled = false;
        https_site.https_enabled = true;
        https_site.https_port = 8443;
        webserver::config::RuntimeConfigSpec invalid;
        invalid.sites = {std::move(https_site)};
        static_cast<void>(webserver::config::build_runtime_config(std::move(invalid)));
    } catch (const std::invalid_argument&) {
        missing_certificate_rejected = true;
    }
    require(missing_certificate_rejected, "HTTPS runtime without a certificate was accepted");
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Runtime configuration snapshot tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Runtime configuration snapshot tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
