#include "core/ConnectionRegistry.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

} // namespace

int main() {
    try {
        auto& registry = webserver::core::ConnectionRegistry::instance();
        registry.clear();
        const auto id = registry.add("HTTP", "192.0.2.10:51000", "Connected");
        registry.update_request(
            id, "GET", "/video/a.mp4?part=1", "https://example.test/", "Proxying");
        auto entries = registry.snapshot();
        require(entries.size() == 1 && registry.size() == 1,
                "registered connection was not returned");
        require(entries.front().source_address == "192.0.2.10:51000",
                "source address was not preserved");
        require(entries.front().method == "GET" &&
                    entries.front().url == "/video/a.mp4?part=1" &&
                    entries.front().referer == "https://example.test/" &&
                    entries.front().status == "Proxying",
                "request fields were not updated atomically");

        std::vector<std::thread> workers;
        for (int worker = 0; worker < 8; ++worker) {
            workers.emplace_back([&registry, worker] {
                for (int index = 0; index < 100; ++index) {
                    const auto connection = registry.add(
                        "HTTPS",
                        "198.51.100." + std::to_string(worker + 1) + ':' +
                            std::to_string(52000 + index),
                        "TLS Handshake");
                    registry.update_status(connection, "Waiting for Request");
                    registry.remove(connection);
                }
            });
        }
        for (auto& worker : workers) worker.join();
        require(registry.snapshot().size() == 1,
                "concurrent add/update/remove left stale connections");

        registry.remove(id);
        require(registry.snapshot().empty(), "removed connection remained visible");
        registry.clear();

        auto& http_registry = webserver::core::HttpRequestRegistry::instance();
        http_registry.clear();
        const auto first_request = http_registry.add(
            "HTTP",
            "192.0.2.20",
            "POST",
            "/upload?part=1",
            "https://portal.test/",
            "media.test",
            "Routing");
        http_registry.update_site(
            first_request, 41, "Media", "media.test", "Policy Check");
        http_registry.update_status(first_request, "Proxying");
        const auto second_request = http_registry.add(
            "HTTPS", "198.51.100.8", "GET", "/health", {}, "api.test", "Routing");
        http_registry.update_site(second_request, 42, "API", "api.test", "Proxying");

        const auto all_requests = http_registry.snapshot();
        const auto media_requests = http_registry.snapshot(41);
        require(all_requests.size() == 2 && http_registry.size() == 2,
                "HTTP request registry did not return all active requests");
        require(media_requests.size() == 1 && http_registry.size(41) == 1 &&
                    media_requests.front().client_ip == "192.0.2.20" &&
                    media_requests.front().site_name == "Media" &&
                    media_requests.front().method == "POST" &&
                    media_requests.front().url == "/upload?part=1" &&
                    media_requests.front().referer == "https://portal.test/" &&
                    media_requests.front().status == "Proxying",
                "HTTP request fields or per-site filtering are incorrect");
        http_registry.remove(first_request);
        http_registry.remove(second_request);
        require(http_registry.snapshot().empty(),
                "completed HTTP requests remained visible");
        http_registry.clear();
        std::cout << "connection registry tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "connection registry tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
