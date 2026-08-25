#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace webserver::core {

struct ConnectionInfo final {
    std::uint64_t id{};
    std::string protocol;
    std::string source_address;
    std::int64_t connected_at_unix_ms{};
    std::uint64_t connected_seconds{};
    std::string status;
    std::string method;
    std::string url;
    std::string referer;
};

class ConnectionRegistry final {
public:
    static ConnectionRegistry& instance();

    [[nodiscard]] std::uint64_t add(
        std::string protocol,
        std::string source_address,
        std::string status);
    void update_request(
        std::uint64_t id,
        std::string_view method,
        std::string_view url,
        std::string_view referer,
        std::string_view status);
    void update_status(std::uint64_t id, std::string_view status);
    void remove(std::uint64_t id);
    [[nodiscard]] std::vector<ConnectionInfo> snapshot(
        std::size_t limit = 5000) const;
    [[nodiscard]] std::size_t size() const;
    void clear();

private:
    struct StoredConnection final {
        ConnectionInfo info;
        std::chrono::steady_clock::time_point connected_at;
    };

    ConnectionRegistry() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::uint64_t, StoredConnection> connections_;
    std::uint64_t next_id_{1};
};

struct HttpRequestInfo final {
    std::uint64_t id{};
    std::int64_t site_id{};
    std::string site_name;
    std::string host;
    std::string protocol;
    std::string client_ip;
    std::int64_t connected_at_unix_ms{};
    std::uint64_t connected_seconds{};
    std::string status;
    std::string method;
    std::string url;
    std::string referer;
};

class HttpRequestRegistry final {
public:
    static HttpRequestRegistry& instance();

    [[nodiscard]] std::uint64_t add(
        std::string protocol,
        std::string client_ip,
        std::string_view method,
        std::string_view url,
        std::string_view referer,
        std::string_view host,
        std::string_view status);
    void update_site(
        std::uint64_t id,
        std::int64_t site_id,
        std::string_view site_name,
        std::string_view host,
        std::string_view status);
    void update_status(std::uint64_t id, std::string_view status);
    void remove(std::uint64_t id);
    [[nodiscard]] std::vector<HttpRequestInfo> snapshot(
        std::optional<std::int64_t> site_id = std::nullopt,
        std::size_t limit = 5000) const;
    [[nodiscard]] std::size_t size(
        std::optional<std::int64_t> site_id = std::nullopt) const;
    void clear();

private:
    struct StoredRequest final {
        HttpRequestInfo info;
        std::chrono::steady_clock::time_point connected_at;
    };

    HttpRequestRegistry() = default;
    mutable std::mutex mutex_;
    std::unordered_map<std::uint64_t, StoredRequest> requests_;
    std::uint64_t next_id_{1};
};

} // namespace webserver::core
