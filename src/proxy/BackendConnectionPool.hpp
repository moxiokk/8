#pragma once

#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/tcp_stream.hpp>

#include <chrono>
#include <cstddef>
#include <condition_variable>
#include <list>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <variant>

namespace webserver::proxy {

using BackendPlainStream = boost::beast::tcp_stream;
using BackendTlsStream = boost::asio::ssl::stream<BackendPlainStream>;
using BackendStream = std::variant<BackendPlainStream, BackendTlsStream>;

// Shared for the lifetime of pooled outbound TLS streams.
[[nodiscard]] boost::asio::ssl::context& outbound_tls_context();

class BackendConnectionPool final {
public:
    static BackendConnectionPool& instance();

    [[nodiscard]] std::optional<BackendStream> acquire(
        const std::string& pool_key,
        std::chrono::seconds idle_ttl);
    void release(
        std::string pool_key,
        BackendStream stream,
        std::size_t maximum_idle,
        std::chrono::seconds idle_ttl);
    void clear();

private:
    BackendConnectionPool();
    ~BackendConnectionPool();
    BackendConnectionPool(const BackendConnectionPool&) = delete;
    BackendConnectionPool& operator=(const BackendConnectionPool&) = delete;

    struct IdleConnection final {
        BackendStream stream;
        std::chrono::steady_clock::time_point released_at;
        std::chrono::steady_clock::time_point expires_at;
    };

    void run_reaper() noexcept;

    std::mutex mutex_;
    std::condition_variable reaper_wakeup_;
    std::unordered_map<std::string, std::list<IdleConnection>> idle_;
    std::optional<std::chrono::steady_clock::time_point> next_expiration_;
    bool stopping_{};
    std::thread reaper_;
};

} // namespace webserver::proxy
