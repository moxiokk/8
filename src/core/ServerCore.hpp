#pragma once

#include "config/RuntimeConfig.hpp"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <string>
#include <thread>
#include <vector>

namespace webserver::network {
class ConnectionAdmission;
class HttpListener;
class TlsListener;
}

namespace webserver::logging {
class LogManager;
}

namespace webserver::core {

struct ServerOptions final {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{80};
    std::optional<std::uint16_t> https_port;
    std::size_t worker_threads{0};
    std::size_t maximum_connections{16'384};
    std::vector<routing::VirtualHostConfig> virtual_hosts{routing::default_virtual_hosts()};
    std::vector<tls::TlsCertificateConfig> tls_certificates;
    bool reject_unknown_sni{true};
    std::uint64_t config_revision{1};
    std::optional<config::RuntimeConfigSpec> runtime_config;
    std::shared_ptr<logging::LogManager> logger;
};

struct ListenerStatus final {
    std::string protocol;
    std::string address;
    std::uint16_t configured_port{};
    std::uint16_t bound_port{};
    std::size_t site_count{};
    std::string status;
};

class ServerCore final {
public:
    explicit ServerCore(ServerOptions options = {});
    ~ServerCore();

    ServerCore(const ServerCore&) = delete;
    ServerCore& operator=(const ServerCore&) = delete;
    ServerCore(ServerCore&&) = delete;
    ServerCore& operator=(ServerCore&&) = delete;

    void start();
    [[nodiscard]] std::function<void()> prepare_reload(config::RuntimeConfigSpec spec);
    void reload(config::RuntimeConfigSpec spec);
    void stop();
    void wait();

    [[nodiscard]] boost::asio::io_context& io_context() noexcept;
    [[nodiscard]] boost::asio::ip::tcp::endpoint local_endpoint() const;
    [[nodiscard]] boost::asio::ip::tcp::endpoint http_local_endpoint(
        std::uint16_t configured_port) const;
    [[nodiscard]] std::optional<boost::asio::ip::tcp::endpoint> tls_local_endpoint() const;
    [[nodiscard]] std::optional<boost::asio::ip::tcp::endpoint> tls_local_endpoint(
        std::uint16_t configured_port) const;
    [[nodiscard]] std::size_t worker_count() const noexcept;
    [[nodiscard]] std::size_t active_connection_count() const noexcept;
    [[nodiscard]] std::size_t maximum_connection_count() const noexcept;
    [[nodiscard]] std::uint64_t rejected_connection_count() const noexcept;
    [[nodiscard]] std::size_t retired_listener_count() const;
    [[nodiscard]] std::uint64_t runtime_revision() const noexcept;
    [[nodiscard]] std::vector<ListenerStatus> listener_statuses() const;

private:
    void run_worker() noexcept;

    ServerOptions options_;
    boost::asio::io_context io_context_;
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> work_guard_;
    std::shared_ptr<config::RuntimeConfigStore> runtime_store_;
    std::shared_ptr<network::ConnectionAdmission> connection_admission_;
    std::unordered_map<std::uint16_t, std::shared_ptr<network::HttpListener>> http_listeners_;
    std::unordered_map<std::uint16_t, std::shared_ptr<network::TlsListener>> tls_listeners_;
    std::vector<std::shared_ptr<network::HttpListener>> retired_http_listeners_;
    std::vector<std::shared_ptr<network::TlsListener>> retired_tls_listeners_;
    std::vector<std::thread> workers_;
    mutable std::mutex control_mutex_;
    std::atomic_bool started_{false};
    std::atomic_bool stopping_{false};
};

} // namespace webserver::core
