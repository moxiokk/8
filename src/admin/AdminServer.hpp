#pragma once

#include "core/ServerCore.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <thread>

namespace webserver::admin {

class AdminApi;
class AuthService;
class AdminListener;

}

namespace webserver::config {

class ConfigService;

}

namespace webserver::logging {
class LogManager;
}

namespace webserver::admin {

class AdminServer final {
public:
    AdminServer(
        config::ConfigService& config_service,
        AuthService& auth_service,
        std::filesystem::path static_root,
        std::uint16_t port = 3312,
        std::shared_ptr<logging::LogManager> logger = {},
        std::function<std::vector<core::ListenerStatus>()> listener_status_provider = {});
    ~AdminServer();

    AdminServer(const AdminServer&) = delete;
    AdminServer& operator=(const AdminServer&) = delete;

    void start();
    void stop();
    void wait();

    [[nodiscard]] boost::asio::io_context& io_context() noexcept;
    [[nodiscard]] boost::asio::ip::tcp::endpoint local_endpoint() const;

private:
    void run_worker() noexcept;

    boost::asio::io_context io_context_{1};
    std::shared_ptr<logging::LogManager> logger_;
    std::shared_ptr<AdminApi> api_;
    std::shared_ptr<AdminListener> listener_;
    std::thread worker_;
    std::atomic_bool started_{false};
    std::atomic_bool stopping_{false};
};

} // namespace webserver::admin
