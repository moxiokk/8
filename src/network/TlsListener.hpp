#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/steady_timer.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

namespace webserver::http {
class TlsHttpSession;
}

namespace webserver::config {
class RuntimeConfigStore;
}

namespace webserver::logging {
class LogManager;
}

namespace webserver::network {

class ConnectionAdmission;

class TlsListener final : public std::enable_shared_from_this<TlsListener> {
public:
    using DrainedHandler = std::function<void(TlsListener*)>;

    TlsListener(
        boost::asio::io_context& io_context,
        const boost::asio::ip::tcp::endpoint& endpoint,
        std::shared_ptr<config::RuntimeConfigStore> runtime_store,
        std::shared_ptr<ConnectionAdmission> connection_admission,
        std::shared_ptr<logging::LogManager> logger = {});

    void start(std::uint64_t minimum_runtime_revision = 0);
    void retire(DrainedHandler on_drained) noexcept;
    void stop() noexcept;

    [[nodiscard]] boost::asio::ip::tcp::endpoint local_endpoint() const;

private:
    void accept_next();
    void on_accept(
        const boost::system::error_code& error,
        boost::asio::ip::tcp::socket socket);
    void schedule_accept_retry();
    void on_accept_retry(const boost::system::error_code& error);
    void notify_if_drained();
    void retire_on_executor(DrainedHandler on_drained);
    void stop_on_executor();
    void emergency_close_noexcept(bool stopping) noexcept;
    void recover_accept_noexcept() noexcept;

    template <typename Method>
    auto guarded_handler(Method method) {
        return [self = shared_from_this(), method](auto&&... arguments) mutable noexcept {
            try {
                std::invoke(
                    method,
                    self.get(),
                    std::forward<decltype(arguments)>(arguments)...);
            } catch (...) {
                self->recover_accept_noexcept();
            }
        };
    }

    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    boost::asio::steady_timer accept_retry_timer_;
    boost::asio::ip::tcp::endpoint endpoint_;
    std::uint16_t listener_port_{};
    std::shared_ptr<std::atomic_bool> stopping_;
    std::shared_ptr<config::RuntimeConfigStore> runtime_store_;
    std::shared_ptr<ConnectionAdmission> connection_admission_;
    std::shared_ptr<logging::LogManager> logger_;
    std::unordered_map<http::TlsHttpSession*, std::shared_ptr<http::TlsHttpSession>> sessions_;
    DrainedHandler on_drained_;
    std::chrono::milliseconds accept_retry_delay_{10};
    std::atomic<std::uint64_t> minimum_runtime_revision_{0};
    std::atomic_bool retired_{false};
};

} // namespace webserver::network
