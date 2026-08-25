#include "network/TlsListener.hpp"

#include "config/RuntimeConfig.hpp"
#include "http/TlsHttpSession.hpp"
#include "logging/LogManager.hpp"
#include "network/ConnectionAdmission.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/strand.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <string>
#include <utility>

namespace webserver::network {
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

TlsListener::TlsListener(
    asio::io_context& io_context,
    const tcp::endpoint& endpoint,
    std::shared_ptr<config::RuntimeConfigStore> runtime_store,
    std::shared_ptr<ConnectionAdmission> connection_admission,
    std::shared_ptr<logging::LogManager> logger)
    : io_context_(io_context),
      acceptor_(asio::make_strand(io_context)),
      accept_retry_timer_(acceptor_.get_executor()),
      listener_port_(endpoint.port()),
      stopping_(std::make_shared<std::atomic_bool>(false)),
      runtime_store_(std::move(runtime_store)),
      connection_admission_(std::move(connection_admission)),
      logger_(std::move(logger)) {
    acceptor_.open(endpoint.protocol());
    acceptor_.set_option(asio::socket_base::reuse_address{true});
    acceptor_.bind(endpoint);
    acceptor_.listen(asio::socket_base::max_listen_connections);
    endpoint_ = acceptor_.local_endpoint();
}

void TlsListener::start(std::uint64_t minimum_runtime_revision) {
    minimum_runtime_revision_.store(minimum_runtime_revision, std::memory_order_release);
    accept_next();
}

void TlsListener::retire(DrainedHandler on_drained) noexcept {
    try {
        asio::dispatch(acceptor_.get_executor(), [
            self = shared_from_this(), on_drained = std::move(on_drained)]() mutable noexcept {
            try {
                self->retire_on_executor(std::move(on_drained));
            } catch (...) {
                self->emergency_close_noexcept(false);
            }
        });
    } catch (...) {
        emergency_close_noexcept(false);
    }
}

void TlsListener::stop() noexcept {
    stopping_->store(true);
    try {
        asio::dispatch(acceptor_.get_executor(), [self = shared_from_this()]() noexcept {
            try {
                self->stop_on_executor();
            } catch (...) {
                self->emergency_close_noexcept(true);
            }
        });
    } catch (...) {
        emergency_close_noexcept(true);
    }
}

tcp::endpoint TlsListener::local_endpoint() const {
    return endpoint_;
}

void TlsListener::accept_next() {
    if (retired_.load() || stopping_->load() || !acceptor_.is_open()) {
        notify_if_drained();
        return;
    }
    acceptor_.async_accept(
        asio::make_strand(io_context_),
        guarded_handler(&TlsListener::on_accept));
}

void TlsListener::on_accept(
    const boost::system::error_code& error,
    tcp::socket socket) {
    if (error) {
        if (error != asio::error::operation_aborted &&
            acceptor_.is_open() &&
            !stopping_->load()) {
            if (logger_) {
                try {
                    logger_->log_error(
                        logging::ErrorSeverity::error,
                        "tls_listener",
                        "accept failed on port " + std::to_string(listener_port_) +
                            ": " + error.message());
                } catch (...) {
                }
            }
            schedule_accept_retry();
        }
        notify_if_drained();
        return;
    }

    accept_retry_delay_ = std::chrono::milliseconds{10};
    if (stopping_->load() || retired_.load()) {
        boost::system::error_code ignored;
        socket.close(ignored);
        notify_if_drained();
        return;
    }
    if (runtime_store_->load()->revision() <
        minimum_runtime_revision_.load(std::memory_order_acquire)) {
        boost::system::error_code ignored;
        socket.close(ignored);
        schedule_accept_retry();
        return;
    }

    try {
        auto permit = connection_admission_->try_acquire();
        if (!permit) {
            boost::system::error_code ignored;
            socket.close(ignored);
            schedule_accept_retry();
            return;
        }
        const auto runtime = runtime_store_->load();
        const auto tls_contexts = runtime->tls_contexts();
        if (!tls_contexts) {
            boost::system::error_code ignored;
            socket.close(ignored);
            accept_next();
            return;
        }

        const auto session = std::make_shared<http::TlsHttpSession>(
            std::move(socket),
            stopping_,
            runtime_store_,
            listener_port_,
            tls_contexts,
            logger_,
            [weak_listener = weak_from_this(), permit = std::move(permit)](
                http::TlsHttpSession* closed_session) {
                static_cast<void>(permit);
                if (const auto listener = weak_listener.lock()) {
                    asio::dispatch(
                        listener->acceptor_.get_executor(),
                        [listener, closed_session] {
                            listener->sessions_.erase(closed_session);
                            listener->notify_if_drained();
                        });
                }
            });
        sessions_.emplace(session.get(), session);
        try {
            session->start();
        } catch (...) {
            sessions_.erase(session.get());
            throw;
        }
    } catch (const std::exception& exception) {
        if (logger_) {
            try {
                logger_->log_error(
                    logging::ErrorSeverity::critical,
                    "tls_listener",
                    "could not create a TLS session: " + std::string{exception.what()});
            } catch (...) {
            }
        }
        schedule_accept_retry();
        return;
    } catch (...) {
        schedule_accept_retry();
        return;
    }
    try {
        accept_next();
    } catch (...) {
        schedule_accept_retry();
    }
}

void TlsListener::schedule_accept_retry() {
    if (retired_.load() || stopping_->load() || !acceptor_.is_open()) {
        notify_if_drained();
        return;
    }
    accept_retry_timer_.expires_after(accept_retry_delay_);
    accept_retry_delay_ = std::min(
        accept_retry_delay_ * 2, std::chrono::milliseconds{1000});
    accept_retry_timer_.async_wait(
        guarded_handler(&TlsListener::on_accept_retry));
}

void TlsListener::on_accept_retry(const boost::system::error_code& error) {
    if (!error) accept_next();
}

void TlsListener::notify_if_drained() {
    if (!retired_.load() || !sessions_.empty() || !on_drained_) return;
    auto on_drained = std::move(on_drained_);
    on_drained(this);
}

void TlsListener::retire_on_executor(DrainedHandler on_drained) {
    retired_.store(true);
    on_drained_ = std::move(on_drained);
    try {
        accept_retry_timer_.cancel();
    } catch (...) {
    }
    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);
    notify_if_drained();
}

void TlsListener::stop_on_executor() {
    try {
        accept_retry_timer_.cancel();
    } catch (...) {
    }
    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);
    for (const auto& session_entry : sessions_) {
        session_entry.second->stop();
    }
}

void TlsListener::emergency_close_noexcept(bool stopping) noexcept {
    if (stopping) stopping_->store(true);
    else retired_.store(true);
    try {
        accept_retry_timer_.cancel();
    } catch (...) {
    }
    boost::system::error_code ignored;
    acceptor_.cancel(ignored);
    acceptor_.close(ignored);
}

void TlsListener::recover_accept_noexcept() noexcept {
    try {
        schedule_accept_retry();
    } catch (...) {
        emergency_close_noexcept(false);
    }
}

} // namespace webserver::network
