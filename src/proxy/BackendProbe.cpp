#include "proxy/BackendProbe.hpp"

#include "proxy/BackendConnectionPool.hpp"
#include "routing/HostNormalizer.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/system/errc.hpp>
#include <openssl/ssl.h>

#include <chrono>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace webserver::proxy {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
using tcp = asio::ip::tcp;

std::string tls_name(const routing::BackendConfig& backend) {
    if (!backend.tls_sni.empty()) return backend.tls_sni;
    if (!backend.host.empty()) {
        if (const auto normalized = routing::HostNormalizer::normalize_authority(backend.host)) {
            return *normalized;
        }
    }
    return backend.address;
}

class ProbeState final : public BackendProbeOperation,
                         public std::enable_shared_from_this<ProbeState> {
public:
    ProbeState(
        routing::BackendConfig backend,
        asio::any_io_executor executor,
        std::function<void(BackendProbeResult)> completion)
        : backend_(std::move(backend)),
          executor_(std::move(executor)),
          resolver_(executor_),
          timer_(executor_),
          completion_(std::move(completion)) {
        result_.protocol = backend_.protocol == routing::BackendProtocol::https ? "https" : "http";
    }

    void start() {
        started_ = std::chrono::steady_clock::now();
        timer_.expires_after(std::chrono::seconds{backend_.connect_timeout_seconds});
        timer_.async_wait(guarded_handler(&ProbeState::on_timeout));
        resolver_.async_resolve(
            backend_.address, std::to_string(backend_.port),
            guarded_handler(&ProbeState::on_resolved));
    }

    void cancel() override {
        try {
            asio::dispatch(executor_, guarded_handler(&ProbeState::cancel_on_executor));
        } catch (...) {
            abort_noexcept();
        }
    }

private:
    template <typename Method>
    auto guarded_handler(Method method) {
        return [self = shared_from_this(), method](auto&&... arguments) mutable noexcept {
            try {
                std::invoke(
                    method,
                    self.get(),
                    std::forward<decltype(arguments)>(arguments)...);
            } catch (...) {
                self->abort_noexcept();
            }
        };
    }

    template <typename Method>
    auto guarded_connect_handler(Method method) {
        // Keep the signature concrete so Beast selects its endpoint-sequence
        // async_connect overload (Boost 1.86+ rejects a generic handler here).
        auto handler = guarded_handler(method);
        return [handler = std::move(handler)](
                   const boost::system::error_code& error,
                   const tcp::endpoint& endpoint) mutable noexcept {
            handler(error, endpoint);
        };
    }

    void on_timeout(const boost::system::error_code& error) {
        if (!error && !finished_) {
            resolver_.cancel();
            finish(asio::error::timed_out);
        }
    }

    void cancel_on_executor() {
        finish(asio::error::operation_aborted);
    }

    void on_resolved(
        const boost::system::error_code& error,
        const tcp::resolver::results_type& endpoints) {
        if (finished_) return;
        if (error) return finish(error);
        if (backend_.protocol == routing::BackendProtocol::https) {
            tls_stream_.emplace(executor_, outbound_tls_context());
            const auto name = tls_name(backend_);
            boost::system::error_code address_error;
            static_cast<void>(asio::ip::make_address(name, address_error));
            if (address_error && SSL_set_tlsext_host_name(
                    tls_stream_->native_handle(), name.c_str()) != 1) {
                return finish(boost::system::errc::make_error_code(
                    boost::system::errc::invalid_argument));
            }
            if (backend_.tls_verify_certificate) {
                tls_stream_->set_verify_mode(asio::ssl::verify_peer);
                tls_stream_->set_verify_callback(asio::ssl::host_name_verification(name));
            } else {
                tls_stream_->set_verify_mode(asio::ssl::verify_none);
            }
            beast::get_lowest_layer(*tls_stream_).async_connect(
                endpoints,
                guarded_connect_handler(&ProbeState::on_tls_connected));
            return;
        }
        plain_stream_.emplace(executor_);
        plain_stream_->async_connect(
            endpoints,
            guarded_connect_handler(&ProbeState::on_connected));
    }

    void on_connected(const boost::system::error_code& error, const tcp::endpoint& endpoint) {
        if (finished_) return;
        if (error) return finish(error);
        result_.remote_address = endpoint.address().to_string();
        result_.remote_port = endpoint.port();
        finish({});
    }

    void on_tls_connected(const boost::system::error_code& error, const tcp::endpoint& endpoint) {
        if (finished_) return;
        if (error) return finish(error);
        result_.remote_address = endpoint.address().to_string();
        result_.remote_port = endpoint.port();
        tls_stream_->async_handshake(
            asio::ssl::stream_base::client,
            guarded_handler(&ProbeState::on_tls_handshake));
    }

    void on_tls_handshake(const boost::system::error_code& error) {
        if (!error) result_.tls_verified = backend_.tls_verify_certificate;
        finish(error);
    }

    void finish(const boost::system::error_code& error) {
        if (finished_) return;
        finished_ = true;
        timer_.cancel();
        resolver_.cancel();
        result_.success = !error;
        result_.error = error ? error.message() : std::string{};
        result_.latency_ms = std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - started_).count();
        boost::system::error_code ignored;
        if (plain_stream_) plain_stream_->socket().close(ignored);
        if (tls_stream_) beast::get_lowest_layer(*tls_stream_).socket().close(ignored);
        if (completion_) {
            auto completion = std::move(completion_);
            completion(std::move(result_));
        }
    }

    void abort_noexcept() noexcept {
        finished_ = true;
        try {
            timer_.cancel();
        } catch (...) {
        }
        boost::system::error_code ignored;
        resolver_.cancel();
        if (plain_stream_) plain_stream_->socket().close(ignored);
        if (tls_stream_) beast::get_lowest_layer(*tls_stream_).socket().close(ignored);
        if (completion_) {
            auto completion = std::move(completion_);
            try {
                completion(std::move(result_));
            } catch (...) {
            }
        }
    }

    routing::BackendConfig backend_;
    asio::any_io_executor executor_;
    tcp::resolver resolver_;
    asio::steady_timer timer_;
    std::optional<BackendPlainStream> plain_stream_;
    std::optional<BackendTlsStream> tls_stream_;
    BackendProbeResult result_;
    std::function<void(BackendProbeResult)> completion_;
    std::chrono::steady_clock::time_point started_;
    bool finished_{};
};

} // namespace

BackendProbeResult probe_backend(const routing::BackendConfig& backend) {
    asio::io_context context;
    std::optional<BackendProbeResult> result;
    auto operation = async_probe_backend(
        backend,
        context.get_executor(),
        [&result](BackendProbeResult completed) { result.emplace(std::move(completed)); });
    static_cast<void>(operation);
    context.run();
    if (!result) {
        throw std::runtime_error{"backend probe completed without a result"};
    }
    return std::move(*result);
}

std::shared_ptr<BackendProbeOperation> async_probe_backend(
    routing::BackendConfig backend,
    asio::any_io_executor executor,
    std::function<void(BackendProbeResult)> completion) {
    if (!completion) {
        throw std::invalid_argument{"backend probe completion handler cannot be empty"};
    }
    auto state = std::make_shared<ProbeState>(
        std::move(backend), std::move(executor), std::move(completion));
    state->start();
    return state;
}

} // namespace webserver::proxy
