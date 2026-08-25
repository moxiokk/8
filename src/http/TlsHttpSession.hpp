#pragma once

#include "tls/TlsContextManager.hpp"

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/buffer_body.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/string_body.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <utility>

namespace webserver::config {
class RuntimeConfigStore;
struct RuntimeSettings;
}

namespace webserver::logging {
class LogManager;
}

namespace webserver::routing {
struct BackendConfig;
struct BackendOverloadConfig;
}

namespace webserver::proxy {
class ProxyOperation;
}

namespace webserver::http {

class RequestDispatcher;

class TlsHttpSession final : public std::enable_shared_from_this<TlsHttpSession> {
public:
    using CloseHandler = std::function<void(TlsHttpSession*)>;

    TlsHttpSession(
        boost::asio::ip::tcp::socket socket,
        std::shared_ptr<const std::atomic_bool> stopping,
        std::shared_ptr<config::RuntimeConfigStore> runtime_store,
        std::uint16_t listener_port,
        std::shared_ptr<tls::TlsContextManager> tls_contexts,
        std::shared_ptr<logging::LogManager> logger,
        CloseHandler on_close);
    ~TlsHttpSession();

    void start();
    void stop();

private:
    using TlsStream = boost::asio::ssl::stream<boost::beast::tcp_stream>;
    using RequestParser = boost::beast::http::request_parser<boost::beast::http::buffer_body>;
    using Response = boost::beast::http::response<boost::beast::http::string_body>;

    void on_handshake(const boost::system::error_code& error);
    void read_request();
    void on_header_read(const boost::system::error_code& error, std::size_t bytes_transferred);
    void send_payload_too_large();
    void clear_http_request();
    void on_dispatch_response(Response response);
    void start_proxy(
        routing::BackendConfig backend,
        boost::beast::http::request<boost::beast::http::empty_body> request,
        std::string client_ip,
        std::string scheme,
        std::string request_id,
        config::RuntimeSettings settings,
        routing::BackendOverloadConfig overload);
    void on_stream_complete(unsigned status, std::uint64_t bytes, bool keep_alive);
    void write_response(Response response);
    void on_write(
        bool keep_alive,
        const boost::system::error_code& error,
        std::size_t bytes_transferred);
    void close();
    void on_shutdown(const boost::system::error_code& error);
    void close_socket();
    void abort_noexcept() noexcept;
    void stop_on_executor();

    template <typename Method, typename... Bound>
    auto guarded_handler(Method method, Bound&&... bound) {
        return [self = shared_from_this(), method,
                ... values = std::forward<Bound>(bound)](auto&&... arguments) mutable noexcept {
            try {
                std::invoke(
                    method,
                    self.get(),
                    values...,
                    std::forward<decltype(arguments)>(arguments)...);
            } catch (...) {
                self->abort_noexcept();
            }
        };
    }

    template <typename Handler>
    void invoke_guarded(Handler&& handler) noexcept {
        try {
            std::forward<Handler>(handler)();
        } catch (...) {
            abort_noexcept();
        }
    }

    std::shared_ptr<tls::TlsContextManager> tls_contexts_;
    TlsStream stream_;
    boost::beast::flat_buffer buffer_;
    std::optional<RequestParser> parser_;
    std::shared_ptr<Response> response_;
    std::shared_ptr<RequestDispatcher> dispatcher_;
    std::shared_ptr<proxy::ProxyOperation> proxy_operation_;
    std::shared_ptr<const std::atomic_bool> stopping_;
    std::shared_ptr<config::RuntimeConfigStore> runtime_store_;
    std::uint16_t listener_port_{};
    std::shared_ptr<logging::LogManager> logger_;
    tls::TlsConnectionState tls_state_;
    CloseHandler on_close_;
    std::uint64_t connection_id_{};
    std::uint64_t http_request_id_{};
    bool handshake_complete_{false};
    bool closing_{false};
    bool closed_{false};
};

} // namespace webserver::http
