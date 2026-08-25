#include "http/HttpSession.hpp"

#include "config/RuntimeConfig.hpp"
#include "core/ConnectionRegistry.hpp"
#include "http/RequestDispatcher.hpp"
#include "logging/LogManager.hpp"
#include "proxy/ProxyTransaction.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <chrono>
#include <string_view>
#include <utility>
#include <vector>

namespace webserver::http {
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

std::string source_address(const tcp::socket& socket) {
    boost::system::error_code error;
    const auto endpoint = socket.remote_endpoint(error);
    if (error) return "unknown";
    const auto address = endpoint.address().to_string();
    return endpoint.address().is_v6()
               ? '[' + address + "]:" + std::to_string(endpoint.port())
               : address + ':' + std::to_string(endpoint.port());
}

} // namespace

HttpSession::HttpSession(
    tcp::socket socket,
    std::shared_ptr<const std::atomic_bool> stopping,
    std::shared_ptr<config::RuntimeConfigStore> runtime_store,
    std::uint16_t listener_port,
    std::shared_ptr<logging::LogManager> logger,
    CloseHandler on_close)
    : stream_(std::move(socket)),
      stopping_(std::move(stopping)),
      runtime_store_(std::move(runtime_store)),
      listener_port_(listener_port),
      logger_(std::move(logger)),
      on_close_(std::move(on_close)),
      connection_id_(core::ConnectionRegistry::instance().add(
          "HTTP", source_address(stream_.socket()), "Connected")) {}

HttpSession::~HttpSession() {
    clear_http_request();
    core::ConnectionRegistry::instance().remove(connection_id_);
}

void HttpSession::start() {
    read_request();
}

void HttpSession::stop() {
    try {
        boost::asio::dispatch(
            stream_.get_executor(), guarded_handler(&HttpSession::stop_on_executor));
    } catch (...) {
        abort_noexcept();
    }
}

void HttpSession::stop_on_executor() {
    if (proxy_operation_) {
        proxy_operation_->cancel();
        return;
    }
    if (dispatcher_) {
        dispatcher_->cancel();
    }
    if (!response_) {
        close();
    }
}

void HttpSession::read_request() {
    clear_http_request();
    core::ConnectionRegistry::instance().update_request(
        connection_id_, {}, {}, {}, "Waiting for Request");
    parser_.emplace();
    parser_->body_limit(runtime_store_->load()->settings().max_upload_bytes);
    parser_->header_limit(16 * 1024);

    const auto settings = runtime_store_->load()->settings();
    stream_.expires_after(std::chrono::seconds{settings.client_header_timeout_seconds});
    http::async_read_header(
        stream_,
        buffer_,
        *parser_,
        guarded_handler(&HttpSession::on_header_read));
}

void HttpSession::on_header_read(
    const boost::system::error_code& error,
    std::size_t) {
    if (error == http::error::end_of_stream) {
        close();
        return;
    }
    if (error == http::error::body_limit) {
        send_payload_too_large();
        return;
    }
    if (error) {
        if (logger_ && error != boost::asio::error::operation_aborted) {
            logger_->log_error(
                logging::ErrorSeverity::warning,
                "http_session",
                "request read failed: " + error.message());
        }
        close();
        return;
    }

    boost::system::error_code endpoint_error;
    const auto peer_endpoint = stream_.socket().remote_endpoint(endpoint_error);
    if (endpoint_error) {
        close();
        return;
    }

    const auto runtime = runtime_store_->load();
    const auto& parsed = parser_->get();
    const auto method = parsed.method_string();
    const auto target = parsed.target();
    const auto referer = parsed[http::field::referer];
    core::ConnectionRegistry::instance().update_request(
        connection_id_,
        std::string_view{method.data(), method.size()},
        std::string_view{target.data(), target.size()},
        std::string_view{referer.data(), referer.size()},
        "Routing");
    RequestDispatcher::Request request{parsed.method(), parsed.target(), parsed.version()};
    request.base() = parsed.base();
    std::vector<std::pair<std::string, std::string>> real_ip_headers;
    for (const auto& name : runtime->client_ip_resolver().header_priority()) {
        const auto found = parsed.find(beast::string_view{name.data(), name.size()});
        if (found != parsed.end()) {
            const auto value = found->value();
            real_ip_headers.emplace_back(name, std::string{value.data(), value.size()});
        }
    }
    const auto client_ip = runtime->client_ip_resolver().resolve(
        peer_endpoint.address(), real_ip_headers);
    const auto host = parsed[http::field::host];
    http_request_id_ = core::HttpRequestRegistry::instance().add(
        "HTTP",
        client_ip,
        std::string_view{method.data(), method.size()},
        std::string_view{target.data(), target.size()},
        std::string_view{referer.data(), referer.size()},
        std::string_view{host.data(), host.size()},
        "Routing");
    auto dispatcher = std::make_shared<RequestDispatcher>(
        stream_.get_executor(),
        runtime,
        listener_port_,
        std::move(request),
        client_ip,
        RequestSecurityContext{},
        [self = shared_from_this()](
            std::int64_t site_id,
            std::string_view site_name,
            std::string_view normalized_host) noexcept {
            self->invoke_guarded([&] {
                if (self->http_request_id_ != 0) {
                    core::HttpRequestRegistry::instance().update_site(
                        self->http_request_id_, site_id, site_name, normalized_host, "Policy Check");
                }
            });
        },
        [self = shared_from_this()](
            routing::BackendConfig backend,
            RequestDispatcher::Request proxy_request,
            std::string proxy_client_ip,
            std::string scheme,
            std::string request_id,
            config::RuntimeSettings settings,
            routing::BackendOverloadConfig overload) noexcept {
            self->invoke_guarded([&] {
                self->start_proxy(
                    std::move(backend), std::move(proxy_request), std::move(proxy_client_ip),
                    std::move(scheme), std::move(request_id), std::move(settings),
                    std::move(overload));
            });
        },
        logger_,
        [self = shared_from_this()](Response response) noexcept {
            self->invoke_guarded([&] { self->on_proxy_response(std::move(response)); });
        });
    dispatcher_ = dispatcher;
    dispatcher->start();
}

void HttpSession::send_payload_too_large() {
    const auto version = parser_ ? parser_->get().version() : 11;
    Response response{http::status::payload_too_large, version};
    response.set(http::field::content_type, "text/plain; charset=utf-8");
    response.keep_alive(false);
    response.body() = "Payload Too Large";
    response.prepare_payload();
    if (parser_) {
        const auto& parsed = parser_->get();
        const auto method = parsed.method_string();
        const auto target = parsed.target();
        const auto referer = parsed[http::field::referer];
        core::ConnectionRegistry::instance().update_request(
            connection_id_,
            std::string_view{method.data(), method.size()},
            std::string_view{target.data(), target.size()},
            std::string_view{referer.data(), referer.size()},
            "Payload Too Large");
    }
    write_response(std::move(response));
}

void HttpSession::clear_http_request() {
    if (http_request_id_ == 0) return;
    core::HttpRequestRegistry::instance().remove(http_request_id_);
    http_request_id_ = 0;
}

void HttpSession::start_proxy(
    routing::BackendConfig backend,
    RequestDispatcher::Request request,
    std::string client_ip,
    std::string scheme,
    std::string request_id,
    config::RuntimeSettings settings,
    routing::BackendOverloadConfig overload) {
    core::ConnectionRegistry::instance().update_status(connection_id_, "Proxying");
    if (http_request_id_ != 0) {
        core::HttpRequestRegistry::instance().update_status(http_request_id_, "Proxying");
    }
    auto operation = std::make_shared<proxy::ProxyTransaction<beast::tcp_stream>>(
        stream_,
        buffer_,
        *parser_,
        stream_.get_executor(),
        std::move(backend),
        std::move(request),
        std::move(client_ip),
        std::move(scheme),
        std::move(request_id),
        std::move(settings),
        std::move(overload),
        [self = shared_from_this()](
            unsigned status, std::uint64_t bytes, bool keep_alive) noexcept {
            self->invoke_guarded(
                [&] { self->on_stream_complete(status, bytes, keep_alive); });
        },
        [weak = weak_from_this()](const boost::system::error_code& error) noexcept {
            try {
                if (const auto self = weak.lock(); self && self->logger_ &&
                    error != boost::asio::error::operation_aborted) {
                    self->logger_->log_error(
                        logging::ErrorSeverity::error,
                        "streaming_proxy",
                        "backend stream failed: " + error.message());
                }
            } catch (...) {
            }
        });
    proxy_operation_ = operation;
    operation->start();
}

void HttpSession::on_stream_complete(unsigned status, std::uint64_t bytes, bool keep_alive) {
    proxy_operation_.reset();
    parser_.reset();
    if (dispatcher_) dispatcher_->complete_stream(status, bytes);
    dispatcher_.reset();
    clear_http_request();
    if (closed_) return;
    if (!keep_alive || stopping_->load()) {
        close();
        return;
    }
    read_request();
}

void HttpSession::on_proxy_response(Response response) {
    dispatcher_.reset();
    if (closed_) {
        return;
    }
    if (stopping_->load()) {
        response.keep_alive(false);
    }
    if (parser_ && !parser_->is_done()) {
        response.keep_alive(false);
    }
    core::ConnectionRegistry::instance().update_status(connection_id_, "Writing Response");
    if (http_request_id_ != 0) {
        core::HttpRequestRegistry::instance().update_status(
            http_request_id_, "Writing Response");
    }
    write_response(std::move(response));
}

void HttpSession::write_response(Response response) {
    const bool keep_alive = response.keep_alive();
    response_ = std::make_shared<Response>(std::move(response));

    stream_.expires_after(std::chrono::seconds{
        runtime_store_->load()->settings().client_write_timeout_seconds});
    http::async_write(
        stream_,
        *response_,
        guarded_handler(&HttpSession::on_write, keep_alive));
}

void HttpSession::on_write(
    bool keep_alive,
    const boost::system::error_code& error,
    std::size_t) {
    if (error) {
        if (logger_ && error != boost::asio::error::operation_aborted) {
            logger_->log_error(
                logging::ErrorSeverity::warning,
                "http_session",
                "response write failed: " + error.message());
        }
        close();
        return;
    }

    response_.reset();
    parser_.reset();
    clear_http_request();

    if (!keep_alive || stopping_->load()) {
        close();
        return;
    }

    read_request();
}

void HttpSession::close() {
    if (closed_) {
        return;
    }
    closed_ = true;
    clear_http_request();
    core::ConnectionRegistry::instance().remove(connection_id_);

    if (dispatcher_) {
        auto active_dispatcher = std::move(dispatcher_);
        active_dispatcher->cancel();
    }
    if (proxy_operation_) {
        auto operation = std::move(proxy_operation_);
        operation->cancel();
    }

    stream_.expires_never();
    boost::system::error_code ignored;
    stream_.socket().shutdown(tcp::socket::shutdown_send, ignored);
    stream_.socket().close(ignored);

    if (on_close_) {
        auto on_close = std::move(on_close_);
        on_close(this);
    }
}

void HttpSession::abort_noexcept() noexcept {
    closed_ = true;

    try {
        clear_http_request();
    } catch (...) {
        http_request_id_ = 0;
    }
    try {
        core::ConnectionRegistry::instance().remove(connection_id_);
    } catch (...) {
    }

    try {
        if (dispatcher_) dispatcher_->cancel();
    } catch (...) {
    }
    dispatcher_.reset();
    try {
        if (proxy_operation_) proxy_operation_->cancel();
    } catch (...) {
    }
    proxy_operation_.reset();

    boost::system::error_code ignored;
    try {
        stream_.expires_never();
    } catch (...) {
    }
    stream_.socket().cancel(ignored);
    stream_.socket().shutdown(tcp::socket::shutdown_both, ignored);
    stream_.socket().close(ignored);

    if (on_close_) {
        auto on_close = std::move(on_close_);
        try {
            on_close(this);
        } catch (...) {
        }
    }
}

} // namespace webserver::http
