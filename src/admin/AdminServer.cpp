#include "admin/AdminServer.hpp"

#include "admin/AdminApi.hpp"
#include "admin/AuthService.hpp"
#include "config/ConfigService.hpp"
#include "logging/LogManager.hpp"
#include "proxy/BackendProbe.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/write.hpp>

#include <algorithm>
#include <chrono>
#include <exception>
#include <fstream>
#include <functional>
#include <iterator>
#include <new>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace webserver::admin {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

constexpr std::size_t maximum_admin_connections = 128;

std::string content_type(const std::filesystem::path& path) {
    const auto extension = path.extension().string();
    if (extension == ".html") return "text/html; charset=utf-8";
    if (extension == ".js") return "text/javascript; charset=utf-8";
    if (extension == ".css") return "text/css; charset=utf-8";
    if (extension == ".json") return "application/json; charset=utf-8";
    if (extension == ".svg") return "image/svg+xml";
    if (extension == ".png") return "image/png";
    if (extension == ".ico") return "image/x-icon";
    if (extension == ".woff2") return "font/woff2";
    return "application/octet-stream";
}

void set_browser_security_headers(http::fields& fields) {
    fields.set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; "
                                          "style-src 'self'; script-src 'self'; "
                                          "base-uri 'none'; frame-ancestors 'none'; form-action 'self'");
    fields.set("X-Content-Type-Options", "nosniff");
    fields.set("X-Frame-Options", "DENY");
    fields.set("Referrer-Policy", "no-referrer");
    fields.set(http::field::cache_control, "no-store");
}

http::response<http::string_body> text_response(
    const http::request<http::string_body>& request,
    http::status status,
    std::string body) {
    http::response<http::string_body> response{status, request.version()};
    response.set(http::field::content_type, "text/plain; charset=utf-8");
    set_browser_security_headers(response.base());
    response.keep_alive(request.keep_alive());
    response.body() = std::move(body);
    response.prepare_payload();
    return response;
}

http::response<http::string_body> static_response(
    const http::request<http::string_body>& request,
    const std::filesystem::path& root) {
    if (request.method() != http::verb::get && request.method() != http::verb::head) {
        return text_response(request, http::status::method_not_allowed, "Method Not Allowed");
    }

    const auto target = request.target();
    const auto query = target.find('?');
    const auto path_view = target.substr(0, query);
    std::string path{path_view.data(), path_view.size()};
    if (path.empty() || path.front() != '/' || path.find("..") != std::string::npos ||
        path.find('\\') != std::string::npos || path.find('%') != std::string::npos) {
        return text_response(request, http::status::bad_request, "Invalid path");
    }
    if (path == "/") {
        path = "/index.html";
    }

    auto file_path = root / path.substr(1);
    if ((!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) &&
        std::filesystem::path{path}.extension().empty()) {
        file_path = root / "index.html";
    }
    if (!std::filesystem::exists(file_path) || !std::filesystem::is_regular_file(file_path)) {
        return text_response(request, http::status::not_found, "Not Found");
    }

    std::ifstream input{file_path, std::ios::binary};
    if (!input) {
        return text_response(request, http::status::internal_server_error, "Cannot read admin asset");
    }
    std::string body{
        std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};

    http::response<http::string_body> response{http::status::ok, request.version()};
    response.set(http::field::content_type, content_type(file_path));
    set_browser_security_headers(response.base());
    response.keep_alive(request.keep_alive());
    if (request.method() == http::verb::head) {
        response.content_length(body.size());
    } else {
        response.body() = std::move(body);
        response.prepare_payload();
    }
    return response;
}

class AdminSession final : public std::enable_shared_from_this<AdminSession> {
public:
    using CloseHandler = std::function<void(AdminSession*)>;

    AdminSession(
        tcp::socket socket,
        std::shared_ptr<const std::atomic_bool> stopping,
        std::shared_ptr<AdminApi> api,
        std::filesystem::path static_root,
        std::shared_ptr<logging::LogManager> logger,
        CloseHandler on_close)
        : stream_(std::move(socket)),
          stopping_(std::move(stopping)),
          api_(std::move(api)),
          static_root_(std::move(static_root)),
          logger_(std::move(logger)),
          on_close_(std::move(on_close)) {}

    void start() { read_request(); }

    void stop() {
        try {
            asio::dispatch(
                stream_.get_executor(), guarded_handler(&AdminSession::close));
        } catch (...) {
            abort_noexcept();
        }
    }

private:
    using Parser = http::request_parser<http::string_body>;
    using Response = http::response<http::string_body>;

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

    void read_request() {
        parser_.emplace();
        parser_->header_limit(16 * 1024);
        parser_->body_limit(16 * 1024 * 1024);
        stream_.expires_after(15s);
        http::async_read(
            stream_,
            buffer_,
            *parser_,
            guarded_handler(&AdminSession::on_read));
    }

    void on_read(const boost::system::error_code& error, std::size_t) {
        if (error == http::error::end_of_stream) {
            close();
            return;
        }
        if (error) {
            if (logger_ && error != asio::error::operation_aborted) {
                logger_->log_error(
                    logging::ErrorSeverity::warning,
                    "admin_session",
                    "request read failed: " + error.message());
            }
            close();
            return;
        }

        auto request = parser_->release();
        parser_.reset();
        const auto target = request.target();
        if (target.starts_with("/api/")) {
            boost::system::error_code endpoint_error;
            const auto remote = stream_.socket().remote_endpoint(endpoint_error);
            if (endpoint_error || !remote.address().is_loopback()) {
                write_response(text_response(
                    request, http::status::forbidden, "Loopback access only"));
            } else {
                async_operation_ = api_->handle_async(
                    std::move(request),
                    remote.address().to_string(),
                    stream_.get_executor(),
                    [self = shared_from_this()](Response response) noexcept {
                        self->invoke_guarded([&] {
                            self->async_operation_.reset();
                            if (self->closed_) return;
                            if (self->stopping_->load()) response.keep_alive(false);
                            self->write_response(std::move(response));
                        });
                    },
                    [weak = weak_from_this()]() noexcept {
                        if (const auto self = weak.lock()) self->abort_noexcept();
                    });
            }
            return;
        }
        auto response = static_response(request, static_root_);
        if (stopping_->load()) response.keep_alive(false);
        write_response(std::move(response));
    }

    void write_response(Response response) {
        const bool keep_alive = response.keep_alive();
        response_ = std::make_shared<Response>(std::move(response));
        stream_.expires_after(30s);
        http::async_write(
            stream_,
            *response_,
            guarded_handler(&AdminSession::on_write, keep_alive));
    }

    void on_write(bool keep_alive, const boost::system::error_code& error, std::size_t) {
        response_.reset();
        if (error && logger_ && error != asio::error::operation_aborted) {
            logger_->log_error(
                logging::ErrorSeverity::warning,
                "admin_session",
                "response write failed: " + error.message());
        }
        if (error || !keep_alive || stopping_->load()) {
            close();
            return;
        }
        read_request();
    }

    void close() {
        if (closed_) return;
        closed_ = true;
        if (async_operation_) {
            auto operation = std::move(async_operation_);
            operation->cancel();
        }
        stream_.expires_never();
        boost::system::error_code ignored;
        stream_.socket().shutdown(tcp::socket::shutdown_both, ignored);
        stream_.socket().close(ignored);
        if (on_close_) {
            auto on_close = std::move(on_close_);
            on_close(this);
        }
    }

    void abort_noexcept() noexcept {
        closed_ = true;
        try {
            if (async_operation_) async_operation_->cancel();
        } catch (...) {
        }
        async_operation_.reset();
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

    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    std::optional<Parser> parser_;
    std::shared_ptr<Response> response_;
    std::shared_ptr<proxy::BackendProbeOperation> async_operation_;
    std::shared_ptr<const std::atomic_bool> stopping_;
    std::shared_ptr<AdminApi> api_;
    std::filesystem::path static_root_;
    std::shared_ptr<logging::LogManager> logger_;
    CloseHandler on_close_;
    bool closed_{false};
};

} // namespace

class AdminListener final : public std::enable_shared_from_this<AdminListener> {
public:
    AdminListener(
        asio::io_context& io_context,
        std::shared_ptr<AdminApi> api,
        std::filesystem::path static_root,
        std::uint16_t port,
        std::shared_ptr<logging::LogManager> logger)
        : io_context_(io_context),
          acceptor_(asio::make_strand(io_context)),
          accept_retry_timer_(acceptor_.get_executor()),
          stopping_(std::make_shared<std::atomic_bool>(false)),
          api_(std::move(api)),
          static_root_(std::move(static_root)),
          logger_(std::move(logger)) {
        const tcp::endpoint endpoint{asio::ip::address_v4::loopback(), port};
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(asio::socket_base::reuse_address{true});
        acceptor_.bind(endpoint);
        acceptor_.listen(asio::socket_base::max_listen_connections);
        endpoint_ = acceptor_.local_endpoint();
    }

    void start() { accept_next(); }

    void stop() noexcept {
        stopping_->store(true);
        try {
            asio::dispatch(acceptor_.get_executor(), [self = shared_from_this()]() noexcept {
                try {
                    self->stop_on_executor();
                } catch (...) {
                    self->emergency_close_noexcept();
                }
            });
        } catch (...) {
            emergency_close_noexcept();
        }
    }

    [[nodiscard]] tcp::endpoint local_endpoint() const { return endpoint_; }

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
                self->recover_accept_noexcept();
            }
        };
    }

    void accept_next() {
        if (stopping_->load() || !acceptor_.is_open()) return;
        acceptor_.async_accept(
            asio::make_strand(io_context_),
            guarded_handler(&AdminListener::on_accept));
    }

    void on_accept(const boost::system::error_code& error, tcp::socket socket) {
        if (error) {
            if (error != asio::error::operation_aborted && acceptor_.is_open() &&
                !stopping_->load()) {
                if (logger_) {
                    try {
                        logger_->log_error(
                            logging::ErrorSeverity::error,
                            "admin_listener",
                            "accept failed: " + error.message());
                    } catch (...) {
                    }
                }
                schedule_accept_retry();
            }
            return;
        }
        if (stopping_->load()) {
            boost::system::error_code ignored;
            socket.close(ignored);
            return;
        }

        accept_retry_delay_ = 10ms;
        if (sessions_.size() >= maximum_admin_connections) {
            boost::system::error_code ignored;
            socket.close(ignored);
            schedule_accept_retry();
            return;
        }

        try {
            const auto session = std::make_shared<AdminSession>(
                std::move(socket),
                stopping_,
                api_,
                static_root_,
                logger_,
                [weak = weak_from_this()](AdminSession* closed) {
                    if (const auto listener = weak.lock()) {
                        asio::dispatch(listener->acceptor_.get_executor(), [listener, closed] {
                            listener->sessions_.erase(closed);
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
                        "admin_listener",
                        "could not create an admin session: " +
                            std::string{exception.what()});
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

    void schedule_accept_retry() {
        if (stopping_->load() || !acceptor_.is_open()) return;
        accept_retry_timer_.expires_after(accept_retry_delay_);
        accept_retry_delay_ = std::min(
            accept_retry_delay_ * 2, std::chrono::milliseconds{1000});
        accept_retry_timer_.async_wait(
            guarded_handler(&AdminListener::on_accept_retry));
    }

    void on_accept_retry(const boost::system::error_code& error) {
        if (!error) accept_next();
    }

    void stop_on_executor() {
        try {
            accept_retry_timer_.cancel();
        } catch (...) {
        }
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
        for (const auto& [session_ptr, session] : sessions_) {
            static_cast<void>(session_ptr);
            session->stop();
        }
    }

    void emergency_close_noexcept() noexcept {
        stopping_->store(true);
        try {
            accept_retry_timer_.cancel();
        } catch (...) {
        }
        boost::system::error_code ignored;
        acceptor_.cancel(ignored);
        acceptor_.close(ignored);
    }

    void recover_accept_noexcept() noexcept {
        try {
            schedule_accept_retry();
        } catch (...) {
            emergency_close_noexcept();
        }
    }

    asio::io_context& io_context_;
    tcp::acceptor acceptor_;
    asio::steady_timer accept_retry_timer_;
    tcp::endpoint endpoint_;
    std::shared_ptr<std::atomic_bool> stopping_;
    std::shared_ptr<AdminApi> api_;
    std::filesystem::path static_root_;
    std::shared_ptr<logging::LogManager> logger_;
    std::unordered_map<AdminSession*, std::shared_ptr<AdminSession>> sessions_;
    std::chrono::milliseconds accept_retry_delay_{10};
};

AdminServer::AdminServer(
    config::ConfigService& config_service,
    AuthService& auth_service,
    std::filesystem::path static_root,
    std::uint16_t port,
    std::shared_ptr<logging::LogManager> logger,
    std::function<std::vector<core::ListenerStatus>()> listener_status_provider)
    : logger_(std::move(logger)),
      api_(std::make_shared<AdminApi>(
          config_service, auth_service, logger_, std::move(listener_status_provider))),
      listener_(std::make_shared<AdminListener>(
          io_context_, api_, std::move(static_root), port, logger_)) {}

AdminServer::~AdminServer() {
    stop();
    wait();
}

void AdminServer::start() {
    if (started_.exchange(true)) {
        throw std::logic_error{"admin server has already been started"};
    }
    listener_->start();
    worker_ = std::thread([this] { run_worker(); });
}

void AdminServer::stop() {
    if (!started_.load() || stopping_.exchange(true)) return;
    listener_->stop();
}

void AdminServer::wait() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

tcp::endpoint AdminServer::local_endpoint() const {
    return listener_->local_endpoint();
}

asio::io_context& AdminServer::io_context() noexcept {
    return io_context_;
}

void AdminServer::run_worker() noexcept {
    for (;;) {
        try {
            io_context_.run();
            return;
        } catch (const std::bad_alloc&) {
            if (logger_) {
                try {
                    logger_->log_error(
                        logging::ErrorSeverity::critical,
                        "admin_worker",
                        "worker handler ran out of memory; event loop will continue");
                } catch (...) {
                }
            }
        } catch (const std::exception& exception) {
            if (logger_) {
                try {
                    logger_->log_error(
                        logging::ErrorSeverity::critical,
                        "admin_worker",
                        "uncaught worker handler exception: " +
                            std::string{exception.what()});
                } catch (...) {
                }
            }
        } catch (...) {
            if (logger_) {
                try {
                    logger_->log_error(
                        logging::ErrorSeverity::critical,
                        "admin_worker",
                        "unknown worker handler exception; event loop will continue");
                } catch (...) {
                }
            }
        }
    }
}

} // namespace webserver::admin
