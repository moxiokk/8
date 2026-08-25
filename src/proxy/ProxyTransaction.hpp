#pragma once

#include "config/RuntimeConfig.hpp"
#include "proxy/BackendConcurrencyLimiter.hpp"
#include "proxy/BackendConnectionPool.hpp"
#include "routing/HostNormalizer.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/async_result.hpp>
#include <boost/asio/bind_executor.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core/error.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/beast/core/string.hpp>
#include <boost/beast/http/buffer_body.hpp>
#include <boost/beast/http/chunk_encode.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket/rfc6455.hpp>
#include <boost/system/errc.hpp>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <new>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webserver::proxy {

class ProxyOperation {
public:
    virtual ~ProxyOperation() = default;
    virtual void start() = 0;
    virtual void cancel() = 0;
};

namespace detail {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

inline constexpr std::size_t http_transfer_chunk_size = 16 * 1024;
inline constexpr std::size_t tunnel_chunk_size = 32 * 1024;

inline std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

inline bool token_character(unsigned char character) {
    if (std::isalnum(character)) return true;
    constexpr std::string_view punctuation{"!#$%&'*+-.^_`|~"};
    return punctuation.find(static_cast<char>(character)) != std::string_view::npos;
}

template <typename Fields>
void strip_hop_headers(Fields& fields, bool preserve_upgrade, bool preserve_transfer_encoding) {
    std::vector<std::string> named;
    for (const auto& field : fields) {
        if (field.name() != http::field::connection) continue;
        std::string_view value{field.value().data(), field.value().size()};
        std::size_t start = 0;
        while (start <= value.size()) {
            const auto comma = value.find(',', start);
            const auto end = comma == std::string_view::npos ? value.size() : comma;
            const auto token = trim(value.substr(start, end - start));
            if (!token.empty() && std::all_of(token.begin(), token.end(),
                [](unsigned char c) { return token_character(c); })) named.emplace_back(token);
            if (comma == std::string_view::npos) break;
            start = comma + 1;
        }
    }
    for (const auto& name : named) {
        if (preserve_upgrade && beast::iequals(
                beast::string_view{name.data(), name.size()}, "upgrade")) continue;
        fields.erase(beast::string_view{name.data(), name.size()});
    }
    if (!preserve_upgrade) {
        fields.erase(http::field::connection);
        fields.erase(http::field::upgrade);
    }
    fields.erase(http::field::keep_alive);
    fields.erase(http::field::te);
    fields.erase(http::field::trailer);
    if (!preserve_transfer_encoding) fields.erase(http::field::transfer_encoding);
    fields.erase("Proxy-Connection");
    fields.erase("Proxy-Authenticate");
    fields.erase("Proxy-Authorization");
}

inline void remove_forwarding_headers(http::fields& fields) {
    fields.erase("Forwarded");
    fields.erase("X-Forwarded-For");
    fields.erase("X-Forwarded-Host");
    fields.erase("X-Forwarded-Proto");
    fields.erase("X-Real-IP");
    fields.erase("CF-Connecting-IP");
    fields.erase("True-Client-IP");
    fields.erase("X-Request-ID");
}

template <typename Downstream>
class ProxyTransactionImpl final : public ProxyOperation,
                                   public std::enable_shared_from_this<ProxyTransactionImpl<Downstream>> {
public:
    using Request = http::request<http::empty_body>;
    using Completion = std::function<void(unsigned, std::uint64_t, bool)>;
    using Failure = std::function<void(const boost::system::error_code&)>;

    ProxyTransactionImpl(
        Downstream& downstream,
        beast::flat_buffer& client_buffer,
        http::request_parser<http::buffer_body>& client_parser,
        asio::any_io_executor executor,
        routing::BackendConfig backend,
        Request request,
        std::string client_ip,
        std::string scheme,
        std::string request_id,
        config::RuntimeSettings settings,
        routing::BackendOverloadConfig overload,
        Completion completion,
        Failure failure = {})
        : downstream_(downstream),
          client_buffer_(client_buffer),
          client_parser_(client_parser),
          executor_(std::move(executor)),
          backend_(std::move(backend)),
          resolver_(executor_),
          connect_timer_(executor_),
          request_(std::move(request)),
          client_ip_(std::move(client_ip)),
          scheme_(std::move(scheme)),
          request_id_(std::move(request_id)),
          settings_(std::move(settings)),
          overload_(std::move(overload)),
          completion_(std::move(completion)),
          failure_(std::move(failure)),
          client_version_(request_.version()),
          client_keep_alive_(request_.keep_alive()),
          head_request_(request_.method() == http::verb::head),
          websocket_(beast::websocket::is_upgrade(request_)),
          expect_continue_(beast::iequals(request_[http::field::expect], "100-continue")) {}

    void start() override {
        try {
            asio::dispatch(executor_, guarded_handler(&Self::start_on_executor));
        } catch (...) {
            abort_from_exception_noexcept();
        }
    }

    void cancel() override {
        try {
            asio::dispatch(executor_, guarded_handler(&Self::cancel_on_executor));
        } catch (...) {
            abort_from_exception_noexcept();
        }
    }

private:
    using Self = ProxyTransactionImpl<Downstream>;
    using ResponseParser = http::response_parser<http::buffer_body>;
    using ResponseSerializer = http::response_serializer<http::buffer_body>;
    using UpgradeParser = http::response_parser<http::empty_body>;

    struct HttpTransferBuffer final {
        HttpTransferBuffer() noexcept {}
        std::array<char, http_transfer_chunk_size> bytes;
    };

    struct DeferredFinish final {
        unsigned status{};
        std::uint64_t bytes{};
        bool keep_alive{};
    };

    struct TunnelBuffers final {
        TunnelBuffers() noexcept {}
        std::array<char, tunnel_chunk_size> client_to_backend;
        std::array<char, tunnel_chunk_size> backend_to_client;
    };

    template <typename Handler>
    auto bind_to_executor(Handler&& handler) {
        return asio::bind_executor(executor_, std::forward<Handler>(handler));
    }

    template <typename Method>
    auto guarded_handler(Method method) {
        return [self = this->shared_from_this(), method](auto&&... arguments) mutable noexcept {
            try {
                std::invoke(
                    method,
                    self.get(),
                    std::forward<decltype(arguments)>(arguments)...);
            } catch (...) {
                self->abort_from_exception_noexcept();
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

    template <typename Operation>
    void with_backend(Operation&& operation) {
        std::visit(std::forward<Operation>(operation), *backend_stream_);
    }

    template <typename Initiation>
    void start_backend_operation(Initiation&& initiation) {
        ++backend_operations_pending_;
        try {
            std::forward<Initiation>(initiation)();
        } catch (...) {
            --backend_operations_pending_;
            throw;
        }
    }

    void finish_backend_operation() {
        if (backend_operations_pending_ != 0) {
            --backend_operations_pending_;
        }
        maybe_release_closed_backend();
    }

    template <typename Initiation>
    void start_client_operation(Initiation&& initiation) {
        ++client_operations_pending_;
        try {
            std::forward<Initiation>(initiation)();
        } catch (...) {
            --client_operations_pending_;
            throw;
        }
    }

    void finish_client_operation() {
        if (client_operations_pending_ != 0) {
            --client_operations_pending_;
        }
    }

    void expire_backend_after(std::chrono::seconds timeout) {
        with_backend([timeout](auto& stream) {
            beast::get_lowest_layer(stream).expires_after(timeout);
        });
    }

    void expire_backend_never() {
        with_backend([](auto& stream) { beast::get_lowest_layer(stream).expires_never(); });
    }

    [[nodiscard]] bool backend_socket_open() {
        bool open = false;
        with_backend([&open](auto& stream) {
            open = beast::get_lowest_layer(stream).socket().is_open();
        });
        return open;
    }

    [[nodiscard]] std::string effective_backend_host() const {
        if (!backend_.host.empty()) return backend_.host;
        const auto value = request_[http::field::host];
        return std::string{value.data(), value.size()};
    }

    [[nodiscard]] std::string effective_tls_sni() const {
        if (!backend_.tls_sni.empty()) return backend_.tls_sni;
        if (!backend_.host.empty()) {
            if (const auto normalized = routing::HostNormalizer::normalize_authority(backend_.host)) {
                return *normalized;
            }
        }
        return backend_.address;
    }

    [[nodiscard]] std::string backend_pool_key() const {
        return (backend_.protocol == routing::BackendProtocol::https ? "https|" : "http|") +
               backend_.address + ':' + std::to_string(backend_.port) + '|' +
               effective_backend_host() + '|' + effective_tls_sni() + '|' +
               (backend_.tls_verify_certificate ? "verify" : "insecure");
    }

    void start_on_executor() {
        beast::get_lowest_layer(downstream_).expires_never();
        const auto backend_name =
            (backend_.protocol == routing::BackendProtocol::https ? "https://" : "http://") +
            backend_.address + ':' + std::to_string(backend_.port);
        pending_acquire_ = BackendConcurrencyLimiter::instance().async_acquire(
            overload_.site_id,
            overload_.site_name,
            backend_name,
            overload_.maximum_active_connections,
            overload_.maximum_queue,
            std::chrono::seconds{overload_.queue_timeout_seconds},
            executor_,
            [self = this->shared_from_this()](
                BackendAcquireResult result,
                std::shared_ptr<BackendConcurrencyLimiter::Permit> permit) noexcept {
                try {
                    self->on_backend_permit(result, std::move(permit));
                } catch (...) {
                    self->abort_from_exception_noexcept();
                }
            });
    }

    void cancel_on_executor() {
        if (completed_) return;
        if (pending_acquire_) pending_acquire_->cancel();
        connecting_ = false;
        connect_timer_.cancel();
        resolver_.cancel();
        close_backend();
        finish_when_io_quiesced(
            status_ == 0 ? 499U : status_, response_bytes_, false);
    }

    void on_backend_permit(
        BackendAcquireResult result,
        std::shared_ptr<BackendConcurrencyLimiter::Permit> permit) {
        pending_acquire_.reset();
        if (completed_) return;
        if (result != BackendAcquireResult::granted || !permit) {
            return send_error(
                http::status::service_unavailable,
                result == BackendAcquireResult::queue_timeout
                    ? "Backend Queue Timeout"
                    : "Backend Overloaded");
        }
        permit_ = std::move(permit);
        // Queued transactions deliberately carry no large transfer buffer.
        if (!websocket_) {
            try {
                http_transfer_buffer_ = std::make_unique<HttpTransferBuffer>();
            } catch (const std::bad_alloc&) {
                return send_error(
                    http::status::service_unavailable,
                    "Insufficient Memory");
            }
        }
        prepare_request();
        if (settings_.backend_keep_alive && backend_.keep_alive && !websocket_) {
            auto pooled = BackendConnectionPool::instance().acquire(
                backend_pool_key(),
                std::chrono::seconds{settings_.backend_idle_connection_ttl_seconds});
            if (pooled) {
                backend_close_requested_ = false;
                backend_stream_.emplace(std::move(*pooled));
                backend_from_pool_ = true;
            }
        }
        if (backend_stream_) {
            write_request_header();
            return;
        }
        connect_backend();
    }

    void prepare_request() {
        remove_forwarding_headers(request_.base());
        strip_hop_headers(request_.base(), websocket_, true);
        request_.set(http::field::host, effective_backend_host());
        request_.set("X-Real-IP", client_ip_);
        request_.set("X-Forwarded-For", client_ip_);
        request_.set("X-Forwarded-Proto", scheme_);
        if (!request_id_.empty()) request_.set("X-Request-ID", request_id_);
        request_.version(11);
        if (!websocket_) {
            request_.keep_alive(settings_.backend_keep_alive && backend_.keep_alive);
            request_.erase(http::field::expect);
        }
    }

    void connect_backend() {
        backend_from_pool_ = false;
        backend_close_requested_ = false;
        if (backend_.protocol == routing::BackendProtocol::https) {
            backend_stream_.emplace(std::in_place_type<BackendTlsStream>, executor_, outbound_tls_context());
            auto& tls_stream = std::get<BackendTlsStream>(*backend_stream_);
            const auto sni = effective_tls_sni();
            boost::system::error_code address_error;
            static_cast<void>(asio::ip::make_address(sni, address_error));
            if (address_error && SSL_set_tlsext_host_name(tls_stream.native_handle(), sni.c_str()) != 1) {
                return fail(boost::system::errc::make_error_code(
                    boost::system::errc::invalid_argument));
            }
            if (backend_.tls_verify_certificate) {
                tls_stream.set_verify_mode(asio::ssl::verify_peer);
                tls_stream.set_verify_callback(asio::ssl::host_name_verification(sni));
            } else {
                tls_stream.set_verify_mode(asio::ssl::verify_none);
            }
        } else {
            backend_stream_.emplace(std::in_place_type<BackendPlainStream>, executor_);
        }
        connecting_ = true;
        connect_timer_.expires_after(std::chrono::seconds{backend_.connect_timeout_seconds});
        connect_timer_.async_wait(bind_to_executor(
            guarded_handler(&Self::on_connect_timeout)));
        resolver_.async_resolve(
            backend_.address,
            std::to_string(backend_.port),
            bind_to_executor(guarded_handler(&Self::on_resolved)));
    }

    void on_connect_timeout(const boost::system::error_code& error) {
        if (error || !connecting_ || completed_) return;
        connecting_ = false;
        resolver_.cancel();
        close_backend();
        fail(asio::error::timed_out);
    }

    void on_resolved(
        const boost::system::error_code& error,
        const tcp::resolver::results_type& endpoints) {
        if (!connecting_ || completed_) return;
        if (error) {
            connecting_ = false;
            connect_timer_.cancel();
            return fail(error);
        }
        expire_backend_after(std::chrono::seconds{backend_.connect_timeout_seconds});
        start_backend_operation([this, &endpoints] {
            with_backend([this, &endpoints](auto& stream) {
                beast::get_lowest_layer(stream).async_connect(
                    endpoints,
                    bind_to_executor(guarded_connect_handler(&Self::on_connect)));
            });
        });
    }

    void on_connect(
        const boost::system::error_code& error,
        const tcp::endpoint&) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (!connecting_ || completed_) return;
        if (error) return fail(error);
        if (backend_.protocol == routing::BackendProtocol::https) {
            expire_backend_after(std::chrono::seconds{backend_.connect_timeout_seconds});
            return start_backend_operation([this] {
                std::get<BackendTlsStream>(*backend_stream_).async_handshake(
                    asio::ssl::stream_base::client,
                    bind_to_executor(guarded_handler(&Self::on_tls_handshake)));
            });
        }
        connecting_ = false;
        connect_timer_.cancel();
        write_request_header();
    }

    void on_tls_handshake(const boost::system::error_code& error) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (!connecting_ || completed_) return;
        connecting_ = false;
        connect_timer_.cancel();
        if (error) return fail(error);
        write_request_header();
    }

    void write_request_header() {
        request_serializer_.emplace(request_);
        expire_backend_after(std::chrono::seconds{settings_.backend_idle_timeout_seconds});
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                http::async_write_header(
                    stream, *request_serializer_,
                    bind_to_executor(guarded_handler(&Self::on_request_header_written)));
            });
        });
    }

    void on_request_header_written(
        const boost::system::error_code& error,
        std::size_t bytes_transferred) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) {
            if (backend_from_pool_ && !retried_pooled_connection_ && bytes_transferred == 0) {
                retried_pooled_connection_ = true;
                close_backend();
                request_serializer_.reset();
                return connect_backend();
            }
            return fail(error);
        }
        backend_from_pool_ = false;
        request_serializer_.reset();
        if (websocket_) return read_upgrade_response();
        if (!client_parser_.is_done()) {
            if (expect_continue_) return send_continue();
            read_response_header();
            return read_request_body_chunk();
        }
        request_upload_complete_ = true;
        read_response_header();
    }

    void send_continue() {
        continue_response_ = std::make_shared<http::response<http::empty_body>>(
            http::status::continue_, client_version_);
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_write_timeout_seconds});
        start_client_operation([this] {
            http::async_write(
                downstream_, *continue_response_,
                guarded_handler(&Self::on_continue_written));
        });
    }

    void on_continue_written(const boost::system::error_code& error, std::size_t) {
        finish_client_operation();
        continue_response_.reset();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        read_response_header();
        read_request_body_chunk();
    }

    void read_request_body_chunk() {
        if (completed_ || stop_request_upload_) return;
        auto& body = client_parser_.get().body();
        body.data = http_transfer_buffer_->bytes.data();
        body.size = http_transfer_buffer_->bytes.size();
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_body_timeout_seconds});
        start_client_operation([this] {
            http::async_read_some(
                downstream_, client_buffer_, client_parser_,
                guarded_handler(&Self::on_request_body_read));
        });
    }

    void on_request_body_read(const boost::system::error_code& error, std::size_t) {
        finish_client_operation();
        if (deferred_finish_) {
            maybe_finish_deferred();
            return;
        }
        if (completed_ || stop_request_upload_) return;
        if (error && error != http::error::need_buffer) {
            const bool timeout = error == beast::error::timeout || error == asio::error::timed_out;
            const auto status = error == http::error::body_limit
                                    ? http::status::payload_too_large
                                    : timeout ? http::status::request_timeout
                                              : http::status::bad_request;
            return send_error(
                status,
                error == http::error::body_limit
                    ? "Payload Too Large"
                    : timeout ? "Request Timeout" : "Invalid Request Body");
        }
        auto& body = client_parser_.get().body();
        const auto produced = http_transfer_buffer_->bytes.size() - body.size;
        request_body_done_ = client_parser_.is_done();
        if (produced == 0) {
            if (request_body_done_) return finish_request_body();
            return read_request_body_chunk();
        }
        expire_backend_after(std::chrono::seconds{settings_.backend_idle_timeout_seconds});
        if (request_.chunked()) {
            return start_backend_operation([this, produced] {
                with_backend([this, produced](auto& stream) {
                    asio::async_write(
                        stream, http::make_chunk(asio::buffer(
                            http_transfer_buffer_->bytes.data(), produced)),
                        bind_to_executor(guarded_handler(&Self::on_request_body_written)));
                });
            });
        }
        start_backend_operation([this, produced] {
            with_backend([this, produced](auto& stream) {
                asio::async_write(
                    stream, asio::buffer(http_transfer_buffer_->bytes.data(), produced),
                    bind_to_executor(guarded_handler(&Self::on_request_body_written)));
            });
        });
    }

    void on_request_body_written(const boost::system::error_code& error, std::size_t) {
        finish_backend_operation();
        if (deferred_finish_) {
            maybe_finish_deferred();
            return;
        }
        if (completed_ || stop_request_upload_) return;
        if (error) return fail(error);
        if (request_body_done_) return finish_request_body();
        read_request_body_chunk();
    }

    void finish_request_body() {
        if (completed_ || stop_request_upload_) return;
        if (!request_.chunked()) {
            request_upload_complete_ = true;
            return;
        }
        expire_backend_after(std::chrono::seconds{settings_.backend_idle_timeout_seconds});
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                asio::async_write(
                    stream, http::make_chunk_last(),
                    bind_to_executor(guarded_handler(&Self::on_request_body_finished)));
            });
        });
    }

    void on_request_body_finished(const boost::system::error_code& error, std::size_t) {
        finish_backend_operation();
        if (deferred_finish_) {
            maybe_finish_deferred();
            return;
        }
        if (completed_ || stop_request_upload_) return;
        if (error) return fail(error);
        request_upload_complete_ = true;
    }

    void read_response_header() {
        if (response_header_started_ || completed_) return;
        response_header_started_ = true;
        response_parser_.emplace();
        response_parser_->header_limit(64 * 1024);
        response_parser_->body_limit(std::numeric_limits<std::uint64_t>::max());
        response_parser_->skip(head_request_);
        expire_backend_after(std::chrono::seconds{backend_.response_timeout_seconds});
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                http::async_read_header(
                    stream, backend_buffer_, *response_parser_,
                    bind_to_executor(guarded_handler(&Self::on_response_header)));
            });
        });
    }

    void on_response_header(const boost::system::error_code& error, std::size_t) {
        finish_backend_operation();
        if (backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        auto& response = response_parser_->get();
        if (response.result_int() >= 100 && response.result_int() < 200 &&
            response.result() != http::status::switching_protocols) {
            response_parser_.reset();
            response_header_started_ = false;
            read_response_header();
            return;
        }
        if (response.result() == http::status::switching_protocols) {
            return send_error(http::status::bad_gateway, "Unexpected protocol upgrade");
        }
        early_backend_response_ = !request_upload_complete_;
        stop_request_upload_ = early_backend_response_;
        if (early_backend_response_) {
            client_keep_alive_ = false;
            if (!response_parser_->is_done()) {
                try {
                    response_transfer_buffer_ = std::make_unique<HttpTransferBuffer>();
                } catch (const std::bad_alloc&) {
                    return send_error(
                        http::status::service_unavailable,
                        "Insufficient Memory");
                }
            }
        }
        status_ = response.result_int();
        backend_keep_alive_ = response.keep_alive() && !early_backend_response_;
        strip_hop_headers(response.base(), false, true);
        if (!request_id_.empty()) response.set("X-Request-ID", request_id_);
        response.version(client_version_);
        response.keep_alive(client_keep_alive_);
        response.body().data = nullptr;
        response.body().size = 0;
        response.body().more = !response_parser_->is_done();
        response_serializer_.emplace(response);
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_write_timeout_seconds});
        start_client_operation([this] {
            http::async_write_header(
                downstream_, *response_serializer_,
                guarded_handler(&Self::on_header_written));
        });
    }

    void on_header_written(const boost::system::error_code& error, std::size_t) {
        finish_client_operation();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail_after_header(error);
        if (response_parser_->is_done()) {
            if (response_serializer_->is_done()) return finish_normal();
            return start_client_operation([this] {
                http::async_write_some(
                    downstream_, *response_serializer_,
                    guarded_handler(&Self::on_body_written));
            });
        }
        read_body_chunk();
    }

    void read_body_chunk() {
        auto& transfer = response_transfer_buffer_
                             ? *response_transfer_buffer_
                             : *http_transfer_buffer_;
        auto& body = response_parser_->get().body();
        body.data = transfer.bytes.data();
        body.size = transfer.bytes.size();
        expire_backend_after(std::chrono::seconds{settings_.backend_idle_timeout_seconds});
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                http::async_read_some(
                    stream, backend_buffer_, *response_parser_,
                    bind_to_executor(guarded_handler(&Self::on_body_read)));
            });
        });
    }

    void on_body_read(const boost::system::error_code& error, std::size_t) {
        finish_backend_operation();
        if (backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error && error != http::error::need_buffer) return fail_after_header(error);
        auto& transfer = response_transfer_buffer_
                             ? *response_transfer_buffer_
                             : *http_transfer_buffer_;
        auto& body = response_parser_->get().body();
        const auto produced = transfer.bytes.size() - body.size;
        body.data = transfer.bytes.data();
        body.size = produced;
        body.more = !response_parser_->is_done();
        response_bytes_ += produced;
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_write_timeout_seconds});
        start_client_operation([this] {
            http::async_write_some(
                downstream_, *response_serializer_,
                guarded_handler(&Self::on_body_written));
        });
    }

    void on_body_written(
        const boost::system::error_code& error,
        std::size_t) {
        finish_client_operation();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }

        // With buffer_body, need_buffer is not a failure. It means the current
        // body buffer was consumed and the serializer needs the next one.
        if (error == http::error::need_buffer) {
            if (response_parser_->is_done() && response_serializer_->is_done()) {
                return finish_normal();
            }
            return read_body_chunk();
        }

        if (error) return fail_after_header(error);

        if (response_serializer_->is_done()) return finish_normal();

        start_client_operation([this] {
            http::async_write_some(
                downstream_,
                *response_serializer_,
                guarded_handler(&Self::on_body_written));
        });
    }

    void finish_normal() {
        if (early_backend_response_ || !request_upload_complete_) {
            close_backend();
            finish_when_io_quiesced(status_, response_bytes_, false);
            return;
        }
        const bool reusable = settings_.backend_keep_alive && backend_.keep_alive &&
                              backend_keep_alive_ && backend_stream_ && backend_socket_open();
        if (reusable) {
            expire_backend_never();
            BackendConnectionPool::instance().release(
                backend_pool_key(),
                std::move(*backend_stream_),
                settings_.backend_pool_size,
                std::chrono::seconds{settings_.backend_idle_connection_ttl_seconds});
            backend_stream_.reset();
        } else {
            close_backend();
        }
        finish(status_, response_bytes_, client_keep_alive_);
    }

    void read_upgrade_response() {
        upgrade_parser_.emplace();
        upgrade_parser_->header_limit(64 * 1024);
        expire_backend_after(std::chrono::seconds{backend_.response_timeout_seconds});
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                http::async_read_header(
                    stream, backend_buffer_, *upgrade_parser_,
                    bind_to_executor(guarded_handler(&Self::on_upgrade_response)));
            });
        });
    }

    void on_upgrade_response(const boost::system::error_code& error, std::size_t) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        if (upgrade_parser_->get().result() != http::status::switching_protocols) {
            return send_error(http::status::bad_gateway, "WebSocket backend rejected upgrade");
        }
        // Full-duplex buffers only exist after the backend accepted the upgrade.
        try {
            tunnel_buffers_ = std::make_unique<TunnelBuffers>();
        } catch (const std::bad_alloc&) {
            return send_error(
                http::status::service_unavailable,
                "Insufficient Memory");
        }
        status_ = 101;
        auto response = upgrade_parser_->release();
        response.version(client_version_);
        if (!request_id_.empty()) response.set("X-Request-ID", request_id_);
        upgrade_response_ = std::make_shared<http::response<http::empty_body>>(std::move(response));
        expire_backend_never();
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_write_timeout_seconds});
        start_client_operation([this] {
            http::async_write(
                downstream_, *upgrade_response_,
                guarded_handler(&Self::on_upgrade_written));
        });
    }

    void on_upgrade_written(const boost::system::error_code& error, std::size_t) {
        finish_client_operation();
        upgrade_response_.reset();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        flush_client_buffer();
    }

    void flush_client_buffer() {
        if (client_buffer_.size() == 0) return flush_backend_buffer();
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                asio::async_write(
                    stream, client_buffer_.data(),
                    bind_to_executor(guarded_handler(&Self::on_client_buffer_flushed)));
            });
        });
    }

    void on_client_buffer_flushed(const boost::system::error_code& error, std::size_t bytes) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        client_buffer_.consume(bytes);
        flush_backend_buffer();
    }

    void flush_backend_buffer() {
        if (backend_buffer_.size() == 0) return start_tunnel();
        start_client_operation([this] {
            asio::async_write(
                downstream_, backend_buffer_.data(),
                guarded_handler(&Self::on_backend_buffer_flushed));
        });
    }

    void on_backend_buffer_flushed(const boost::system::error_code& error, std::size_t bytes) {
        finish_client_operation();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return fail(error);
        backend_buffer_.consume(bytes);
        start_tunnel();
    }

    void start_tunnel() {
        beast::get_lowest_layer(downstream_).expires_never();
        read_from_client();
        read_from_backend();
    }

    void read_from_client() {
        start_client_operation([this] {
            downstream_.async_read_some(
                asio::buffer(tunnel_buffers_->client_to_backend),
                guarded_handler(&Self::on_client_tunnel_read));
        });
    }

    void on_client_tunnel_read(const boost::system::error_code& error, std::size_t bytes) {
        finish_client_operation();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return finish_tunnel(error);
        start_backend_operation([this, bytes] {
            with_backend([this, bytes](auto& stream) {
                asio::async_write(
                    stream, asio::buffer(tunnel_buffers_->client_to_backend.data(), bytes),
                    bind_to_executor(guarded_handler(&Self::on_backend_tunnel_written)));
            });
        });
    }

    void on_backend_tunnel_written(const boost::system::error_code& error, std::size_t bytes) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return finish_tunnel(error);
        response_bytes_ += bytes;
        read_from_client();
    }

    void read_from_backend() {
        start_backend_operation([this] {
            with_backend([this](auto& stream) {
                stream.async_read_some(
                    asio::buffer(tunnel_buffers_->backend_to_client),
                    bind_to_executor(guarded_handler(&Self::on_backend_tunnel_read)));
            });
        });
    }

    void on_backend_tunnel_read(const boost::system::error_code& error, std::size_t bytes) {
        finish_backend_operation();
        if (deferred_finish_ || backend_close_requested_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return finish_tunnel(error);
        start_client_operation([this, bytes] {
            asio::async_write(
                downstream_, asio::buffer(tunnel_buffers_->backend_to_client.data(), bytes),
                guarded_handler(&Self::on_client_tunnel_written));
        });
    }

    void on_client_tunnel_written(const boost::system::error_code& error, std::size_t bytes) {
        finish_client_operation();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        if (error) return finish_tunnel(error);
        response_bytes_ += bytes;
        read_from_backend();
    }

    void finish_tunnel(const boost::system::error_code& error) {
        if (completed_) return;
        if (error != asio::error::eof && error != asio::error::operation_aborted && failure_) {
            failure_(error);
        }
        close_backend();
        finish_when_io_quiesced(101, response_bytes_, false);
    }

    void send_error(http::status status, std::string body) {
        close_backend();
        status_ = static_cast<unsigned>(status);
        error_response_ = std::make_shared<http::response<http::string_body>>(status, client_version_);
        error_response_->set(http::field::server, BOOST_BEAST_VERSION_STRING);
        error_response_->set(http::field::content_type, "text/plain; charset=utf-8");
        if (status == http::status::service_unavailable) {
            error_response_->set(http::field::retry_after, std::to_string(overload_.queue_timeout_seconds));
        }
        error_keep_alive_ = client_keep_alive_ && client_parser_.is_done() &&
            status != http::status::bad_request && status != http::status::payload_too_large &&
            status != http::status::request_timeout;
        error_response_->keep_alive(error_keep_alive_);
        error_response_->body() = std::move(body);
        error_response_->prepare_payload();
        response_bytes_ = error_response_->body().size();
        beast::get_lowest_layer(downstream_).expires_after(
            std::chrono::seconds{settings_.client_write_timeout_seconds});
        start_client_operation([this] {
            http::async_write(
                downstream_, *error_response_,
                guarded_handler(&Self::on_error_written));
        });
    }

    void on_error_written(const boost::system::error_code& error, std::size_t) {
        finish_client_operation();
        error_response_.reset();
        if (deferred_finish_ || completed_) {
            maybe_finish_deferred();
            return;
        }
        finish_when_io_quiesced(
            status_, response_bytes_, !error && error_keep_alive_);
    }

    void fail(const boost::system::error_code& error) {
        if (completed_) return;
        connecting_ = false;
        connect_timer_.cancel();
        resolver_.cancel();
        if (failure_) failure_(error);
        const bool timeout = error == beast::error::timeout || error == asio::error::timed_out;
        send_error(timeout ? http::status::gateway_timeout : http::status::bad_gateway,
                   timeout ? "Gateway Timeout" : "Bad Gateway");
    }

    void fail_after_header(const boost::system::error_code& error) {
        if (completed_) return;
        if (failure_) failure_(error);
        close_backend();
        finish_when_io_quiesced(
            status_ == 0 ? 502U : status_, response_bytes_, false);
    }

    void abort_from_exception_noexcept() noexcept {
        const bool completion_already_started = completed_;

        connecting_ = false;
        try {
            if (pending_acquire_) pending_acquire_->cancel();
        } catch (...) {
        }
        boost::system::error_code ignored;
        try {
            connect_timer_.cancel();
        } catch (...) {
        }
        resolver_.cancel();
        try {
            close_backend();
        } catch (...) {
        }

        auto& lowest = beast::get_lowest_layer(downstream_);
        try {
            lowest.expires_never();
        } catch (...) {
        }
        lowest.socket().cancel(ignored);
        lowest.socket().shutdown(tcp::socket::shutdown_both, ignored);
        lowest.socket().close(ignored);

        if (completion_already_started) return;
        deferred_finish_ = DeferredFinish{
            status_ == 0 ? 500U : status_, response_bytes_, false};
        client_cancel_requested_ = true;
        try {
            maybe_finish_deferred();
        } catch (...) {
            // All production completion handlers are noexcept. Keep the
            // operation closed even if a third-party completion violates that
            // contract.
        }
    }

    void close_backend() {
        if (!backend_stream_) return;
        backend_close_requested_ = true;
        expire_backend_never();
        with_backend([](auto& stream) {
            auto& lowest = beast::get_lowest_layer(stream);
            boost::system::error_code ignored;
            lowest.socket().shutdown(tcp::socket::shutdown_both, ignored);
            lowest.socket().close(ignored);
        });
        maybe_release_closed_backend();
    }

    void maybe_release_closed_backend() {
        if (backend_close_requested_ && backend_operations_pending_ == 0) {
            backend_stream_.reset();
        }
    }

    void finish_when_io_quiesced(unsigned status, std::uint64_t bytes, bool keep_alive) {
        if (completed_) return;
        deferred_finish_ = DeferredFinish{status, bytes, keep_alive};
        if (client_operations_pending_ != 0 && !client_cancel_requested_) {
            client_cancel_requested_ = true;
            boost::system::error_code ignored;
            beast::get_lowest_layer(downstream_).socket().cancel(ignored);
        }
        maybe_finish_deferred();
    }

    void maybe_finish_deferred() {
        if (!deferred_finish_ || client_operations_pending_ != 0 ||
            backend_operations_pending_ != 0) {
            return;
        }
        maybe_release_closed_backend();
        const auto deferred = *deferred_finish_;
        deferred_finish_.reset();
        finish(deferred.status, deferred.bytes, deferred.keep_alive);
    }

    void finish(unsigned status, std::uint64_t bytes, bool keep_alive) {
        if (completed_) return;
        completed_ = true;
        connecting_ = false;
        connect_timer_.cancel();
        resolver_.cancel();
        if (pending_acquire_) pending_acquire_->cancel();
        pending_acquire_.reset();
        permit_.reset();
        if (completion_) {
            auto completion = std::move(completion_);
            completion(status, bytes, keep_alive);
        }
        failure_ = {};
    }

    Downstream& downstream_;
    beast::flat_buffer& client_buffer_;
    http::request_parser<http::buffer_body>& client_parser_;
    asio::any_io_executor executor_;
    routing::BackendConfig backend_;
    tcp::resolver resolver_;
    asio::steady_timer connect_timer_;
    Request request_;
    std::string client_ip_;
    std::string scheme_;
    std::string request_id_;
    config::RuntimeSettings settings_;
    routing::BackendOverloadConfig overload_;
    Completion completion_;
    Failure failure_;
    std::optional<BackendStream> backend_stream_;
    std::shared_ptr<BackendConcurrencyLimiter::Pending> pending_acquire_;
    std::shared_ptr<BackendConcurrencyLimiter::Permit> permit_;
    std::optional<http::request_serializer<http::empty_body>> request_serializer_;
    beast::flat_buffer backend_buffer_;
    std::optional<ResponseParser> response_parser_;
    std::optional<ResponseSerializer> response_serializer_;
    std::optional<UpgradeParser> upgrade_parser_;
    std::shared_ptr<http::response<http::empty_body>> upgrade_response_;
    std::shared_ptr<http::response<http::empty_body>> continue_response_;
    std::shared_ptr<http::response<http::string_body>> error_response_;
    std::unique_ptr<HttpTransferBuffer> http_transfer_buffer_;
    std::unique_ptr<HttpTransferBuffer> response_transfer_buffer_;
    std::unique_ptr<TunnelBuffers> tunnel_buffers_;
    std::optional<DeferredFinish> deferred_finish_;
    unsigned client_version_{};
    bool client_keep_alive_{};
    bool head_request_{};
    bool websocket_{};
    bool expect_continue_{};
    bool request_body_done_{};
    bool request_upload_complete_{};
    bool response_header_started_{};
    bool early_backend_response_{};
    bool stop_request_upload_{};
    bool client_cancel_requested_{};
    bool backend_close_requested_{};
    bool backend_from_pool_{};
    bool retried_pooled_connection_{};
    bool error_keep_alive_{};
    bool backend_keep_alive_{};
    bool connecting_{};
    bool completed_{};
    std::size_t client_operations_pending_{};
    std::size_t backend_operations_pending_{};
    unsigned status_{};
    std::uint64_t response_bytes_{};
};

} // namespace detail

template <typename Downstream>
using ProxyTransaction = detail::ProxyTransactionImpl<Downstream>;

} // namespace webserver::proxy
