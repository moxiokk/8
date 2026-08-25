#include "core/ServerCore.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/parser.hpp>
#include <boost/beast/http/empty_body.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>

#include <exception>
#include <array>
#include <atomic>
#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

class KeepAliveBackend final {
public:
    KeepAliveBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          socket_(io_context_),
          worker_([this] { run(); }) {}

    ~KeepAliveBackend() {
        boost::system::error_code ignored;
        socket_.close(ignored);
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

    void rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            acceptor_.accept(socket_);
            beast::flat_buffer buffer;
            for (int index = 0; index < 3; ++index) {
                http::request_parser<http::string_body> request_parser;
                request_parser.body_limit(12 * 1024 * 1024);
                http::read(socket_, buffer, request_parser);
                auto request = request_parser.release();
                require(request.keep_alive(), "backend request did not request keep-alive");
                if (index == 2) {
                    require(
                        request.method() == http::verb::post &&
                            request.body().size() == 10 * 1024 * 1024 &&
                            request.body().front() == 'U' && request.body().back() == 'U',
                        "streamed upload was not received intact by the backend");
                }

                http::response<http::string_body> response{http::status::ok, 11};
                response.set(http::field::content_type, "application/octet-stream");
                response.keep_alive(index < 2);
                response.body() = index == 0
                                      ? std::string{"pooled-connection-ready"}
                                      : index == 1 ? std::string(9 * 1024 * 1024, 'S')
                                                   : std::string{"upload-streamed"};
                response.prepare_payload();
                http::write(socket_, response);
            }
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::thread worker_;
    std::exception_ptr failure_;
};

class EarlyResponseBackend final {
public:
    EarlyResponseBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          socket_(io_context_),
          worker_([this] { run(); }) {}

    ~EarlyResponseBackend() {
        boost::system::error_code ignored;
        socket_.close(ignored);
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

    void rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            acceptor_.accept(socket_);
            beast::flat_buffer buffer;
            http::request_parser<http::empty_body> parser;
            parser.body_limit(64 * 1024 * 1024);
            http::read_header(socket_, buffer, parser);
            require(
                parser.get().method() == http::verb::post &&
                    parser.content_length_remaining().value_or(0) ==
                        32ULL * 1024ULL * 1024ULL,
                "early-response backend did not receive the upload header");

            http::response<http::string_body> response{
                http::status::payload_too_large, 11};
            response.set(http::field::content_type, "text/plain");
            response.keep_alive(false);
            response.body() = "backend rejected upload from headers";
            response.prepare_payload();
            http::write(socket_, response);
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::thread worker_;
    std::exception_ptr failure_;
};

class CancelledBackend final {
public:
    CancelledBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          socket_(io_context_),
          worker_([this] { run(); }) {}

    ~CancelledBackend() {
        boost::system::error_code ignored;
        socket_.close(ignored);
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    [[nodiscard]] tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

    void wait_for_request() const {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{3};
        while (!request_received_.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
        require(request_received_.load(std::memory_order_acquire),
                "backend did not receive the cancellation fixture request");
    }

    void rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            acceptor_.accept(socket_);
            beast::flat_buffer buffer;
            http::request<http::string_body> request;
            http::read(socket_, buffer, request);
            request_received_.store(true, std::memory_order_release);

            std::array<char, 256> input{};
            boost::system::error_code error;
            while (socket_.read_some(asio::buffer(input), error) != 0 && !error) {
            }
            if (error != asio::error::eof && error != asio::error::connection_reset &&
                error != asio::error::operation_aborted) {
                throw boost::system::system_error{error};
            }
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::atomic_bool request_received_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

http::response<http::string_body> exchange(
    beast::tcp_stream& client,
    beast::flat_buffer& buffer,
    std::string target) {
    http::request<http::string_body> request{http::verb::get, std::move(target), 11};
    request.set(http::field::host, "stream.test");
    request.keep_alive(true);
    http::write(client, request);
    http::response_parser<http::string_body> parser;
    parser.body_limit(12 * 1024 * 1024);
    http::read(client, buffer, parser);
    return parser.release();
}

http::response<http::string_body> upload(
    beast::tcp_stream& client,
    beast::flat_buffer& buffer) {
    http::request<http::string_body> request{http::verb::post, "/upload", 11};
    request.set(http::field::host, "stream.test");
    request.keep_alive(true);
    request.body() = std::string(10 * 1024 * 1024, 'U');
    request.prepare_payload();
    http::write(client, request);
    http::response<http::string_body> response;
    http::read(client, buffer, response);
    return response;
}

void run_test() {
    KeepAliveBackend backend;
    const auto origin = backend.endpoint();
    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "stream-site", {"stream.test"},
        webserver::routing::BackendConfig{origin.address().to_string(), origin.port()}}};
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        asio::io_context io_context;
        beast::tcp_stream client{io_context};
        client.socket().connect(server.local_endpoint());
        beast::flat_buffer buffer;
        const auto first = exchange(client, buffer, "/first");
        require(first.body() == "pooled-connection-ready", "first backend response is incorrect");
        const auto large = exchange(client, buffer, "/large");
        require(
            large.body().size() == 9 * 1024 * 1024 &&
                large.body().front() == 'S' && large.body().back() == 'S',
            "response larger than the former 8 MiB limit was not streamed intact");
        const auto uploaded = upload(client, buffer);
        require(uploaded.body() == "upload-streamed", "10 MiB upload did not stream through proxy");
        server.stop();
        server.wait();
        backend.rethrow();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }
}

void run_early_response_test() {
    EarlyResponseBackend backend;
    const auto origin = backend.endpoint();
    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "early-response-site", {"early.test"},
        webserver::routing::BackendConfig{origin.address().to_string(), origin.port()}}};
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        asio::io_context io_context;
        beast::tcp_stream client{io_context};
        client.expires_after(std::chrono::seconds{5});
        client.connect(server.local_endpoint());

        http::request<http::empty_body> request{http::verb::post, "/huge-upload", 11};
        request.set(http::field::host, "early.test");
        request.content_length(32ULL * 1024ULL * 1024ULL);
        request.keep_alive(true);
        http::request_serializer<http::empty_body> serializer{request};
        http::write_header(client, serializer);

        // Do not send any body bytes. The proxy must concurrently read the
        // Backend response instead of waiting for the declared upload body.
        client.expires_after(std::chrono::seconds{5});
        beast::flat_buffer buffer;
        http::response<http::string_body> response;
        http::read(client, buffer, response);
        require(
            response.result() == http::status::payload_too_large &&
                response.body() == "backend rejected upload from headers",
            "backend 413 was not forwarded before the client upload completed");
        require(!response.keep_alive(), "early response kept an undrained client connection alive");

        server.stop();
        server.wait();
        backend.rethrow();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }
}

void run_cancel_with_pending_backend_io_test() {
    CancelledBackend backend;
    const auto origin = backend.endpoint();
    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "cancel-site", {"cancel.test"},
        webserver::routing::BackendConfig{origin.address().to_string(), origin.port()}}};
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        asio::io_context io_context;
        beast::tcp_stream client{io_context};
        client.connect(server.local_endpoint());
        http::request<http::empty_body> request{http::verb::get, "/pending", 11};
        request.set(http::field::host, "cancel.test");
        request.keep_alive(true);
        http::write(client, request);
        backend.wait_for_request();

        // Shutdown cancels an outstanding Backend response-header read. The
        // stream object must remain alive until its aborted handler returns.
        server.stop();
        server.wait();
        boost::system::error_code ignored;
        client.socket().close(ignored);
        backend.rethrow();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }
}

} // namespace

int main() {
    try {
        run_test();
        run_early_response_test();
        run_cancel_with_pending_backend_io_test();
        std::cout << "Streaming proxy integration test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Streaming proxy integration test failed: " << error.what() << '\n';
        return 1;
    }
}
