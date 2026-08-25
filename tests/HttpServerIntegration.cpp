#include "core/ServerCore.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/system/system_error.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

std::string header_value(const http::fields& fields, const char* name) {
    const auto value = fields[name];
    return std::string{value.data(), value.size()};
}

std::string view_string(beast::string_view value) {
    return std::string{value.data(), value.size()};
}

class BackendFixture final {
public:
    BackendFixture()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()) {
        acceptor_.non_blocking(true);
        worker_ = std::thread([this] { run(); });
    }

    ~BackendFixture() {
        stopping_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
        boost::system::error_code ignored;
        acceptor_.close(ignored);
    }

    BackendFixture(const BackendFixture&) = delete;
    BackendFixture& operator=(const BackendFixture&) = delete;

    [[nodiscard]] tcp::endpoint endpoint() const {
        return endpoint_;
    }

    void join_and_rethrow() {
        if (worker_.joinable()) {
            worker_.join();
        }
        if (failure_) {
            std::rethrow_exception(failure_);
        }
    }

private:
    void run() noexcept {
        try {
            std::size_t request_number = 0;
            while (request_number < 2 && !stopping_.load()) {
                tcp::socket socket{io_context_};
                boost::system::error_code accept_error;
                acceptor_.accept(socket, accept_error);
                if (accept_error == asio::error::would_block ||
                    accept_error == asio::error::try_again) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                if (accept_error) {
                    if (stopping_.load() || accept_error == asio::error::operation_aborted) {
                        return;
                    }
                    throw boost::system::system_error{accept_error};
                }

                handle_request(socket, request_number);
                ++request_number;
            }

            boost::system::error_code ignored;
            acceptor_.close(ignored);
        } catch (...) {
            failure_ = std::current_exception();
            boost::system::error_code ignored;
            acceptor_.close(ignored);
        }
    }

    static void handle_request(tcp::socket& socket, std::size_t request_number) {
        beast::flat_buffer buffer;
        http::request<http::string_body> request;
        http::read(socket, buffer, request);

        require(
            request.base().count("X-Client-Hop") == 0,
            "client Connection-nominated header reached the backend");
        require(
            request.base().count("Forwarded") == 0 &&
                request.base().count("CF-Connecting-IP") == 0,
            "untrusted forwarding header reached the backend");
        require(
            header_value(request.base(), "X-Real-IP") == "127.0.0.1" &&
                header_value(request.base(), "X-Forwarded-For") == "127.0.0.1",
            "proxy did not rebuild client IP headers from the TCP peer");
        require(
            header_value(request.base(), "X-Forwarded-Proto") == "http",
            "proxy sent the wrong forwarded protocol");
        require(
            header_value(request.base(), "X-Request-ID").size() == 32 &&
                header_value(request.base(), "X-Request-ID") != "client-spoofed-id",
            "proxy did not replace the untrusted request ID");
        require(request.keep_alive(), "proxy did not enable backend keep-alive");

        if (request_number == 0) {
            require(request.method() == http::verb::post, "POST method was not forwarded");
            require(request.target() == "/submit?source=test", "request target was not forwarded");
            require(request.body() == "payload", "request body was not forwarded");
        } else {
            require(request.method() == http::verb::get, "GET method was not forwarded");
            require(request.target() == "/health", "second request target was not forwarded");
        }

        http::response<http::string_body> response{http::status::accepted, 11};
        response.set(http::field::content_type, "text/plain");
        response.set("X-Backend-Host", request[http::field::host]);
        response.set("X-Backend-Target", request.target());
        response.set("X-Backend-Method", request.method_string());
        response.set("X-Backend-Request-ID", request["X-Request-ID"]);
        response.set("X-Remove-Me", "backend-only-hop-header");
        response.set(http::field::connection, "close, X-Remove-Me");
        response.body() = view_string(request.method_string()) + " " +
                          view_string(request.target()) + " " + request.body();
        response.prepare_payload();
        http::write(socket, response);

        boost::system::error_code ignored;
        socket.shutdown(tcp::socket::shutdown_both, ignored);
        socket.close(ignored);
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::atomic_bool stopping_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

http::response<http::string_body> send_request(
    beast::tcp_stream& stream,
    beast::flat_buffer& buffer,
    http::request<http::string_body> request) {
    http::write(stream, request);

    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return response;
}

void run_test() {
    BackendFixture backend;
    const auto backend_endpoint = backend.endpoint();

    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {
        webserver::routing::VirtualHostConfig{
            "example-site",
            {"example.com", "www.example.com"},
            webserver::routing::BackendConfig{
                backend_endpoint.address().to_string(), backend_endpoint.port()}},
        webserver::routing::VirtualHostConfig{
            "offline-site",
            {"down.example"},
            webserver::routing::BackendConfig{
                backend_endpoint.address().to_string(), backend_endpoint.port()}},
    };

    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        const auto endpoint = server.local_endpoint();
        asio::io_context client_context;
        beast::tcp_stream stream{client_context};
        stream.socket().connect(endpoint);
        beast::flat_buffer buffer;

        http::request<http::string_body> first_request{
            http::verb::post, "/submit?source=test", 11};
        first_request.set(
            http::field::host, "EXAMPLE.COM:" + std::to_string(endpoint.port()));
        first_request.set(http::field::user_agent, "WebServer integration test");
        first_request.set("X-Forwarded-For", "203.0.113.10");
        first_request.set("X-Real-IP", "203.0.113.11");
        first_request.set("Forwarded", "for=203.0.113.12");
        first_request.set("CF-Connecting-IP", "203.0.113.13");
        first_request.set("X-Request-ID", "client-spoofed-id");
        first_request.set("X-Client-Hop", "must-not-reach-backend");
        first_request.set(http::field::connection, "keep-alive, X-Client-Hop");
        first_request.body() = "payload";
        first_request.prepare_payload();

        const auto first = send_request(stream, buffer, std::move(first_request));
        require(first.result() == http::status::accepted, "proxied POST did not return HTTP 202");
        require(
            first.body() == "POST /submit?source=test payload",
            "proxied POST returned the wrong response body");
        require(
            header_value(first.base(), "X-Backend-Host") ==
                "EXAMPLE.COM:" + std::to_string(endpoint.port()),
            "proxy did not preserve the original Host header");
        require(
            first.base().count("X-Remove-Me") == 0,
            "backend Connection-nominated header reached the client");
        require(first.keep_alive(), "first client response did not preserve keep-alive");
        require(
            header_value(first.base(), "X-Request-ID") ==
                header_value(first.base(), "X-Backend-Request-ID"),
            "client and backend did not receive the same generated request ID");

        http::request<http::string_body> second_request{http::verb::get, "/health", 11};
        second_request.set(http::field::host, "www.example.com");
        second_request.keep_alive(true);
        const auto second = send_request(stream, buffer, std::move(second_request));
        require(second.result() == http::status::accepted, "proxied GET did not return HTTP 202");
        require(second.body() == "GET /health ", "proxied GET returned the wrong response body");
        require(
            header_value(second.base(), "X-Backend-Target") == "/health",
            "backend response header was not forwarded");
        require(second.keep_alive(), "second client response did not preserve keep-alive");
        require(
            header_value(second.base(), "X-Request-ID") !=
                header_value(first.base(), "X-Request-ID"),
            "keep-alive requests reused a request ID");

        backend.join_and_rethrow();

        http::request<http::string_body> offline_request{http::verb::get, "/", 11};
        offline_request.set(http::field::host, "down.example");
        offline_request.keep_alive(true);
        const auto offline = send_request(stream, buffer, std::move(offline_request));
        require(offline.result() == http::status::bad_gateway, "offline backend did not return 502");
        require(offline.body() == "Bad Gateway", "offline backend returned the wrong body");
        require(offline.keep_alive(), "502 response unexpectedly closed the client connection");

        http::request<http::string_body> missing_request{http::verb::get, "/", 11};
        missing_request.set(http::field::host, "unknown.example");
        missing_request.keep_alive(false);
        const auto missing = send_request(stream, buffer, std::move(missing_request));
        require(missing.result() == http::status::not_found, "unknown host did not return HTTP 404");
        require(missing.body() == "Virtual host not found", "unknown host returned the wrong body");
        require(!missing.keep_alive(), "unknown-host response did not close the connection");

        boost::system::error_code ignored;
        stream.socket().shutdown(tcp::socket::shutdown_both, ignored);
        stream.socket().close(ignored);

        beast::tcp_stream idle_stream{client_context};
        idle_stream.socket().connect(endpoint);
        beast::flat_buffer idle_buffer;
        http::request<http::string_body> idle_request{http::verb::get, "/", 11};
        idle_request.set(http::field::host, "down.example");
        idle_request.keep_alive(true);
        const auto idle_response = send_request(
            idle_stream, idle_buffer, std::move(idle_request));
        require(idle_response.result() == http::status::bad_gateway, "idle setup did not return 502");

        server.stop();
        server.wait();

        std::array<char, 1> probe{};
        boost::system::error_code close_error;
        const auto received_bytes = idle_stream.socket().read_some(
            asio::buffer(probe), close_error);
        require(received_bytes == 0, "server sent unexpected data during graceful stop");
        require(
            close_error == asio::error::eof || close_error == asio::error::connection_reset,
            "graceful stop did not close an idle keep-alive session");
        idle_stream.socket().close(ignored);
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }

    server.stop();
    server.wait();
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "HTTP reverse proxy integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "HTTP reverse proxy integration test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
