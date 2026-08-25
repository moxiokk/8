#include "core/ServerCore.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/buffers_to_string.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/system/system_error.hpp>
#include <openssl/ssl.h>

#include <chrono>
#include <exception>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

class WebSocketBackend final {
public:
    WebSocketBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          worker_([this] { run(); }) {}

    ~WebSocketBackend() {
        boost::system::error_code ignored;
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
            tcp::socket socket{io_context_};
            acceptor_.accept(socket);
            websocket::stream<tcp::socket> stream{std::move(socket)};
            stream.accept();
            beast::flat_buffer buffer;
            stream.read(buffer);
            stream.text(stream.got_text());
            stream.write(buffer.data());
            boost::system::error_code ignored;
            stream.close(websocket::close_code::normal, ignored);
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    std::thread worker_;
    std::exception_ptr failure_;
};

class CancelledWebSocketBackend final {
public:
    CancelledWebSocketBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          ready_(ready_promise_.get_future()),
          worker_([this] { run(); }) {}

    ~CancelledWebSocketBackend() {
        boost::system::error_code ignored;
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    [[nodiscard]] tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

    void wait_until_ready() {
        require(ready_.wait_for(2s) == std::future_status::ready,
                "cancellation backend did not complete the WebSocket handshake");
    }

    void rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            tcp::socket socket{io_context_};
            acceptor_.accept(socket);
            websocket::stream<tcp::socket> stream{std::move(socket)};
            stream.accept();
            ready_promise_.set_value();
            beast::flat_buffer buffer;
            boost::system::error_code error;
            stream.read(buffer, error);
            if (error && error != websocket::error::closed &&
                error != asio::error::eof && error != asio::error::connection_reset &&
                error != asio::error::operation_aborted) {
                throw boost::system::system_error{error};
            }
        } catch (...) {
            try {
                ready_promise_.set_value();
            } catch (...) {
            }
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    std::promise<void> ready_promise_;
    std::future<void> ready_;
    std::thread worker_;
    std::exception_ptr failure_;
};

void run_test() {
    WebSocketBackend backend;
    const auto backend_endpoint = backend.endpoint();

    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "websocket-site",
        {"ws.test"},
        webserver::routing::BackendConfig{
            backend_endpoint.address().to_string(), backend_endpoint.port()}}};
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        asio::io_context io_context;
        websocket::stream<beast::tcp_stream> client{io_context};
        client.next_layer().socket().connect(server.local_endpoint());
        client.handshake("ws.test", "/socket");
        client.text(true);
        client.write(asio::buffer(std::string{"websocket-through-proxy"}));
        beast::flat_buffer response;
        client.read(response);
        require(
            beast::buffers_to_string(response.data()) == "websocket-through-proxy",
            "WebSocket payload was not relayed in both directions");
        boost::system::error_code ignored;
        client.close(websocket::close_code::normal, ignored);
        server.stop();
        server.wait();
        backend.rethrow();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }
}

void run_tls_cancellation_test(const char* certificate, const char* private_key) {
    CancelledWebSocketBackend backend;
    const auto backend_endpoint = backend.endpoint();

    webserver::core::ServerOptions options;
    options.port = 0;
    options.https_port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "websocket-cancellation-site",
        {"a.test"},
        webserver::routing::BackendConfig{
            backend_endpoint.address().to_string(), backend_endpoint.port()}}};
    options.tls_certificates = {webserver::tls::TlsCertificateConfig{
        "a", {"a.test"}, certificate, private_key, true}};

    webserver::core::ServerCore server{std::move(options)};
    server.start();
    try {
        const auto endpoint = server.tls_local_endpoint();
        require(endpoint.has_value(), "TLS WebSocket listener did not start");

        asio::io_context client_context;
        asio::ssl::context tls_context{asio::ssl::context::tls_client};
        tls_context.set_verify_mode(asio::ssl::verify_none);
        websocket::stream<asio::ssl::stream<beast::tcp_stream>> client{
            client_context, tls_context};
        require(SSL_set_tlsext_host_name(
                    client.next_layer().native_handle(), "a.test") == 1,
                "could not configure TLS WebSocket SNI");
        beast::get_lowest_layer(client).socket().connect(*endpoint);
        client.next_layer().handshake(asio::ssl::stream_base::client);
        client.handshake("a.test", "/cancel");
        backend.wait_until_ready();
        std::this_thread::sleep_for(25ms);

        server.stop();
        std::this_thread::sleep_for(25ms);
        boost::system::error_code ignored;
        client.next_layer().shutdown(ignored);
        beast::get_lowest_layer(client).socket().close(ignored);
        server.wait();
        backend.rethrow();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        require(argc == 3, "expected certificate and private-key paths");
        run_test();
        run_tls_cancellation_test(argv[1], argv[2]);
        std::cout << "WebSocket integration test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "WebSocket integration test failed: " << error.what() << '\n';
        return 1;
    }
}
