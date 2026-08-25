#include "core/ConnectionRegistry.hpp"
#include "core/ServerCore.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/system/system_error.hpp>

#include <openssl/ssl.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <mutex>
#include <optional>
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
    if (!condition) throw std::runtime_error{message};
}

template <typename Predicate>
void wait_until(Predicate predicate, const char* message) {
    const auto deadline = std::chrono::steady_clock::now() + 5s;
    while (!predicate()) {
        if (std::chrono::steady_clock::now() >= deadline) {
            throw std::runtime_error{message};
        }
        std::this_thread::sleep_for(5ms);
    }
}

class BlockingBackend final {
public:
    BlockingBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()),
          worker_([this] { run(); }) {}

    ~BlockingBackend() {
        release_.store(true);
        boost::system::error_code ignored;
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    [[nodiscard]] tcp::endpoint endpoint() const { return endpoint_; }
    [[nodiscard]] bool received() const noexcept { return received_.load(); }
    void release() noexcept { release_.store(true); }

    void join_and_rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            tcp::socket socket{io_context_};
            acceptor_.accept(socket);
            beast::flat_buffer buffer;
            http::request<http::string_body> request;
            http::read(socket, buffer, request);
            require(request.method() == http::verb::get, "backend received wrong method");
            received_.store(true);
            wait_until([this] { return release_.load(); }, "backend release timed out");

            http::response<http::string_body> response{http::status::ok, 11};
            response.body() = "ok";
            response.prepare_payload();
            response.keep_alive(false);
            http::write(socket, response);
            boost::system::error_code ignored;
            socket.close(ignored);
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::atomic_bool received_{false};
    std::atomic_bool release_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

http::response<http::string_body> oversized_http_request(const tcp::endpoint& endpoint) {
    asio::io_context io_context;
    beast::tcp_stream stream{io_context};
    stream.connect(endpoint);
    constexpr std::string_view request =
        "POST /upload HTTP/1.1\r\n"
        "Host: a.test\r\n"
        "Content-Length: 200\r\n"
        "Connection: keep-alive\r\n\r\n";
    asio::write(stream.socket(), asio::buffer(request));
    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return response;
}

http::response<http::string_body> oversized_https_request(const tcp::endpoint& endpoint) {
    asio::io_context io_context;
    asio::ssl::context context{asio::ssl::context::tls_client};
    context.set_verify_mode(asio::ssl::verify_none);
    asio::ssl::stream<beast::tcp_stream> stream{io_context, context};
    require(
        SSL_set_tlsext_host_name(stream.native_handle(), "a.test") == 1,
        "could not set upload-limit test SNI");
    beast::get_lowest_layer(stream).connect(endpoint);
    stream.handshake(asio::ssl::stream_base::client);
    constexpr std::string_view request =
        "POST /upload HTTP/1.1\r\n"
        "Host: a.test\r\n"
        "Content-Length: 200\r\n"
        "Connection: keep-alive\r\n\r\n";
    asio::write(stream, asio::buffer(request));
    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    boost::system::error_code ignored;
    beast::get_lowest_layer(stream).socket().close(ignored);
    return response;
}

void run_test(char* argv[]) {
    auto& registry = webserver::core::HttpRequestRegistry::instance();
    registry.clear();
    BlockingBackend backend;

    webserver::config::RuntimeConfigSpec runtime;
    runtime.settings.max_upload_bytes = 100;
    webserver::config::RuntimeSiteConfig site;
    site.virtual_host = webserver::routing::VirtualHostConfig{
        "Upload site",
        {"a.test"},
        webserver::routing::BackendConfig{
            backend.endpoint().address().to_string(), backend.endpoint().port()},
        {},
        webserver::routing::BackendOverloadConfig{77, "Upload site", 10, 10, 5}};
    site.http_enabled = true;
    site.http_port = 0;
    site.https_enabled = true;
    site.https_port = 0;
    runtime.sites.push_back(std::move(site));
    runtime.tls_certificates.push_back(webserver::tls::TlsCertificateConfig{
        "upload", {"a.test"}, argv[1], argv[2], true});

    webserver::core::ServerOptions options;
    options.port = 0;
    options.https_port = 0;
    options.worker_threads = 2;
    options.runtime_config = std::move(runtime);
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    std::exception_ptr client_failure;
    std::optional<http::status> client_status;
    std::thread client([&] {
        try {
            asio::io_context io_context;
            beast::tcp_stream stream{io_context};
            stream.connect(server.local_endpoint());
            http::request<http::string_body> request{http::verb::get, "/slow", 11};
            request.set(http::field::host, "a.test");
            request.set(http::field::referer, "https://portal.test/files");
            request.keep_alive(false);
            http::write(stream, request);
            beast::flat_buffer buffer;
            http::response<http::string_body> response;
            http::read(stream, buffer, response);
            client_status = response.result();
        } catch (...) {
            client_failure = std::current_exception();
        }
    });

    try {
        wait_until([&backend] { return backend.received(); }, "backend did not receive request");
        wait_until([&registry] { return registry.size(77) == 1; },
                   "active HTTP request did not enter the registry");
        const auto active = registry.snapshot(77);
        require(
            active.size() == 1 && active.front().site_name == "Upload site" &&
                active.front().host == "a.test" &&
                active.front().protocol == "HTTP" &&
                active.front().client_ip == "127.0.0.1" &&
                active.front().method == "GET" && active.front().url == "/slow" &&
                active.front().referer == "https://portal.test/files" &&
                active.front().status == "Proxying",
            "active HTTP request registry fields are incorrect");

        backend.release();
        backend.join_and_rethrow();
        client.join();
        if (client_failure) std::rethrow_exception(client_failure);
        require(client_status == http::status::ok, "blocking HTTP request did not finish");
        wait_until([&registry] { return registry.size() == 0; },
                   "completed HTTP request remained in the registry");

        const auto http_response = oversized_http_request(server.local_endpoint());
        require(
            http_response.result() == http::status::payload_too_large &&
                http_response.body() == "Payload Too Large" && !http_response.keep_alive(),
            "HTTP header-stage body limit did not return a closing 413 response");

        const auto tls_endpoint = server.tls_local_endpoint();
        require(tls_endpoint.has_value(), "TLS listener did not start");
        const auto https_response = oversized_https_request(*tls_endpoint);
        require(
            https_response.result() == http::status::payload_too_large &&
                https_response.body() == "Payload Too Large" && !https_response.keep_alive(),
            "HTTPS header-stage body limit did not return a closing 413 response");

        server.stop();
        server.wait();
    } catch (...) {
        backend.release();
        if (client.joinable()) client.join();
        server.stop();
        server.wait();
        registry.clear();
        throw;
    }
    registry.clear();
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 3) throw std::invalid_argument{"expected certificate and key paths"};
        run_test(argv);
        std::cout << "HTTP realtime and upload limit integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "HTTP realtime and upload limit integration test failed: "
                  << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
