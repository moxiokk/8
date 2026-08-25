#include "core/ServerCore.hpp"
#include "proxy/BackendConnectionPool.hpp"

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

#include <atomic>
#include <chrono>
#include <exception>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

class TlsBackend final {
public:
    TlsBackend(const std::filesystem::path& certificate, const std::filesystem::path& key)
        : context_(ssl::context::tls_server),
          acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}) {
        context_.use_certificate_chain_file(certificate.string());
        context_.use_private_key_file(key.string(), ssl::context::pem);
        acceptor_.non_blocking(true);
        worker_ = std::thread([this] { run(); });
    }

    ~TlsBackend() {
        stopping_.store(true);
        if (worker_.joinable()) worker_.join();
        boost::system::error_code ignored;
        acceptor_.close(ignored);
    }

    [[nodiscard]] std::uint16_t port() const { return acceptor_.local_endpoint().port(); }

    void join_and_rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            tcp::socket socket{io_context_};
            for (;;) {
                boost::system::error_code error;
                acceptor_.accept(socket, error);
                if (!error) break;
                if (error == asio::error::would_block || error == asio::error::try_again) {
                    if (stopping_.load()) return;
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                throw boost::system::system_error{error};
            }
            ssl::stream<tcp::socket> stream{std::move(socket), context_};
            stream.handshake(ssl::stream_base::server);
            beast::flat_buffer buffer;
            http::request<http::string_body> request;
            http::read(stream, buffer, request);
            require(request[http::field::host] == "upstream.a.test", "custom upstream Host was not sent");
            require(request.target() == "/secure", "HTTPS upstream target was not forwarded");
            http::response<http::string_body> response{http::status::ok, 11};
            response.set(http::field::content_type, "text/plain");
            response.keep_alive(false);
            response.body() = "verified HTTPS upstream";
            response.prepare_payload();
            http::write(stream, response);
            boost::system::error_code ignored;
            stream.shutdown(ignored);
        } catch (...) {
            failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    ssl::context context_;
    tcp::acceptor acceptor_;
    std::thread worker_;
    std::exception_ptr failure_;
    std::atomic_bool stopping_{false};
};

void run_test(const std::filesystem::path& certificate, const std::filesystem::path& key) {
    webserver::proxy::outbound_tls_context().load_verify_file(certificate.string());
    TlsBackend backend{certificate, key};

    webserver::routing::BackendConfig upstream{"localhost", backend.port()};
    upstream.protocol = webserver::routing::BackendProtocol::https;
    upstream.host = "upstream.a.test";
    upstream.tls_sni = "a.test";
    upstream.tls_verify_certificate = true;
    upstream.connect_timeout_seconds = 5;
    upstream.response_timeout_seconds = 5;
    upstream.keep_alive = false;

    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "tls-upstream-site", {"proxy.test"}, std::move(upstream)}};
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    asio::io_context client_context;
    beast::tcp_stream client{client_context};
    client.connect(server.local_endpoint());
    http::request<http::string_body> request{http::verb::get, "/secure", 11};
    request.set(http::field::host, "proxy.test");
    request.keep_alive(false);
    http::write(client, request);
    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(client, buffer, response);
    require(response.result() == http::status::ok, "HTTPS upstream proxy did not return 200");
    require(response.body() == "verified HTTPS upstream", "HTTPS upstream body was corrupted");

    server.stop();
    backend.join_and_rethrow();
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 3) throw std::runtime_error{"certificate and key paths are required"};
        run_test(argv[1], argv[2]);
        std::cout << "HTTPS upstream proxy integration test passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "HTTPS upstream proxy integration test failed: " << error.what() << '\n';
        return 1;
    }
}
