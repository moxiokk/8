#include "core/ServerCore.hpp"

#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/system/system_error.hpp>

#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
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
    if (!condition) {
        throw std::runtime_error{message};
    }
}

std::string header_value(const http::fields& fields, const char* name) {
    const auto value = fields[name];
    return std::string{value.data(), value.size()};
}

class HttpsBackendFixture final {
public:
    HttpsBackendFixture()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()) {
        acceptor_.non_blocking(true);
        worker_ = std::thread([this] { run(); });
    }

    ~HttpsBackendFixture() {
        stopping_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
        boost::system::error_code ignored;
        acceptor_.close(ignored);
    }

    HttpsBackendFixture(const HttpsBackendFixture&) = delete;
    HttpsBackendFixture& operator=(const HttpsBackendFixture&) = delete;

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
            while (request_number < 3 && !stopping_.load()) {
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

                beast::flat_buffer buffer;
                http::request<http::string_body> request;
                http::read(socket, buffer, request);
                require(
                    header_value(request.base(), "X-Forwarded-Proto") == "https",
                    "HTTPS proxy sent the wrong forwarded protocol");
                require(
                    header_value(request.base(), "X-Real-IP") == "127.0.0.1",
                    "HTTPS proxy sent the wrong client IP");

                const std::string expected_host = request_number == 1 ? "b.test" : "a.test";
                require(
                    header_value(request.base(), "Host") == expected_host,
                    "HTTPS request reached the wrong virtual host backend");

                http::response<http::string_body> response{http::status::ok, 11};
                response.set(http::field::content_type, "text/plain");
                response.body() = "HTTPS backend for " + expected_host;
                response.prepare_payload();
                http::write(socket, response);

                boost::system::error_code ignored;
                socket.shutdown(tcp::socket::shutdown_both, ignored);
                socket.close(ignored);
                ++request_number;
            }

            boost::system::error_code ignored;
            acceptor_.close(ignored);
        } catch (...) {
            if (!stopping_.load()) {
                failure_ = std::current_exception();
            }
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::atomic_bool stopping_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

class TlsClient final {
public:
    TlsClient(const tcp::endpoint& endpoint, std::optional<std::string> sni)
        : ssl_context_(make_context()),
          stream_(io_context_, ssl_context_) {
        static constexpr std::array<unsigned char, 9> http_1_1{
            8, 'h', 't', 't', 'p', '/', '1', '.', '1'};
        if (SSL_set_alpn_protos(
                stream_.native_handle(), http_1_1.data(), static_cast<unsigned int>(http_1_1.size())) != 0) {
            throw std::runtime_error{"could not configure TLS client ALPN"};
        }
        if (sni && SSL_set_tlsext_host_name(stream_.native_handle(), sni->c_str()) != 1) {
            throw std::runtime_error{"could not configure TLS client SNI"};
        }

        beast::get_lowest_layer(stream_).socket().connect(endpoint);
        stream_.handshake(asio::ssl::stream_base::client);
    }

    TlsClient(const TlsClient&) = delete;
    TlsClient& operator=(const TlsClient&) = delete;

    ~TlsClient() {
        close();
    }

[[nodiscard]] bool peer_certificate_matches(const std::string& host) {
    std::unique_ptr<X509, decltype(&X509_free)> certificate{
        SSL_get1_peer_certificate(stream_.native_handle()), &X509_free};

    return certificate &&
           X509_check_host(
               certificate.get(),
               host.c_str(),
               host.size(),
               X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
               nullptr) == 1;
}

[[nodiscard]] std::string negotiated_protocol() {
    const unsigned char* protocol = nullptr;
    unsigned int protocol_size = 0;

    SSL_get0_alpn_selected(
        stream_.native_handle(),
        &protocol,
        &protocol_size);

    return std::string{
        reinterpret_cast<const char*>(protocol),
        static_cast<std::size_t>(protocol_size)};
}

    http::response<http::string_body> request(std::string host) {
        http::request<http::string_body> request{http::verb::get, "/secure", 11};
        request.set(http::field::host, std::move(host));
        request.keep_alive(false);
        http::write(stream_, request);

        beast::flat_buffer buffer;
        http::response<http::string_body> response;
        http::read(stream_, buffer, response);
        return response;
    }

    void close() noexcept {
        if (closed_) {
            return;
        }
        closed_ = true;

        boost::system::error_code ignored;
        stream_.shutdown(ignored);
        auto& socket = beast::get_lowest_layer(stream_).socket();
        socket.shutdown(tcp::socket::shutdown_both, ignored);
        socket.close(ignored);
    }

private:
    static asio::ssl::context make_context() {
        asio::ssl::context context{asio::ssl::context::tls_client};
        context.set_verify_mode(asio::ssl::verify_none);
        if (SSL_CTX_set_min_proto_version(context.native_handle(), TLS1_2_VERSION) != 1) {
            throw std::runtime_error{"could not set TLS client minimum version"};
        }
        return context;
    }

    asio::io_context io_context_;
    asio::ssl::context ssl_context_;
    asio::ssl::stream<beast::tcp_stream> stream_;
    bool closed_{false};
};

void require_handshake_rejected(
    const tcp::endpoint& endpoint,
    const std::string& sni,
    bool tls_1_1_only) {
    asio::io_context io_context;
    asio::ssl::context context{asio::ssl::context::tls_client};
    context.set_verify_mode(asio::ssl::verify_none);
    if (tls_1_1_only &&
        SSL_CTX_set_max_proto_version(context.native_handle(), TLS1_1_VERSION) != 1) {
        throw std::runtime_error{"could not set legacy TLS test maximum version"};
    }

    asio::ssl::stream<beast::tcp_stream> stream{io_context, context};
    require(
        SSL_set_tlsext_host_name(stream.native_handle(), sni.c_str()) == 1,
        "could not configure rejected-handshake SNI");
    beast::get_lowest_layer(stream).socket().connect(endpoint);

    boost::system::error_code handshake_error;
    stream.handshake(asio::ssl::stream_base::client, handshake_error);
    require(
        static_cast<bool>(handshake_error),
        "TLS handshake that should be rejected succeeded");

    boost::system::error_code ignored;
    beast::get_lowest_layer(stream).socket().close(ignored);
}

void run_test(char* argv[]) {
    HttpsBackendFixture backend;
    const auto backend_endpoint = backend.endpoint();

    webserver::core::ServerOptions options;
    options.port = 0;
    options.https_port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {
        webserver::routing::VirtualHostConfig{
            "site-a",
            {"a.test", "www.a.test"},
            webserver::routing::BackendConfig{
                backend_endpoint.address().to_string(), backend_endpoint.port()}},
        webserver::routing::VirtualHostConfig{
            "site-b",
            {"b.test"},
            webserver::routing::BackendConfig{
                backend_endpoint.address().to_string(), backend_endpoint.port()}},
    };
    options.tls_certificates = {
        webserver::tls::TlsCertificateConfig{
            "a", {"a.test", "*.a.test"}, argv[1], argv[2], true},
        webserver::tls::TlsCertificateConfig{
            "b", {"b.test"}, argv[3], argv[4], false},
    };

    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        const auto tls_endpoint = server.tls_local_endpoint();
        require(tls_endpoint.has_value(), "HTTPS listener did not start");

        TlsClient a_client{*tls_endpoint, std::string{"www.a.test"}};
        require(
            a_client.peer_certificate_matches("a.test"),
            "SNI a.test selected the wrong certificate");
        require(
            a_client.negotiated_protocol() == "http/1.1",
            "HTTPS listener did not negotiate HTTP/1.1 ALPN");
        const auto a_response = a_client.request("a.test");
        require(a_response.result() == http::status::ok, "a.test HTTPS proxy failed");
        require(
            a_response.body() == "HTTPS backend for a.test",
            "a.test HTTPS proxy returned the wrong response");
        a_client.close();

        TlsClient b_client{*tls_endpoint, std::string{"b.test"}};
        require(
            b_client.peer_certificate_matches("b.test") &&
                !b_client.peer_certificate_matches("a.test"),
            "SNI b.test selected the wrong certificate");
        const auto b_response = b_client.request("b.test");
        require(b_response.result() == http::status::ok, "b.test HTTPS proxy failed");
        require(
            b_response.body() == "HTTPS backend for b.test",
            "b.test HTTPS proxy returned the wrong response");
        b_client.close();

        TlsClient default_client{*tls_endpoint, std::nullopt};
        require(
            default_client.peer_certificate_matches("a.test"),
            "connection without SNI did not use the default certificate");
        const auto default_response = default_client.request("a.test");
        require(
            default_response.result() == http::status::ok,
            "default-certificate HTTPS proxy failed");
        default_client.close();

        backend.join_and_rethrow();

        TlsClient conflict_client{*tls_endpoint, std::string{"a.test"}};
        const auto conflict_response = conflict_client.request("b.test");
        require(
            conflict_response.result() == http::status::misdirected_request,
            "SNI/Host conflict did not return HTTP 421");
        conflict_client.close();

        require_handshake_rejected(*tls_endpoint, "unknown.test", false);
        require_handshake_rejected(*tls_endpoint, "a.test", true);

        server.stop();
        server.wait();
    } catch (...) {
        server.stop();
        server.wait();
        throw;
    }

    server.stop();
    server.wait();
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            throw std::runtime_error{"expected four certificate fixture paths"};
        }
        run_test(argv);
        std::cout << "HTTPS/SNI integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "HTTPS/SNI integration test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
