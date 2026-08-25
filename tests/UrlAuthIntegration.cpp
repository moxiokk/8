#include "core/ServerCore.hpp"

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
#include <openssl/evp.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <memory>
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

std::string md5_hex(std::string_view value) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    require(context && EVP_DigestInit_ex(context.get(), EVP_md5(), nullptr) == 1 &&
                EVP_DigestUpdate(context.get(), value.data(), value.size()) == 1,
            "cannot initialize integration-test digest");
    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned digest_size{};
    require(EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) == 1 &&
                digest_size == 16,
            "cannot calculate integration-test digest");
    constexpr std::string_view digits = "0123456789abcdef";
    std::string result(digest_size * 2, '0');
    for (std::size_t index = 0; index < digest_size; ++index) {
        result[index * 2] = digits[digest[index] >> 4U];
        result[index * 2 + 1] = digits[digest[index] & 0x0FU];
    }
    return result;
}

class BackendFixture final {
public:
    BackendFixture()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()),
          worker_([this] { run(); }) {}

    ~BackendFixture() {
        stopping_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
        boost::system::error_code ignored;
        acceptor_.close(ignored);
    }

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
            acceptor_.non_blocking(true);
            tcp::socket socket{io_context_};
            for (;;) {
                boost::system::error_code error;
                acceptor_.accept(socket, error);
                if (!error) {
                    break;
                }
                if (error == asio::error::would_block || error == asio::error::try_again) {
                    if (stopping_.load()) {
                        return;
                    }
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                throw boost::system::system_error{error};
            }

            beast::flat_buffer buffer;
            http::request<http::string_body> request;
            http::read(socket, buffer, request);
            require(request.target() == "/video/a.mp4?quality=hd",
                    "backend received authentication parameters or the wrong target");

            http::response<http::string_body> response{http::status::ok, request.version()};
            response.body() = std::string{request.target().data(), request.target().size()};
            response.prepare_payload();
            http::write(socket, response);

            boost::system::error_code ignored;
            socket.shutdown(tcp::socket::shutdown_both, ignored);
            socket.close(ignored);
            acceptor_.close(ignored);
        } catch (...) {
            failure_ = std::current_exception();
            boost::system::error_code ignored;
            acceptor_.close(ignored);
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::atomic_bool stopping_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

http::response<http::string_body> send(
    beast::tcp_stream& stream,
    beast::flat_buffer& buffer,
    std::string target) {
    http::request<http::string_body> request{http::verb::get, std::move(target), 11};
    request.set(http::field::host, "auth.example");
    request.keep_alive(true);
    http::write(stream, request);
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return response;
}

void run_test() {
    BackendFixture backend;
    const auto backend_endpoint = backend.endpoint();

    webserver::policy::UrlAuthSpec auth;
    auth.enabled = true;
    auth.primary_key = "PrimaryKey123";
    auth.backup_key = "BackupKey123";
    auth.validity_seconds = 1800;

    webserver::policy::SitePolicySpec policy;
    policy.acl_rules = {webserver::policy::AclRuleSpec{
        "hide blocked path",
        true,
        {webserver::policy::AclConditionSpec{
            webserver::policy::AclField::uri,
            webserver::policy::MatchOperator::equal,
            "/blocked",
            {},
            true}},
        webserver::policy::AclAction::deny,
        404,
        {}}};

    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {webserver::routing::VirtualHostConfig{
        "authenticated-site",
        {"auth.example"},
        webserver::routing::BackendConfig{
            backend_endpoint.address().to_string(), backend_endpoint.port()},
        std::move(policy),
        {},
        std::move(auth)}};

    webserver::core::ServerCore server{std::move(options)};
    server.start();
    try {
        asio::io_context client_context;
        beast::tcp_stream stream{client_context};
        stream.socket().connect(server.local_endpoint());
        beast::flat_buffer buffer;

        const auto acl_denied = send(stream, buffer, "/blocked");
        require(acl_denied.result() == http::status::not_found,
                "URL authentication ran before the ACL policy");

        const auto missing = send(stream, buffer, "/video/a.mp4");
        require(missing.result() == http::status::forbidden,
                "missing auth_key did not return HTTP 403");

        const auto invalid = send(
            stream,
            buffer,
            "/video/a.mp4?auth_key=1700000000-0-0-00000000000000000000000000000000");
        require(invalid.result() == http::status::forbidden,
                "invalid auth_key did not return HTTP 403");

        const auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        const auto timestamp_text = std::to_string(timestamp);
        const auto digest = md5_hex(
            "/video/a.mp4-" + timestamp_text + "-0-0-PrimaryKey123");
        const auto accepted = send(
            stream,
            buffer,
            "/video/a.mp4?quality=hd&sign=legacy&time=" + timestamp_text +
                "&auth_key=" + timestamp_text + "-0-0-" + digest);
        require(accepted.result() == http::status::ok,
                "valid auth_key did not reach the backend");
        require(accepted.body() == "/video/a.mp4?quality=hd",
                "backend response shows that auth_key was not removed");

        backend.join_and_rethrow();
        boost::system::error_code ignored;
        stream.socket().close(ignored);
        server.stop();
        server.wait();
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
        std::cout << "URL authentication integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "URL authentication integration test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
