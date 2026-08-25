#include "config/RuntimeConfig.hpp"
#include "core/ServerCore.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>

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
    if (!condition) throw std::runtime_error{message};
}

class BackendFixture final {
public:
    explicit BackendFixture(std::size_t expected_requests)
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()), expected_requests_(expected_requests) {
        acceptor_.non_blocking(true);
        worker_ = std::thread([this] { run(); });
    }

    ~BackendFixture() {
        stopping_.store(true);
        if (worker_.joinable()) worker_.join();
        boost::system::error_code ignored;
        acceptor_.close(ignored);
    }

    [[nodiscard]] tcp::endpoint endpoint() const { return endpoint_; }

    void join_and_rethrow() {
        if (worker_.joinable()) worker_.join();
        if (failure_) std::rethrow_exception(failure_);
    }

private:
    void run() noexcept {
        try {
            std::size_t handled = 0;
            while (handled < expected_requests_ && !stopping_.load()) {
                tcp::socket socket{io_context_};
                boost::system::error_code error;
                acceptor_.accept(socket, error);
                if (error == asio::error::would_block || error == asio::error::try_again) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                if (error) throw boost::system::system_error{error};
                beast::flat_buffer buffer;
                http::request<http::string_body> request;
                http::read(socket, buffer, request);
                http::response<http::string_body> response{http::status::ok, request.version()};
                response.body() = "backend:" + std::string{request.target()};
                response.prepare_payload();
                http::write(socket, response);
                ++handled;
            }
        } catch (...) {
            if (!stopping_.load()) failure_ = std::current_exception();
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::size_t expected_requests_{};
    std::atomic_bool stopping_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

webserver::config::RuntimeConfigSpec spec(
    std::uint64_t revision,
    const tcp::endpoint& backend,
    bool block_private) {
    using namespace webserver;
    policy::SitePolicySpec policy_spec;
    policy_spec.hotlink.enabled = true;
    policy_spec.hotlink.protected_extensions = {"jpg"};
    policy_spec.hotlink.allow_empty_referer = false;
    policy_spec.redirects = {policy::RedirectRuleSpec{
        "legacy", true, {}, "/old", policy::RedirectMatch::exact,
        "/new", 301, false, true}};
    if (block_private) {
        policy_spec.acl_rules = {policy::AclRuleSpec{
            "private", true,
            {policy::AclConditionSpec{
                policy::AclField::uri, policy::MatchOperator::starts_with,
                "/private", {}, false}},
            policy::AclAction::deny, 403, {}}};
    }

    config::RuntimeSiteConfig site;
    site.http_port = 0;
    site.virtual_host = routing::VirtualHostConfig{
        "policy-site", {"policy.test"},
        routing::BackendConfig{backend.address().to_string(), backend.port()},
        std::move(policy_spec)};
    config::RuntimeConfigSpec result;
    result.revision = revision;
    result.sites = {std::move(site)};
    return result;
}

http::response<http::string_body> send(
    beast::tcp_stream& stream,
    beast::flat_buffer& buffer,
    std::string target,
    std::string referer = {}) {
    http::request<http::string_body> request{http::verb::get, std::move(target), 11};
    request.set(http::field::host, "policy.test");
    if (!referer.empty()) request.set(http::field::referer, referer);
    request.keep_alive(true);
    http::write(stream, request);
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return response;
}

void run_test() {
    BackendFixture backend{2};
    webserver::core::ServerOptions options;
    options.worker_threads = 2;
    options.runtime_config = spec(1, backend.endpoint(), true);
    webserver::core::ServerCore server{std::move(options)};
    server.start();
    try {
        asio::io_context client_context;
        beast::tcp_stream stream{client_context};
        stream.socket().connect(server.local_endpoint());
        beast::flat_buffer buffer;

        require(send(stream, buffer, "/private").result() == http::status::forbidden,
                "ACL did not block the request");
        const auto redirect = send(stream, buffer, "/old?q=1");
        require(redirect.result() == http::status::moved_permanently &&
                    redirect[http::field::location] == "/new?q=1",
                "redirect rule was not applied");
        require(send(stream, buffer, "/image.jpg", "https://evil.test/").result() ==
                    http::status::forbidden,
                "hotlink policy did not block a foreign Referer");
        require(send(stream, buffer, "/image.jpg", "https://policy.test/page").body() ==
                    "backend:/image.jpg",
                "same-site asset was not proxied");

        server.reload(spec(2, backend.endpoint(), false));
        require(server.runtime_revision() == 2, "policy snapshot was not hot reloaded");
        require(send(stream, buffer, "/private").body() == "backend:/private",
                "keep-alive request did not use the new policy snapshot");

        boost::system::error_code ignored;
        stream.socket().close(ignored);
        server.stop();
        server.wait();
        backend.join_and_rethrow();
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
        std::cout << "Policy integration tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Policy integration tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
