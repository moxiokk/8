#include "config/RuntimeConfig.hpp"
#include "core/ServerCore.hpp"

#include <boost/asio/error.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <boost/system/system_error.hpp>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <iostream>
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

template <typename Predicate>
bool wait_until(Predicate predicate, std::chrono::steady_clock::duration timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) return true;
        std::this_thread::sleep_for(5ms);
    }
    return predicate();
}

class BackendFixture final {
public:
    BackendFixture(std::string response_body, std::size_t expected_requests)
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          endpoint_(acceptor_.local_endpoint()),
          response_body_(std::move(response_body)),
          expected_requests_(expected_requests) {
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
            std::size_t handled = 0;
            while (handled < expected_requests_ && !stopping_.load()) {
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
                http::response<http::string_body> response{http::status::ok, request.version()};
                response.body() = response_body_;
                response.keep_alive(false);
                response.prepare_payload();
                http::write(socket, response);

                boost::system::error_code ignored;
                socket.close(ignored);
                ++handled;
            }
        } catch (...) {
            if (!stopping_.load()) {
                failure_ = std::current_exception();
            }
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::string response_body_;
    std::size_t expected_requests_{};
    std::atomic_bool stopping_{false};
    std::thread worker_;
    std::exception_ptr failure_;
};

webserver::config::RuntimeSiteConfig runtime_site(
    const tcp::endpoint& backend,
    std::uint16_t listener_port) {
    webserver::config::RuntimeSiteConfig site;
    site.virtual_host = webserver::routing::VirtualHostConfig{
        "hot-reload-site",
        {"reload.test"},
        webserver::routing::BackendConfig{
            backend.address().to_string(), backend.port()}};
    site.http_port = listener_port;
    return site;
}

webserver::config::RuntimeConfigSpec runtime_spec(
    std::uint64_t revision,
    const tcp::endpoint& backend,
    std::uint16_t primary_port,
    std::optional<std::uint16_t> extra_port = std::nullopt) {
    webserver::config::RuntimeConfigSpec spec;
    spec.revision = revision;
    spec.sites.push_back(runtime_site(backend, primary_port));
    if (extra_port) {
        spec.sites.push_back(runtime_site(backend, *extra_port));
    }
    return spec;
}

http::response<http::string_body> request(
    beast::tcp_stream& stream,
    beast::flat_buffer& buffer,
    bool keep_alive) {
    http::request<http::string_body> outgoing{http::verb::get, "/", 11};
    outgoing.set(http::field::host, "reload.test");
    outgoing.keep_alive(keep_alive);
    http::write(stream, outgoing);
    http::response<http::string_body> incoming;
    http::read(stream, buffer, incoming);
    return incoming;
}

void run_test() {
    BackendFixture old_backend{"old-backend", 2};
    BackendFixture new_backend{"new-backend", 2};

    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 2;
    options.virtual_hosts = {
        webserver::routing::VirtualHostConfig{
            "hot-reload-site",
            {"reload.test"},
            webserver::routing::BackendConfig{
                old_backend.endpoint().address().to_string(), old_backend.endpoint().port()}},
    };

    webserver::core::ServerCore server{std::move(options)};
    server.start();
    try {
        asio::io_context client_context;
        beast::tcp_stream client{client_context};
        client.socket().connect(server.local_endpoint());
        beast::flat_buffer buffer;

        const auto before = request(client, buffer, true);
        require(before.body() == "old-backend", "initial request used the wrong backend");

        asio::io_context reservation_context;
        tcp::acceptor occupied_listener{
            reservation_context, tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
        const auto occupied_port = occupied_listener.local_endpoint().port();
        bool bind_failure_rejected = false;
        try {
            server.reload(runtime_spec(99, new_backend.endpoint(), 0, occupied_port));
        } catch (const boost::system::system_error&) {
            bind_failure_rejected = true;
        }
        require(bind_failure_rejected, "occupied listener port was accepted");
        require(server.runtime_revision() == 1, "failed listener preflight replaced the snapshot");
        const auto after_failure = request(client, buffer, true);
        require(
            after_failure.body() == "old-backend",
            "failed listener preflight changed routing state");

        boost::system::error_code close_error;
        occupied_listener.close(close_error);
        const auto added_port = occupied_port;
        auto commit_added_listener = server.prepare_reload(
            runtime_spec(2, new_backend.endpoint(), 0, added_port));

        tcp::socket precommit_client{client_context};
        precommit_client.connect(
            tcp::endpoint{asio::ip::address_v4::loopback(), added_port});
        precommit_client.non_blocking(true);
        require(
            wait_until([&precommit_client] {
                char byte{};
                boost::system::error_code read_error;
                static_cast<void>(precommit_client.read_some(
                    asio::buffer(&byte, 1), read_error));
                return read_error == asio::error::eof ||
                       read_error == asio::error::connection_reset ||
                       read_error == asio::error::connection_aborted ||
                       read_error == asio::error::bad_descriptor;
            }, 2s),
            "pre-started listener accepted traffic before runtime publication");

        commit_added_listener();
        require(server.runtime_revision() == 2, "server did not publish revision 2");

        const auto after = request(client, buffer, false);
        require(
            after.body() == "new-backend",
            "next request on an existing keep-alive connection did not hot reload");

        beast::tcp_stream added_client{client_context};
        added_client.socket().connect(server.http_local_endpoint(added_port));
        beast::flat_buffer added_buffer;
        const auto added_response = request(added_client, added_buffer, false);
        require(added_response.body() == "new-backend", "added listener did not route traffic");

        server.reload(runtime_spec(3, new_backend.endpoint(), 0));
        require(server.runtime_revision() == 3, "server did not publish revision 3");
        require(
            [&server, added_port] {
                try {
                    static_cast<void>(server.http_local_endpoint(added_port));
                    return false;
                } catch (const std::invalid_argument&) {
                    return true;
                }
            }(),
            "removed listener remained in the active listener map");
        require(
            wait_until([&server] { return server.retired_listener_count() == 0; }, 2s),
            "a drained retired listener was not reclaimed");

        old_backend.join_and_rethrow();
        new_backend.join_and_rethrow();
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
        std::cout << "Hot reload integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Hot reload integration test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
