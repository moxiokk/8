#include "config/RuntimeConfig.hpp"
#include "core/ServerCore.hpp"
#include "logging/LogManager.hpp"

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

#include <array>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <mutex>
#include <memory>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

constexpr std::size_t client_count = 8;
constexpr std::size_t requests_per_client = 75;
constexpr std::size_t expected_requests = client_count * requests_per_client + 1;
constexpr std::size_t expected_access_events = expected_requests + 1;

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
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
        try {
            stop();
        } catch (...) {
        }
    }

    BackendFixture(const BackendFixture&) = delete;
    BackendFixture& operator=(const BackendFixture&) = delete;

    [[nodiscard]] tcp::endpoint endpoint() const { return endpoint_; }
    [[nodiscard]] std::size_t handled() const noexcept { return handled_.load(); }

    void stop() {
        if (joined_.exchange(true)) {
            return;
        }
        stopping_.store(true);
        if (worker_.joinable()) {
            worker_.join();
        }
        boost::system::error_code ignored;
        acceptor_.close(ignored);
        if (failure_) {
            std::rethrow_exception(failure_);
        }
    }

private:
    void run() noexcept {
        try {
            while (!stopping_.load()) {
                tcp::socket socket{io_context_};
                boost::system::error_code accept_error;
                acceptor_.accept(socket, accept_error);
                if (accept_error == asio::error::would_block ||
                    accept_error == asio::error::try_again) {
                    std::this_thread::sleep_for(1ms);
                    continue;
                }
                if (accept_error) {
                    if (stopping_.load() || accept_error == asio::error::operation_aborted ||
                        accept_error == asio::error::bad_descriptor) {
                        return;
                    }
                    throw boost::system::system_error{accept_error};
                }

                beast::flat_buffer buffer;
                http::request<http::string_body> request;
                http::read(socket, buffer, request);
                require(
                    request["X-Request-ID"].size() == 32,
                    "proxy did not forward the generated request ID");
                http::response<http::string_body> response{http::status::ok, 11};
                response.set(http::field::content_type, "text/plain");
                response.body() = "ok";
                response.keep_alive(false);
                response.prepare_payload();
                http::write(socket, response);
                handled_.fetch_add(1);
            }
        } catch (...) {
            if (!stopping_.load()) {
                std::scoped_lock lock{failure_mutex_};
                if (!failure_) {
                    failure_ = std::current_exception();
                }
                stopping_.store(true);
            }
        }
    }

    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_;
    std::atomic_bool stopping_{false};
    std::atomic_bool joined_{false};
    std::atomic_size_t handled_{};
    std::thread worker_;
    std::mutex failure_mutex_;
    std::exception_ptr failure_;
};

webserver::config::RuntimeConfigSpec runtime_spec(
    std::uint64_t revision,
    const tcp::endpoint& backend) {
    webserver::config::RuntimeSiteConfig site;
    site.http_port = 0;
    site.virtual_host = webserver::routing::VirtualHostConfig{
        "stability-site",
        {"stability.test"},
        webserver::routing::BackendConfig{
            backend.address().to_string(), backend.port()}};
    webserver::config::RuntimeConfigSpec spec;
    spec.revision = revision;
    spec.sites = {std::move(site)};
    return spec;
}

void run_client(
    const tcp::endpoint& endpoint,
    std::size_t client_index,
    std::atomic_bool& begin) {
    while (!begin.load()) {
        std::this_thread::yield();
    }

    asio::io_context io_context;
    beast::tcp_stream stream{io_context};
    stream.expires_after(20s);
    stream.connect(endpoint);
    beast::flat_buffer buffer;
    std::string previous_request_id;

    for (std::size_t index = 0; index < requests_per_client; ++index) {
        http::request<http::string_body> request{
            http::verb::get,
            "/load?client=" + std::to_string(client_index) +
                "&token=must-not-appear-in-access-log",
            11};
        request.set(http::field::host, "stability.test");
        request.keep_alive(index + 1 != requests_per_client);
        http::write(stream, request);

        http::response<http::string_body> response;
        http::read(stream, buffer, response);
        require(response.result() == http::status::ok, "load request did not return 200");
        require(response.body() == "ok", "load request returned the wrong body");
        const auto request_id_value = response["X-Request-ID"];
        const auto current_request_id =
            std::string{request_id_value.data(), request_id_value.size()};
        require(current_request_id.size() == 32, "response request ID is missing");
        require(current_request_id != previous_request_id, "request ID was reused");
        previous_request_id = current_request_id;
    }
}

void run_test() {
    std::error_code temp_error;
    auto temporary_root = std::filesystem::temp_directory_path(temp_error);
    if (temp_error) {
        temporary_root = std::filesystem::current_path();
    }
    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    const auto log_directory = temporary_root / ("webserver-stability-" + suffix);

    BackendFixture backend;
    webserver::logging::LogOptions log_options;
    log_options.directory = log_directory;
    log_options.max_file_bytes = 4U * 1024U * 1024U;
    log_options.queue_capacity = 4096;
    auto logger = std::make_shared<webserver::logging::LogManager>(log_options);

    webserver::core::ServerOptions options;
    options.worker_threads = 4;
    options.runtime_config = runtime_spec(1, backend.endpoint());
    options.logger = logger;
    webserver::core::ServerCore server{std::move(options)};
    server.start();

    try {
        const auto endpoint = server.local_endpoint();
        std::atomic_bool begin{false};
        std::mutex failures_mutex;
        std::vector<std::exception_ptr> failures;
        std::vector<std::thread> clients;
        clients.reserve(client_count);
        for (std::size_t index = 0; index < client_count; ++index) {
            clients.emplace_back([&, index] {
                try {
                    run_client(endpoint, index, begin);
                } catch (...) {
                    std::scoped_lock lock{failures_mutex};
                    failures.push_back(std::current_exception());
                }
            });
        }

        std::thread reloader{[&] {
            try {
                while (!begin.load()) {
                    std::this_thread::yield();
                }
                for (std::uint64_t revision = 2; revision <= 25; ++revision) {
                    server.reload(runtime_spec(revision, backend.endpoint()));
                    std::this_thread::sleep_for(2ms);
                }
            } catch (...) {
                std::scoped_lock lock{failures_mutex};
                failures.push_back(std::current_exception());
            }
        }};

        begin.store(true);
        for (auto& client : clients) {
            client.join();
        }
        reloader.join();
        if (!failures.empty()) {
            std::rethrow_exception(failures.front());
        }
        require(server.runtime_revision() == 25, "concurrent reload revision was lost");

        asio::io_context idle_context;
        beast::tcp_stream idle_stream{idle_context};
        idle_stream.connect(endpoint);
        beast::flat_buffer idle_buffer;
        http::request<http::string_body> idle_request{http::verb::get, "/idle", 11};
        idle_request.set(http::field::host, "stability.test");
        idle_request.keep_alive(true);
        http::write(idle_stream, idle_request);
        http::response<http::string_body> idle_response;
        http::read(idle_stream, idle_buffer, idle_response);
        require(idle_response.result() == http::status::ok, "idle setup request failed");

        const auto deadline = std::chrono::steady_clock::now() + 5s;
        while (backend.handled() < expected_requests &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(5ms);
        }
        require(backend.handled() == expected_requests, "backend request count is incomplete");
        backend.stop();

        asio::io_context offline_context;
        beast::tcp_stream offline_stream{offline_context};
        offline_stream.connect(endpoint);
        beast::flat_buffer offline_buffer;
        http::request<http::string_body> offline_request{http::verb::get, "/offline", 11};
        offline_request.set(http::field::host, "stability.test");
        offline_request.keep_alive(false);
        http::write(offline_stream, offline_request);
        http::response<http::string_body> offline_response;
        http::read(offline_stream, offline_buffer, offline_response);
        require(
            offline_response.result() == http::status::bad_gateway,
            "offline backend did not return 502");

        server.stop();
        server.wait();
        std::array<char, 1> probe{};
        boost::system::error_code close_error;
        const auto received = idle_stream.socket().read_some(asio::buffer(probe), close_error);
        require(received == 0, "shutdown wrote unexpected bytes to idle connection");
        require(
            close_error == asio::error::eof || close_error == asio::error::connection_reset,
            "shutdown did not close the idle keep-alive connection");

        logger->flush();
        const auto statistics = logger->statistics();
        require(
            statistics.accepted_access == expected_access_events,
            "access event count is wrong");
        require(statistics.dropped_access == 0, "access events were dropped under test load");
        const auto access_log = read_file(log_directory / "access.log");
        const auto error_log = read_file(log_directory / "error.log");
        require(
            access_log.find("must-not-appear-in-access-log") == std::string::npos &&
                access_log.find("?client=") == std::string::npos,
            "access log leaked query parameters");
        require(
            static_cast<std::size_t>(std::count(access_log.begin(), access_log.end(), '\n')) ==
                expected_access_events,
            "access log line count is incomplete");
        require(
            error_log.find("\"component\":\"reverse_proxy\"") != std::string::npos &&
                error_log.find("\"request_id\":") != std::string::npos,
            "backend failure was not correlated in error.log");
    } catch (...) {
        server.stop();
        server.wait();
        try {
            backend.stop();
        } catch (...) {
        }
        std::error_code ignored;
        std::filesystem::remove_all(log_directory, ignored);
        throw;
    }

    std::error_code ignored;
    std::filesystem::remove_all(log_directory, ignored);
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Stability integration test passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Stability integration test failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
