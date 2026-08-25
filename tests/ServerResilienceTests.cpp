#include "core/ServerCore.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>

#include <chrono>
#include <cstdlib>
#include <future>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
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

void run_test() {
    webserver::core::ServerOptions options;
    options.port = 0;
    options.worker_threads = 1;
    options.maximum_connections = 1;

    webserver::core::ServerCore server{std::move(options)};
    server.start();
    try {
        asio::io_context client_context;
        tcp::socket first{client_context};
        first.connect(server.local_endpoint());
        require(
            wait_until([&server] { return server.active_connection_count() == 1; }, 2s),
            "the first connection did not acquire the global admission permit");
        require(server.maximum_connection_count() == 1,
                "the configured global connection limit was not retained");

        tcp::socket second{client_context};
        second.connect(server.local_endpoint());
        require(
            wait_until([&server] { return server.rejected_connection_count() != 0; }, 2s),
            "a connection above the global limit was not rejected");
        require(server.active_connection_count() == 1,
                "a rejected connection consumed an admission permit");

        std::promise<void> worker_resumed;
        auto worker_resumed_future = worker_resumed.get_future();
        asio::post(server.io_context(), [] {
            throw std::runtime_error{"intentional worker-handler failure"};
        });
        asio::post(server.io_context(), [&worker_resumed] { worker_resumed.set_value(); });
        require(worker_resumed_future.wait_for(2s) == std::future_status::ready,
                "the worker did not resume after a handler exception");

        boost::system::error_code ignored;
        first.close(ignored);
        second.close(ignored);
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
        std::cout << "server resilience tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "server resilience tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
