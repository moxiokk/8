#include "proxy/BackendConnectionPool.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core/tcp_stream.hpp>

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace asio = boost::asio;
namespace beast = boost::beast;
using tcp = asio::ip::tcp;
using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

bool peer_was_closed(tcp::socket& peer) {
    char byte{};
    boost::system::error_code error;
    const auto received = peer.read_some(asio::buffer(&byte, 1), error);
    if (!error) return received == 0;
    if (error == asio::error::would_block || error == asio::error::try_again) return false;
    return error == asio::error::eof || error == asio::error::connection_reset ||
           error == asio::error::operation_aborted || error == asio::error::broken_pipe;
}

void test_connection_can_be_acquired_before_expiry() {
    auto& pool = webserver::proxy::BackendConnectionPool::instance();
    pool.clear();

    asio::io_context io_context;
    tcp::acceptor acceptor{
        io_context, tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
    beast::tcp_stream outbound{io_context};
    outbound.connect(acceptor.local_endpoint());
    tcp::socket peer{io_context};
    acceptor.accept(peer);

    pool.release(
        "pool-test-acquire",
        webserver::proxy::BackendStream{
            std::in_place_type<webserver::proxy::BackendPlainStream>,
            std::move(outbound)},
        1,
        5s);
    auto acquired = pool.acquire("pool-test-acquire", 5s);
    require(acquired.has_value(), "live idle connection could not be acquired");
}

void test_connection_is_actively_reaped() {
    auto& pool = webserver::proxy::BackendConnectionPool::instance();
    pool.clear();

    asio::io_context io_context;
    tcp::acceptor acceptor{
        io_context, tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
    beast::tcp_stream outbound{io_context};
    outbound.connect(acceptor.local_endpoint());
    tcp::socket peer{io_context};
    acceptor.accept(peer);
    boost::system::error_code non_blocking_error;
    peer.non_blocking(true, non_blocking_error);
    require(!non_blocking_error, "could not make peer socket non-blocking");

    const auto released_at = std::chrono::steady_clock::now();
    pool.release(
        "pool-test-expiry",
        webserver::proxy::BackendStream{
            std::in_place_type<webserver::proxy::BackendPlainStream>,
            std::move(outbound)},
        1,
        1s);

    bool closed = false;
    const auto deadline = released_at + 4s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (peer_was_closed(peer)) {
            closed = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }

    require(closed, "idle connection was not actively closed after its TTL");
    require(
        std::chrono::steady_clock::now() - released_at >= 900ms,
        "idle connection was reaped substantially before its TTL");
    require(
        !pool.acquire("pool-test-expiry", 5s).has_value(),
        "reaped connection remained in the pool");
}

void test_clear_closes_connection_without_waiting_for_ttl() {
    auto& pool = webserver::proxy::BackendConnectionPool::instance();
    pool.clear();

    asio::io_context io_context;
    tcp::acceptor acceptor{
        io_context, tcp::endpoint{asio::ip::address_v4::loopback(), 0}};
    beast::tcp_stream outbound{io_context};
    outbound.connect(acceptor.local_endpoint());
    tcp::socket peer{io_context};
    acceptor.accept(peer);
    boost::system::error_code non_blocking_error;
    peer.non_blocking(true, non_blocking_error);
    require(!non_blocking_error, "could not make clear-test peer non-blocking");

    pool.release(
        "pool-test-clear",
        webserver::proxy::BackendStream{
            std::in_place_type<webserver::proxy::BackendPlainStream>,
            std::move(outbound)},
        1,
        30s);
    pool.clear();

    bool closed = false;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (std::chrono::steady_clock::now() < deadline) {
        if (peer_was_closed(peer)) {
            closed = true;
            break;
        }
        std::this_thread::sleep_for(10ms);
    }
    require(closed, "clear did not immediately close an idle connection");
}

} // namespace

int main() {
    try {
        test_connection_can_be_acquired_before_expiry();
        test_connection_is_actively_reaped();
        test_clear_closes_connection_without_waiting_for_ttl();
        webserver::proxy::BackendConnectionPool::instance().clear();
        std::cout << "Backend connection pool tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        webserver::proxy::BackendConnectionPool::instance().clear();
        std::cerr << "Backend connection pool tests failed: " << error.what() << '\n';
        return 1;
    }
}
