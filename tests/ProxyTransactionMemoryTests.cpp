#include "proxy/ProxyTransaction.hpp"

#include <boost/beast/core/tcp_stream.hpp>

#include <cstddef>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

using PlainProxyTransaction =
    webserver::proxy::ProxyTransaction<boost::beast::tcp_stream>;

static_assert(
    sizeof(PlainProxyTransaction) < 32 * 1024,
    "queued ProxyTransaction fixed footprint regressed above 32 KiB");
static_assert(
    webserver::proxy::detail::http_transfer_chunk_size == 16 * 1024,
    "HTTP transfer chunk is not 16 KiB");
static_assert(
    webserver::proxy::detail::tunnel_chunk_size == 32 * 1024,
    "WebSocket tunnel chunk is not 32 KiB per direction");

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

} // namespace

int main() {
    try {
        constexpr auto transaction_size = sizeof(PlainProxyTransaction);
        require(
            transaction_size < 32 * 1024,
            "queued ProxyTransaction fixed footprint regressed above 32 KiB");
        require(
            webserver::proxy::detail::http_transfer_chunk_size == 16 * 1024,
            "HTTP transfer chunk is not 16 KiB");
        require(
            webserver::proxy::detail::tunnel_chunk_size == 32 * 1024,
            "WebSocket tunnel chunk is not 32 KiB per direction");

        std::cout << "ProxyTransaction fixed footprint: " << transaction_size
                  << " bytes\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "ProxyTransaction memory test failed: " << error.what() << '\n';
        return 1;
    }
}
