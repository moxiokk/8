#include "network/ClientIpResolver.hpp"

#include <boost/asio/ip/address.hpp>

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

void run_test() {
    using boost::asio::ip::make_address;
    webserver::network::ClientIpResolver resolver{
        {"127.0.0.0/8", "10.0.0.0/8", "2400:cb00::/32"},
        {"EO-Connecting-IP", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For"}};

    require(
        resolver.resolve(make_address("203.0.113.8"),
            {{"EO-Connecting-IP", "192.0.2.44"}, {"CF-Connecting-IP", "198.51.100.4"}}) ==
            "203.0.113.8",
        "untrusted TCP peer was allowed to spoof forwarding headers");
    require(
        resolver.resolve(make_address("127.0.0.1"),
            {{"EO-Connecting-IP", "192.0.2.44"}, {"CF-Connecting-IP", "198.51.100.4"}}) ==
            "192.0.2.44",
        "custom header priority was not respected");

    webserver::network::ClientIpResolver xff_only{
        {"127.0.0.0/8", "10.0.0.0/8"}, {"X-Forwarded-For"}};
    require(
        xff_only.resolve(
            make_address("127.0.0.1"), {{"X-Forwarded-For", "198.51.100.10, 10.2.3.4"}}) ==
            "198.51.100.10",
        "X-Forwarded-For chain was not walked from the trusted edge");
    require(
        xff_only.resolve(make_address("127.0.0.1"), {{"X-Forwarded-For", "not-an-ip"}}) == "127.0.0.1",
        "malformed forwarding chain was not rejected");

    bool invalid_rejected = false;
    try {
        static_cast<void>(webserver::network::ClientIpResolver{{"10.0.0.0/99"}, {"X-Forwarded-For"}});
    } catch (const std::invalid_argument&) {
        invalid_rejected = true;
    }
    require(invalid_rejected, "invalid CIDR prefix was accepted");
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Client IP resolver tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Client IP resolver tests failed: " << error.what() << '\n';
        return 1;
    }
}
