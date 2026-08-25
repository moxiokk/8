#include "routing/HostNormalizer.hpp"
#include "routing/VirtualHostRouter.hpp"

#include <cstdlib>
#include <exception>
#include <iostream>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

void require_host(
    const std::optional<std::string>& actual,
    std::string_view expected,
    std::string_view message) {
    require(actual.has_value() && *actual == expected, std::string{message});
}

void test_host_normalization() {
    using webserver::routing::HostNormalizer;

    require_host(
        HostNormalizer::normalize_authority("A.COM.:8080"),
        "a.com",
        "mixed-case authority was not normalized");
    require_host(
        HostNormalizer::normalize_authority("[2001:DB8::1]:443"),
        "2001:db8::1",
        "IPv6 authority was not normalized");
    require_host(
        HostNormalizer::normalize_domain("WWW.Example.COM."),
        "www.example.com",
        "configured domain was not normalized");

    require(
        !HostNormalizer::normalize_authority("a.com:65536"),
        "out-of-range port was accepted");
    require(
        !HostNormalizer::normalize_authority("bad host"),
        "authority containing whitespace was accepted");
    require(
        !HostNormalizer::normalize_authority("-a.com"),
        "invalid DNS label was accepted");
    require(
        !HostNormalizer::normalize_domain("a.com:80"),
        "configured domain containing a port was accepted");
    require(
        !HostNormalizer::normalize_authority("[::::]:80"),
        "invalid IPv6 literal was accepted");
    require(
        !HostNormalizer::normalize_authority("[192.0.2.1::]:80"),
        "IPv4 component before IPv6 compression was accepted");
    require(
        !HostNormalizer::normalize_authority("a.com.."),
        "domain containing two trailing dots was accepted");
}

void test_virtual_host_lookup() {
    using webserver::routing::BackendConfig;
    using webserver::routing::VirtualHostConfig;
    using webserver::routing::VirtualHostRouter;

    VirtualHostRouter router{{
        VirtualHostConfig{
            "site-a", {"a.com", "www.a.com", "*.a.test"},
            BackendConfig{"127.0.0.1", 8090}},
        VirtualHostConfig{
            "generic", {"*.example.com"},
            BackendConfig{"127.0.0.1", 8091}},
        VirtualHostConfig{
            "api", {"*.api.example.com"},
            BackendConfig{"::1", 8092}},
    }};

    require(router.exact_host_count() == 2, "unexpected exact-domain count");
    require(router.wildcard_host_count() == 3, "unexpected wildcard-domain count");

    const auto exact = router.find("a.com");
    require(exact && exact->name() == "site-a", "exact domain did not resolve");
    require(
        exact->backend().address == "127.0.0.1" &&
            exact->backend().port == 8090,
        "exact domain resolved to the wrong backend");

    const auto wildcard = router.find("one.a.test");
    require(wildcard && wildcard->name() == "site-a", "wildcard domain did not resolve");

    const auto longest = router.find("v1.api.example.com");
    require(longest && longest->name() == "api", "longest wildcard suffix did not win");

    require(!router.find("example.com"), "wildcard unexpectedly matched its root domain");
    require(!router.find("unknown.test"), "unknown domain unexpectedly resolved");
}

void test_duplicate_domain_rejected() {
    using webserver::routing::BackendConfig;
    using webserver::routing::VirtualHostConfig;
    using webserver::routing::VirtualHostRouter;

    bool rejected = false;
    try {
        const VirtualHostRouter router{{
            VirtualHostConfig{"first", {"A.COM"}, BackendConfig{"127.0.0.1", 80}},
            VirtualHostConfig{"second", {"a.com."}, BackendConfig{"127.0.0.1", 81}},
        }};
        static_cast<void>(router);
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, "duplicate normalized domain was accepted");
}

void test_invalid_backend_rejected() {
    using webserver::routing::BackendConfig;
    using webserver::routing::VirtualHostConfig;
    using webserver::routing::VirtualHostRouter;

    const VirtualHostRouter hostname_router{{
        VirtualHostConfig{
            "hostname", {"hostname.example"}, BackendConfig{"localhost", 8090}},
    }};
    require(
        hostname_router.find("hostname.example") != nullptr,
        "valid backend hostname was rejected");

    bool invalid_address_rejected = false;
    try {
        const VirtualHostRouter router{{
            VirtualHostConfig{
                "invalid", {"invalid.example"}, BackendConfig{"bad host", 8090}},
        }};
        static_cast<void>(router);
    } catch (const std::invalid_argument&) {
        invalid_address_rejected = true;
    }
    require(invalid_address_rejected, "invalid backend hostname was accepted");

    bool zero_port_rejected = false;
    try {
        const VirtualHostRouter router{{
            VirtualHostConfig{
                "invalid", {"invalid.example"}, BackendConfig{"127.0.0.1", 0}},
        }};
        static_cast<void>(router);
    } catch (const std::invalid_argument&) {
        zero_port_rejected = true;
    }
    require(zero_port_rejected, "zero backend port was accepted");
}

} // namespace

int main() {
    try {
        test_host_normalization();
        test_virtual_host_lookup();
        test_duplicate_domain_rejected();
        test_invalid_backend_rejected();
        std::cout << "VirtualHost tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "VirtualHost tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
