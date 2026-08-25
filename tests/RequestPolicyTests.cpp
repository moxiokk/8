#include "policy/RequestPolicy.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

struct TestRequest final {
    std::string method{"GET"};
    std::string target{"/"};
    std::string user_agent;
    std::string referer;
    std::unordered_map<std::string, std::string> headers;

    [[nodiscard]] webserver::policy::RequestView view() const {
        return webserver::policy::RequestView{
            method,
            target,
            user_agent,
            referer,
            [this](std::string_view name) -> std::string_view {
                const auto found = headers.find(std::string{name});
                return found == headers.end() ? std::string_view{} : found->second;
            }};
    }
};

TestRequest request(std::string method, std::string target) {
    TestRequest result;
    result.method = std::move(method);
    result.target = std::move(target);
    return result;
}

webserver::policy::AclConditionSpec condition(
    webserver::policy::AclField field,
    webserver::policy::MatchOperator operation,
    std::string value) {
    webserver::policy::AclConditionSpec result;
    result.field = field;
    result.operation = operation;
    result.value = std::move(value);
    return result;
}

void test_acl_and_precompiled_regex() {
    using namespace webserver::policy;
    auto header_condition = condition(AclField::header, MatchOperator::equal, "blocked");
    header_condition.header_name = "X-Policy-Test";
    SitePolicySpec spec;
    spec.acl_rules = {
        AclRuleSpec{
            "allow local admin",
            true,
            {condition(AclField::uri, MatchOperator::starts_with, "/admin"),
             condition(AclField::ip, MatchOperator::equal, "127.0.0.1")},
            AclAction::allow,
            403,
            {}},
        AclRuleSpec{
            "block admin",
            true,
            {condition(AclField::uri, MatchOperator::starts_with, "/admin")},
            AclAction::deny,
            404,
            {}},
        AclRuleSpec{
            "block secrets",
            true,
            {condition(AclField::uri, MatchOperator::regex, R"(^/(\.git|\.env)(/|$))")},
            AclAction::deny,
            403,
            {}},
        AclRuleSpec{
            "block custom header",
            true,
            {std::move(header_condition)},
            AclAction::return_status,
            429,
            {}},
    };
    RequestPolicy policy{std::move(spec), {"example.test"}};

    require(
        !policy.evaluate(request("GET", "/admin").view(), "127.0.0.1", "example.test", "https"),
        "ACL allow did not stop later ACL rules");
    const auto remote_admin = policy.evaluate(
        request("GET", "/admin").view(), "192.0.2.5", "example.test", "https");
    require(remote_admin && remote_admin->status == 404,
            "multi-condition ACL did not deny the remote address");
    const auto secret = policy.evaluate(
        request("GET", "/.git/config").view(), "127.0.0.1", "example.test", "https");
    require(secret && secret->status == 403,
            "precompiled ACL Regex did not match");
    auto header_request = request("GET", "/");
    header_request.headers.emplace("X-Policy-Test", "BLOCKED");
    const auto header_block = policy.evaluate(
        header_request.view(), "127.0.0.1", "example.test", "https");
    require(header_block && header_block->status == 429,
            "arbitrary Header ACL did not match case-insensitively");

    bool invalid_regex_rejected = false;
    try {
        SitePolicySpec invalid;
        invalid.acl_rules = {AclRuleSpec{
            "bad regex",
            true,
            {condition(AclField::uri, MatchOperator::regex, "[")},
            AclAction::deny,
            403,
            {}}};
        const RequestPolicy ignored{std::move(invalid), {"example.test"}};
        static_cast<void>(ignored);
    } catch (const std::invalid_argument&) {
        invalid_regex_rejected = true;
    }
    require(invalid_regex_rejected, "invalid ACL Regex was accepted");

    bool unsupported_regex_rejected = false;
    try {
        SitePolicySpec invalid;
        invalid.acl_rules = {AclRuleSpec{
            "unsupported regex",
            true,
            {condition(AclField::uri, MatchOperator::regex, R"(^(a+)\1$)")},
            AclAction::deny,
            403,
            {}}};
        const RequestPolicy ignored{std::move(invalid), {"example.test"}};
        static_cast<void>(ignored);
    } catch (const std::invalid_argument&) {
        unsupported_regex_rejected = true;
    }
    require(unsupported_regex_rejected, "unsupported RE2 backreference was accepted");

    auto linear_condition = condition(AclField::header, MatchOperator::regex, R"((a+)+$)");
    linear_condition.header_name = "X-Regex-Test";
    SitePolicySpec linear_spec;
    linear_spec.acl_rules = {AclRuleSpec{
        "linear regex",
        true,
        {std::move(linear_condition)},
        AclAction::deny,
        403,
        {}}};
    RequestPolicy linear_policy{std::move(linear_spec), {"example.test"}};
    auto adversarial_request = request("GET", "/");
    adversarial_request.headers.emplace("X-Regex-Test", std::string(4096, 'a') + '!');
    require(
        !linear_policy.evaluate(
            adversarial_request.view(), "127.0.0.1", "example.test", "https"),
        "RE2 ACL incorrectly matched an adversarial non-match");
}

void test_acl_cidr_operators() {
    using namespace webserver::policy;
    SitePolicySpec block_ranges_spec;
    block_ranges_spec.acl_rules = {
        AclRuleSpec{
            "block private IPv4",
            true,
            {condition(AclField::ip, MatchOperator::in_cidr, "192.168.0.0/16")},
            AclAction::deny,
            403,
            {}},
        AclRuleSpec{
            "block Cloudflare IPv6 example",
            true,
            {condition(AclField::ip, MatchOperator::in_cidr, "2400:cb00::/32")},
            AclAction::deny,
            403,
            {}},
    };
    RequestPolicy block_ranges{std::move(block_ranges_spec), {"example.test"}};

    require(
        block_ranges.evaluate(
            request("GET", "/").view(), "192.168.42.7", "example.test", "https")
            .has_value(),
        "IPv4 in_cidr did not match an address inside the range");
    require(
        !block_ranges.evaluate(
            request("GET", "/").view(), "192.169.0.1", "example.test", "https"),
        "IPv4 in_cidr matched an address outside the range");
    require(
        block_ranges.evaluate(
            request("GET", "/").view(), "2400:cb00:1234::1", "example.test", "https")
            .has_value(),
        "IPv6 in_cidr did not match an address inside the range");
    require(
        !block_ranges.evaluate(
            request("GET", "/").view(), "2400:cb01::1", "example.test", "https"),
        "IPv6 in_cidr matched an address outside the range");

    SitePolicySpec outside_range_spec;
    outside_range_spec.acl_rules = {AclRuleSpec{
        "block non-corporate addresses",
        true,
        {condition(AclField::ip, MatchOperator::not_in_cidr, "10.0.0.0/8")},
        AclAction::deny,
        403,
        {}}};
    RequestPolicy outside_range{std::move(outside_range_spec), {"example.test"}};
    require(
        !outside_range.evaluate(
            request("GET", "/").view(), "10.255.0.8", "example.test", "https"),
        "not_in_cidr matched an address inside the range");
    require(
        outside_range.evaluate(
            request("GET", "/").view(), "203.0.113.8", "example.test", "https")
            .has_value(),
        "not_in_cidr did not match an address outside the range");

    const auto require_invalid_cidr = [](AclField field, std::string value) {
        bool rejected = false;
        try {
            SitePolicySpec invalid;
            invalid.acl_rules = {AclRuleSpec{
                "invalid CIDR",
                true,
                {condition(field, MatchOperator::in_cidr, std::move(value))},
                AclAction::deny,
                403,
                {}}};
            const RequestPolicy ignored{std::move(invalid), {"example.test"}};
            static_cast<void>(ignored);
        } catch (const std::invalid_argument&) {
            rejected = true;
        }
        require(rejected, "invalid ACL CIDR configuration was accepted");
    };
    require_invalid_cidr(AclField::ip, "192.168.0.0/33");
    require_invalid_cidr(AclField::ip, "192.168.0.0");
    require_invalid_cidr(AclField::ip, "2400:cb00::/129");
    require_invalid_cidr(AclField::uri, "192.168.0.0/16");
}

void test_rate_limit_and_request_interception() {
    using namespace webserver::policy;
    SitePolicySpec spec;
    spec.rate_limit = RateLimitSpec{true, 60, 2, 4};
    RequestPolicy policy{std::move(spec), {"example.test"}};

    require(!policy.evaluate(request("GET", "/").view(), "192.0.2.1", "example.test", "http"),
            "first rate-limited request was rejected");
    require(!policy.evaluate(request("GET", "/").view(), "192.0.2.1", "example.test", "http"),
            "second rate-limited request was rejected");
    const auto limited = policy.evaluate(
        request("GET", "/").view(), "192.0.2.1", "example.test", "http");
    require(limited && limited->status == 429 &&
                limited->retry_after_seconds == 4,
            "token bucket did not apply the configured temporary ban");
    require(!policy.evaluate(request("GET", "/").view(), "192.0.2.2", "example.test", "http"),
            "rate limiter was not isolated by client IP");

    SitePolicySpec basic_spec;
    RequestPolicy basic{std::move(basic_spec), {"example.test"}};
    const auto trace = basic.evaluate(
        request("TRACE", "/").view(), "127.0.0.1", "example.test", "http");
    require(trace && trace->status == 405,
            "TRACE request was not intercepted");
}

void test_rate_limit_capacity_and_ip_deny_order() {
    using namespace webserver::policy;

    SitePolicySpec capacity_spec;
    capacity_spec.rate_limit = RateLimitSpec{true, 3600, 1, 0};
    RequestPolicy capacity_policy{std::move(capacity_spec), {"example.test"}};
    const auto basic_request = request("GET", "/");
    for (std::uint32_t index = 0; index < 65536U; ++index) {
        const auto client_ip =
            "10." + std::to_string((index >> 16U) & 0xffU) + '.' +
            std::to_string((index >> 8U) & 0xffU) + '.' +
            std::to_string(index & 0xffU);
        require(
            !capacity_policy.evaluate(
                basic_request.view(), client_ip, "example.test", "https"),
            "a new client was rejected before the rate-limit table reached capacity");
    }

    constexpr std::string_view new_client = "10.1.0.0";
    require(
        !capacity_policy.evaluate(
            basic_request.view(), new_client, "example.test", "https"),
        "a new client was rejected when the rate-limit table was full");
    const auto tracked_new_client = capacity_policy.evaluate(
        basic_request.view(), new_client, "example.test", "https");
    require(
        tracked_new_client && tracked_new_client->status == 429,
        "the client admitted after LRU eviction was not tracked");

    SitePolicySpec deny_spec;
    deny_spec.rate_limit = RateLimitSpec{true, 3600, 1, 60};
    deny_spec.acl_rules = {AclRuleSpec{
        "block abusive range",
        true,
        {condition(AclField::ip, MatchOperator::in_cidr, "192.0.2.0/24")},
        AclAction::deny,
        403,
        {}}};
    RequestPolicy deny_policy{std::move(deny_spec), {"example.test"}};
    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto denied = deny_policy.evaluate(
            basic_request.view(), "192.0.2.44", "example.test", "https");
        require(
            denied && denied->status == 403,
            "a pure IP/CIDR deny rule did not run before rate limiting");
    }
}

void test_hotlink_and_redirects() {
    using namespace webserver::policy;
    SitePolicySpec hotlink_spec;
    hotlink_spec.hotlink.enabled = true;
    hotlink_spec.hotlink.protected_extensions = {".JPG", "mp4"};
    hotlink_spec.hotlink.allowed_hosts = {"*.trusted.test"};
    hotlink_spec.hotlink.allow_empty_referer = false;
    RequestPolicy hotlink{std::move(hotlink_spec), {"example.test", "*.example.test"}};

    auto same_site = request("GET", "/assets/photo.JPG?v=1");
    same_site.referer = "https://www.example.test/page";
    require(!hotlink.evaluate(same_site.view(), "127.0.0.1", "example.test", "https"),
            "same-site Referer was blocked");
    auto trusted = request("GET", "/movie.mp4");
    trusted.referer = "https://cdn.trusted.test/watch";
    require(!hotlink.evaluate(trusted.view(), "127.0.0.1", "example.test", "https"),
            "explicit wildcard Referer allow-list did not match");
    auto stolen = request("GET", "/photo.jpg");
    stolen.referer = "https://attacker.test/";
    const auto blocked = hotlink.evaluate(stolen.view(), "127.0.0.1", "example.test", "https");
    require(blocked && blocked->status == 403,
            "cross-site hotlink was not blocked");

    SitePolicySpec redirect_spec;
    redirect_spec.redirects = {
        RedirectRuleSpec{
            "www to apex", true, "www.example.test", "/", RedirectMatch::prefix,
            "https://example.test", 308, true, true},
        RedirectRuleSpec{
            "old path", true, {}, "/old", RedirectMatch::exact,
            "/new", 301, false, true},
    };
    RequestPolicy redirects{std::move(redirect_spec), {"example.test", "www.example.test"}};
    const auto host_redirect = redirects.evaluate(
        request("GET", "/docs/item?q=1").view(),
        "127.0.0.1", "www.example.test", "https");
    require(host_redirect && host_redirect->status == 308 &&
                host_redirect->location == "https://example.test/docs/item?q=1",
            "host redirect did not preserve path and query");
    const auto path_redirect = redirects.evaluate(
        request("GET", "/old?source=legacy").view(),
        "127.0.0.1", "example.test", "https");
    require(path_redirect && path_redirect->location == "/new?source=legacy",
            "path redirect did not preserve the query");

    SitePolicySpec force_spec;
    force_spec.force_https = true;
    force_spec.https_port = 8443;
    RequestPolicy force_https{std::move(force_spec), {"example.test"}};
    const auto forced = force_https.evaluate(
        request("GET", "/path?q=1").view(),
        "127.0.0.1", "example.test", "http");
    require(forced && forced->status == 308 &&
                forced->location == "https://example.test:8443/path?q=1",
            "HTTP to HTTPS redirect used the wrong authority or target");
}

} // namespace

int main() {
    try {
        test_acl_and_precompiled_regex();
        test_acl_cidr_operators();
        test_rate_limit_and_request_interception();
        test_rate_limit_capacity_and_ip_deny_order();
        test_hotlink_and_redirects();
        std::cout << "Request policy tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Request policy tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
