#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace webserver::policy {

enum class AclField {
    ip,
    uri,
    host,
    method,
    user_agent,
    referer,
    header,
};

enum class MatchOperator {
    equal,
    not_equal,
    contains,
    not_contains,
    starts_with,
    ends_with,
    regex,
    in_cidr,
    not_in_cidr,
};

enum class AclAction {
    allow,
    deny,
    redirect,
    return_status,
};

struct AclConditionSpec final {
    AclField field{AclField::uri};
    MatchOperator operation{MatchOperator::contains};
    std::string value;
    std::string header_name;
    bool case_sensitive{false};
};

struct AclRuleSpec final {
    std::string name;
    bool enabled{true};
    std::vector<AclConditionSpec> conditions;
    AclAction action{AclAction::deny};
    unsigned status{403};
    std::string redirect_location;
};

struct RateLimitSpec final {
    bool enabled{false};
    std::uint32_t window_seconds{10};
    std::uint32_t max_requests{100};
    std::uint32_t ban_seconds{60};
};

struct HotlinkSpec final {
    bool enabled{false};
    std::vector<std::string> protected_extensions;
    std::vector<std::string> allowed_hosts;
    bool allow_empty_referer{true};
    std::string redirect_location;
};

enum class RedirectMatch {
    exact,
    prefix,
};

struct RedirectRuleSpec final {
    std::string name;
    bool enabled{true};
    std::string source_host;
    std::string source_path{"/"};
    RedirectMatch match{RedirectMatch::exact};
    std::string destination;
    unsigned status{301};
    bool preserve_path{false};
    bool preserve_query{true};
};

struct SitePolicySpec final {
    bool force_https{false};
    std::uint16_t https_port{443};
    std::vector<AclRuleSpec> acl_rules;
    RateLimitSpec rate_limit;
    HotlinkSpec hotlink;
    std::vector<RedirectRuleSpec> redirects;
};

struct PolicyDecision final {
    unsigned status{403};
    std::string body;
    std::string location;
    std::uint32_t retry_after_seconds{};
};

struct RequestView final {
    std::string_view method;
    std::string_view target;
    std::string_view user_agent;
    std::string_view referer;
    std::function<std::string_view(std::string_view)> header_value;
};

class RequestPolicy final {
public:
    RequestPolicy(SitePolicySpec spec, std::vector<std::string> site_domains);
    ~RequestPolicy();

    RequestPolicy(const RequestPolicy&) = delete;
    RequestPolicy& operator=(const RequestPolicy&) = delete;
    RequestPolicy(RequestPolicy&&) noexcept;
    RequestPolicy& operator=(RequestPolicy&&) noexcept;

    [[nodiscard]] std::optional<PolicyDecision> evaluate(
        const RequestView& request,
        std::string_view client_ip,
        std::string_view normalized_host,
        std::string_view scheme);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace webserver::policy
