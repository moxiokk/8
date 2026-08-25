#include "policy/RequestPolicy.hpp"

#include "routing/HostNormalizer.hpp"

#include <boost/asio/ip/address.hpp>
#include <re2/re2.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cctype>
#include <iterator>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace webserver::policy {
namespace {

constexpr std::size_t max_uri_length = 8192;
constexpr std::size_t max_rate_limit_entries = 65536;

std::string ascii_lower(std::string_view value) {
    std::string result{value};
    std::transform(
        result.begin(), result.end(), result.begin(), [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return result;
}

bool wildcard_host_matches(std::string_view pattern, std::string_view host) {
    if (!pattern.starts_with("*.")) {
        return pattern == host;
    }
    pattern.remove_prefix(2);
    return host.size() > pattern.size() && host.ends_with(pattern) &&
           host[host.size() - pattern.size() - 1] == '.';
}

std::string normalized_host_pattern(std::string_view pattern) {
    const bool wildcard = pattern.starts_with("*.");
    const auto domain = routing::HostNormalizer::normalize_domain(
        wildcard ? pattern.substr(2) : pattern);
    if (!domain || (wildcard && domain->find('.') == std::string::npos)) {
        throw std::invalid_argument{"invalid policy host pattern: " + std::string{pattern}};
    }
    return wildcard ? "*." + *domain : *domain;
}

std::pair<std::string_view, std::string_view> split_target(std::string_view target) {
    const auto query = target.find('?');
    if (query == std::string_view::npos) {
        return {target, {}};
    }
    return {target.substr(0, query), target.substr(query + 1)};
}

std::string target_extension(std::string_view target) {
    const auto [path, ignored_query] = split_target(target);
    static_cast<void>(ignored_query);
    const auto slash = path.find_last_of('/');
    const auto dot = path.find_last_of('.');
    if (dot == std::string_view::npos || (slash != std::string_view::npos && dot < slash) ||
        dot + 1 >= path.size()) {
        return {};
    }
    return ascii_lower(path.substr(dot + 1));
}

std::optional<std::string> referer_host(std::string_view referer) {
    const auto scheme = referer.find("://");
    if (scheme == std::string_view::npos || scheme == 0) {
        return std::nullopt;
    }
    const auto normalized_scheme = ascii_lower(referer.substr(0, scheme));
    if (normalized_scheme != "http" && normalized_scheme != "https") {
        return std::nullopt;
    }
    const auto authority_start = scheme + 3;
    const auto authority_end = referer.find_first_of("/?#", authority_start);
    const auto authority = referer.substr(
        authority_start,
        authority_end == std::string_view::npos ? std::string_view::npos
                                                : authority_end - authority_start);
    return routing::HostNormalizer::normalize_authority(authority);
}

unsigned checked_status(unsigned value, std::string_view context) {
    if (value < 300 || value > 599) {
        throw std::invalid_argument{std::string{context} + " status is out of range"};
    }
    return value;
}

bool valid_redirect_status(unsigned status) {
    return status == 301 || status == 302 || status == 307 || status == 308;
}

bool valid_redirect_destination(std::string_view destination) {
    if (destination.empty() || destination.size() > 4096 ||
        std::any_of(destination.begin(), destination.end(), [](const unsigned char character) {
            return character <= 0x20U || character >= 0x7FU;
        })) {
        return false;
    }
    return destination.starts_with('/') || destination.starts_with("http://") ||
           destination.starts_with("https://");
}

bool valid_header_name(std::string_view name) {
    if (name.empty() || name.size() > 128) {
        return false;
    }
    constexpr std::string_view punctuation = "!#$%&'*+-.^_`|~";
    return std::all_of(name.begin(), name.end(), [&](const unsigned char character) {
        return std::isalnum(character) || punctuation.find(static_cast<char>(character)) !=
                                              std::string_view::npos;
    });
}

std::string append_path(std::string destination, std::string_view path) {
    if (path.empty()) {
        return destination;
    }
    if (!destination.empty() && destination.back() == '/' && path.front() == '/') {
        destination.pop_back();
    } else if (!destination.empty() && destination.back() != '/' && path.front() != '/') {
        destination.push_back('/');
    }
    destination.append(path);
    return destination;
}

class RateLimiter final {
public:
    explicit RateLimiter(RateLimitSpec spec) : spec_(spec) {
        if (!spec_.enabled) {
            return;
        }
        if (spec_.window_seconds == 0 || spec_.window_seconds > 3600) {
            throw std::invalid_argument{"rate limit window must be between 1 and 3600 seconds"};
        }
        if (spec_.max_requests == 0 || spec_.max_requests > 1000000) {
            throw std::invalid_argument{"rate limit maximum must be between 1 and 1000000"};
        }
        if (spec_.ban_seconds > 86400) {
            throw std::invalid_argument{"rate limit ban must not exceed 86400 seconds"};
        }
        entries_.reserve(max_rate_limit_entries);
    }

    [[nodiscard]] std::optional<std::uint32_t> check(std::string_view client_ip) {
        if (!spec_.enabled) {
            return std::nullopt;
        }

        const auto now = std::chrono::steady_clock::now();
        std::scoped_lock lock{mutex_};
        if ((++request_count_ & 1023U) == 0U) {
            cleanup(now);
        }

        const std::string key{client_ip};
        auto found = entries_.find(key);
        if (found == entries_.end()) {
            if (entries_.size() >= max_rate_limit_entries) {
                evict_oldest();
            }
            Entry entry;
            entry.tokens = static_cast<double>(spec_.max_requests - 1U);
            entry.updated = now;
            lru_.push_back(key);
            entry.lru_position = std::prev(lru_.end());
            try {
                entries_.emplace(key, std::move(entry));
            } catch (...) {
                lru_.pop_back();
                throw;
            }
            return std::nullopt;
        }

        auto& entry = found->second;
        lru_.splice(lru_.end(), lru_, entry.lru_position);
        if (entry.banned_until > now) {
            return seconds_until(entry.banned_until, now);
        }
        if (entry.banned_until != std::chrono::steady_clock::time_point{}) {
            entry.tokens = static_cast<double>(spec_.max_requests);
            entry.updated = now;
            entry.banned_until = {};
        }

        const auto elapsed = std::chrono::duration<double>(now - entry.updated).count();
        const auto refill_per_second =
            static_cast<double>(spec_.max_requests) / static_cast<double>(spec_.window_seconds);
        entry.tokens = std::min(
            static_cast<double>(spec_.max_requests), entry.tokens + (elapsed * refill_per_second));
        entry.updated = now;
        if (entry.tokens >= 1.0) {
            entry.tokens -= 1.0;
            return std::nullopt;
        }

        if (spec_.ban_seconds != 0) {
            entry.banned_until = now + std::chrono::seconds{spec_.ban_seconds};
            return spec_.ban_seconds;
        }
        return std::max<std::uint32_t>(
            1U,
            static_cast<std::uint32_t>(std::ceil((1.0 - entry.tokens) / refill_per_second)));
    }

private:
    struct Entry final {
        double tokens{};
        std::chrono::steady_clock::time_point updated{};
        std::chrono::steady_clock::time_point banned_until{};
        std::list<std::string>::iterator lru_position;
    };

    static std::uint32_t seconds_until(
        std::chrono::steady_clock::time_point deadline,
        std::chrono::steady_clock::time_point now) {
        const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - now).count();
        return std::max<std::uint32_t>(
            1U, static_cast<std::uint32_t>((milliseconds + 999) / 1000));
    }

    void cleanup(std::chrono::steady_clock::time_point now) {
        const auto retention = std::chrono::seconds{
            static_cast<std::int64_t>(spec_.window_seconds + spec_.ban_seconds + 1U)};
        for (auto iterator = entries_.begin(); iterator != entries_.end();) {
            if (iterator->second.banned_until <= now && now - iterator->second.updated > retention) {
                lru_.erase(iterator->second.lru_position);
                iterator = entries_.erase(iterator);
            } else {
                ++iterator;
            }
        }
    }

    void evict_oldest() {
        if (lru_.empty()) {
            return;
        }
        entries_.erase(lru_.front());
        lru_.pop_front();
    }

    RateLimitSpec spec_;
    std::mutex mutex_;
    std::unordered_map<std::string, Entry> entries_;
    std::list<std::string> lru_;
    std::uint64_t request_count_{};
};

struct CompiledCondition final {
    struct CidrRange final {
        boost::asio::ip::address network;
        std::uint8_t prefix{};
    };

    AclConditionSpec spec;
    std::unique_ptr<re2::RE2> regex;
    std::optional<CidrRange> cidr;
};

struct CompiledAclRule final {
    AclRuleSpec spec;
    std::vector<CompiledCondition> conditions;
};

struct CompiledRedirect final {
    RedirectRuleSpec spec;
};

CompiledCondition::CidrRange parse_acl_cidr(std::string_view text) {
    const auto slash = text.find('/');
    if (slash == std::string_view::npos || slash == 0 || slash + 1 >= text.size() ||
        text.find('/', slash + 1) != std::string_view::npos) {
        throw std::invalid_argument{"ACL CIDR must use address/prefix notation"};
    }

    boost::system::error_code error;
    const auto network = boost::asio::ip::make_address(std::string{text.substr(0, slash)}, error);
    if (error) {
        throw std::invalid_argument{"ACL contains an invalid CIDR address"};
    }

    const unsigned maximum_prefix = network.is_v4() ? 32U : 128U;
    unsigned prefix{};
    const auto prefix_text = text.substr(slash + 1);
    const auto [end, parse_error] = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (parse_error != std::errc{} || end != prefix_text.data() + prefix_text.size() ||
        prefix > maximum_prefix) {
        throw std::invalid_argument{"ACL contains an invalid CIDR prefix"};
    }
    return {network, static_cast<std::uint8_t>(prefix)};
}

bool cidr_contains(
    const CompiledCondition::CidrRange& range,
    const boost::asio::ip::address& candidate) {
    if (range.network.is_v4() != candidate.is_v4()) return false;
    if (candidate.is_v4()) {
        const auto prefix = static_cast<unsigned>(range.prefix);
        const std::uint32_t mask = prefix == 0 ? 0U : 0xffffffffU << (32U - prefix);
        return (range.network.to_v4().to_uint() & mask) ==
               (candidate.to_v4().to_uint() & mask);
    }

    const auto network = range.network.to_v6().to_bytes();
    const auto address = candidate.to_v6().to_bytes();
    const auto full_bytes = static_cast<std::size_t>(range.prefix / 8U);
    const auto remaining_bits = static_cast<unsigned>(range.prefix % 8U);
    if (!std::equal(network.begin(), network.begin() + full_bytes, address.begin())) return false;
    if (remaining_bits == 0) return true;
    const auto mask = static_cast<unsigned char>(0xffU << (8U - remaining_bits));
    return (network[full_bytes] & mask) == (address[full_bytes] & mask);
}

std::string_view field_value(
    const RequestView& request,
    const AclConditionSpec& condition,
    std::string_view client_ip,
    std::string_view host) {
    switch (condition.field) {
    case AclField::ip:
        return client_ip;
    case AclField::uri:
        return request.target;
    case AclField::host:
        return host;
    case AclField::method:
        return request.method;
    case AclField::user_agent:
        return request.user_agent;
    case AclField::referer:
        return request.referer;
    case AclField::header:
        return request.header_value ? request.header_value(condition.header_name)
                                    : std::string_view{};
    }
    return {};
}

bool match_condition(
    const CompiledCondition& condition,
    std::string_view candidate) {
    if (condition.spec.operation == MatchOperator::regex) {
        return re2::RE2::PartialMatch(
            re2::StringPiece{candidate.data(), candidate.size()}, *condition.regex);
    }
    if (condition.spec.operation == MatchOperator::in_cidr ||
        condition.spec.operation == MatchOperator::not_in_cidr) {
        boost::system::error_code error;
        const auto address = boost::asio::ip::make_address(std::string{candidate}, error);
        if (error) return false;
        const bool contained = cidr_contains(*condition.cidr, address);
        return condition.spec.operation == MatchOperator::in_cidr ? contained : !contained;
    }

    const std::string normalized_candidate = condition.spec.case_sensitive
                                                 ? std::string{candidate}
                                                 : ascii_lower(candidate);
    const std::string normalized_expected = condition.spec.case_sensitive
                                                ? condition.spec.value
                                                : ascii_lower(condition.spec.value);
    const std::string_view value{normalized_candidate};
    const std::string_view expected{normalized_expected};
    switch (condition.spec.operation) {
    case MatchOperator::equal:
        return value == expected;
    case MatchOperator::not_equal:
        return value != expected;
    case MatchOperator::contains:
        return value.find(expected) != std::string_view::npos;
    case MatchOperator::not_contains:
        return value.find(expected) == std::string_view::npos;
    case MatchOperator::starts_with:
        return value.starts_with(expected);
    case MatchOperator::ends_with:
        return value.ends_with(expected);
    case MatchOperator::regex:
    case MatchOperator::in_cidr:
    case MatchOperator::not_in_cidr:
        break;
    }
    return false;
}

bool is_pre_rate_limit_ip_deny(const CompiledAclRule& rule) {
    if (rule.spec.action != AclAction::deny) {
        return false;
    }
    return std::all_of(
        rule.conditions.begin(), rule.conditions.end(), [](const auto& condition) {
            if (condition.spec.field != AclField::ip) {
                return false;
            }
            return condition.spec.operation == MatchOperator::equal ||
                   condition.spec.operation == MatchOperator::in_cidr ||
                   condition.spec.operation == MatchOperator::not_in_cidr;
        });
}

} // namespace

class RequestPolicy::Impl final {
public:
    Impl(SitePolicySpec spec, std::vector<std::string> site_domains)
        : spec_(std::move(spec)), rate_limiter_(spec_.rate_limit) {
        for (const auto& domain : site_domains) {
            hotlink_hosts_.insert(normalized_host_pattern(domain));
        }
        for (const auto& host : spec_.hotlink.allowed_hosts) {
            hotlink_hosts_.insert(normalized_host_pattern(host));
        }
        for (auto extension : spec_.hotlink.protected_extensions) {
            if (extension.starts_with('.')) {
                extension.erase(extension.begin());
            }
            extension = ascii_lower(extension);
            if (extension.empty() || extension.size() > 16 ||
                !std::all_of(extension.begin(), extension.end(), [](const unsigned char character) {
                    return std::isalnum(character);
                })) {
                throw std::invalid_argument{"invalid hotlink-protected extension"};
            }
            hotlink_extensions_.insert(std::move(extension));
        }
        if (spec_.hotlink.enabled && hotlink_extensions_.empty()) {
            throw std::invalid_argument{"hotlink protection requires at least one extension"};
        }
        if (!spec_.hotlink.redirect_location.empty() &&
            !valid_redirect_destination(spec_.hotlink.redirect_location)) {
            throw std::invalid_argument{"invalid hotlink redirect destination"};
        }

        compile_acl();
        compile_redirects();
    }

    std::optional<PolicyDecision> evaluate(
        const RequestView& request,
        std::string_view client_ip,
        std::string_view normalized_host,
        std::string_view scheme) {
        const auto method = ascii_lower(request.method);
        if (method == "trace" || method == "track") {
            return PolicyDecision{405, "Method is not allowed", {}, 0};
        }
        if (request.target.size() > max_uri_length) {
            return PolicyDecision{414, "Request target is too long", {}, 0};
        }

        if (const auto decision = evaluate_acl(
                pre_rate_limit_acl_rules_, request, client_ip, normalized_host)) {
            return decision;
        }

        if (const auto retry_after = rate_limiter_.check(client_ip)) {
            return PolicyDecision{
                429,
                "Rate limit exceeded",
                {},
                *retry_after};
        }

        if (const auto decision = evaluate_acl(
                acl_rules_, request, client_ip, normalized_host)) {
            return decision;
        }
        return evaluate_post_acl(request, normalized_host, scheme);
    }

private:
    static std::optional<PolicyDecision> evaluate_acl(
        const std::vector<CompiledAclRule>& rules,
        const RequestView& request,
        std::string_view client_ip,
        std::string_view normalized_host) {
        for (const auto& rule : rules) {
            const bool matched = std::all_of(
                rule.conditions.begin(),
                rule.conditions.end(),
                [&](const auto& condition) {
                    return match_condition(
                        condition,
                        field_value(request, condition.spec, client_ip, normalized_host));
                });
            if (!matched) {
                continue;
            }
            if (rule.spec.action == AclAction::allow) {
                break;
            }
            if (rule.spec.action == AclAction::redirect) {
                return PolicyDecision{
                    checked_status(rule.spec.status, "ACL redirect"),
                    {},
                    rule.spec.redirect_location};
            }
            return PolicyDecision{
                checked_status(rule.spec.status, "ACL"),
                rule.spec.action == AclAction::deny ? "Request denied by ACL"
                                                    : "Request blocked by ACL",
                {},
                0};
        }

        return std::nullopt;
    }

    std::optional<PolicyDecision> evaluate_post_acl(
        const RequestView& request,
        std::string_view normalized_host,
        std::string_view scheme) const {
        if (spec_.force_https && scheme == "http") {
            std::string location = "https://";
            if (normalized_host.find(':') != std::string_view::npos) {
                location += '[' + std::string{normalized_host} + ']';
            } else {
                location.append(normalized_host);
            }
            if (spec_.https_port != 443) {
                location += ':' + std::to_string(spec_.https_port);
            }
            location.append(request.target);
            return PolicyDecision{308, {}, std::move(location)};
        }

        if (const auto redirect = evaluate_redirects(request, normalized_host)) {
            return redirect;
        }
        return evaluate_hotlink(request);
    }
    void compile_acl() {
        if (spec_.acl_rules.size() > 200) {
            throw std::invalid_argument{"a site cannot contain more than 200 ACL rules"};
        }
        acl_rules_.reserve(spec_.acl_rules.size());
        for (auto rule : spec_.acl_rules) {
            if (!rule.enabled) {
                continue;
            }
            if (rule.name.empty() || rule.name.size() > 128 || rule.conditions.empty() ||
                rule.conditions.size() > 8) {
                throw std::invalid_argument{"invalid ACL rule name or condition count"};
            }
            if (rule.action == AclAction::redirect) {
                if (!valid_redirect_status(rule.status) ||
                    !valid_redirect_destination(rule.redirect_location)) {
                    throw std::invalid_argument{"invalid ACL redirect action"};
                }
            } else if (rule.action != AclAction::allow &&
                       rule.status != 403 && rule.status != 404 && rule.status != 429) {
                throw std::invalid_argument{"ACL status must be 403, 404, or 429"};
            }

            CompiledAclRule compiled;
            compiled.spec = std::move(rule);
            compiled.conditions.reserve(compiled.spec.conditions.size());
            for (const auto& condition : compiled.spec.conditions) {
                if (condition.value.empty() || condition.value.size() > 4096) {
                    throw std::invalid_argument{"ACL condition value must contain 1 to 4096 characters"};
                }
                if (condition.field == AclField::header &&
                    !valid_header_name(condition.header_name)) {
                    throw std::invalid_argument{"ACL Header match requires a valid header name"};
                }
                CompiledCondition compiled_condition;
                compiled_condition.spec = condition;
                if (condition.operation == MatchOperator::regex) {
                    re2::RE2::Options options;
                    options.set_case_sensitive(condition.case_sensitive);
                    options.set_log_errors(false);
                    compiled_condition.regex =
                        std::make_unique<re2::RE2>(condition.value, options);
                    if (!compiled_condition.regex->ok()) {
                        throw std::invalid_argument{
                            "ACL contains an invalid or unsupported RE2 expression"};
                    }
                } else if (condition.operation == MatchOperator::in_cidr ||
                           condition.operation == MatchOperator::not_in_cidr) {
                    if (condition.field != AclField::ip) {
                        throw std::invalid_argument{"ACL CIDR operators are only valid for the IP field"};
                    }
                    compiled_condition.cidr.emplace(parse_acl_cidr(condition.value));
                }
                compiled.conditions.push_back(std::move(compiled_condition));
            }
            if (is_pre_rate_limit_ip_deny(compiled)) {
                pre_rate_limit_acl_rules_.push_back(std::move(compiled));
            } else {
                acl_rules_.push_back(std::move(compiled));
            }
        }
    }

    void compile_redirects() {
        if (spec_.redirects.size() > 100) {
            throw std::invalid_argument{"a site cannot contain more than 100 redirect rules"};
        }
        redirects_.reserve(spec_.redirects.size());
        for (auto rule : spec_.redirects) {
            if (!rule.enabled) {
                continue;
            }
            if (rule.name.empty() || rule.name.size() > 128 ||
                rule.source_path.empty() || !rule.source_path.starts_with('/') ||
                rule.source_path.size() > max_uri_length ||
                !valid_redirect_status(rule.status) ||
                !valid_redirect_destination(rule.destination)) {
                throw std::invalid_argument{"invalid redirect rule"};
            }
            if (!rule.source_host.empty()) {
                rule.source_host = normalized_host_pattern(rule.source_host);
            }
            redirects_.push_back(CompiledRedirect{std::move(rule)});
        }
    }

    std::optional<PolicyDecision> evaluate_redirects(
        const RequestView& request,
        std::string_view normalized_host) const {
        const auto [path, query] = split_target(request.target);
        for (const auto& redirect : redirects_) {
            const auto& rule = redirect.spec;
            if (!rule.source_host.empty() &&
                !wildcard_host_matches(rule.source_host, normalized_host)) {
                continue;
            }
            const bool path_matches = rule.match == RedirectMatch::exact
                                          ? path == rule.source_path
                                          : path.starts_with(rule.source_path);
            if (!path_matches) {
                continue;
            }

            std::string location = rule.destination;
            if (rule.preserve_path) {
                const auto preserved = rule.match == RedirectMatch::prefix
                                           ? path.substr(rule.source_path.size())
                                           : path;
                location = append_path(std::move(location), preserved);
            }
            if (rule.preserve_query && !query.empty()) {
                location += location.find('?') == std::string::npos ? '?' : '&';
                location.append(query);
            }
            return PolicyDecision{
                rule.status, {}, std::move(location)};
        }
        return std::nullopt;
    }

    std::optional<PolicyDecision> evaluate_hotlink(const RequestView& request) const {
        if (!spec_.hotlink.enabled ||
            !hotlink_extensions_.contains(target_extension(request.target))) {
            return std::nullopt;
        }

        const auto referer = request.referer;
        if (referer.empty()) {
            if (spec_.hotlink.allow_empty_referer) {
                return std::nullopt;
            }
        } else if (const auto host = referer_host(referer)) {
            const bool allowed = std::any_of(
                hotlink_hosts_.begin(), hotlink_hosts_.end(), [&](const auto& pattern) {
                    return wildcard_host_matches(pattern, *host);
                });
            if (allowed) {
                return std::nullopt;
            }
        }

        if (!spec_.hotlink.redirect_location.empty()) {
            return PolicyDecision{
                302, {}, spec_.hotlink.redirect_location};
        }
        return PolicyDecision{403, "Hotlink protection denied the request", {}, 0};
    }

    SitePolicySpec spec_;
    RateLimiter rate_limiter_;
    std::vector<CompiledAclRule> pre_rate_limit_acl_rules_;
    std::vector<CompiledAclRule> acl_rules_;
    std::vector<CompiledRedirect> redirects_;
    std::unordered_set<std::string> hotlink_extensions_;
    std::unordered_set<std::string> hotlink_hosts_;
};

RequestPolicy::RequestPolicy(SitePolicySpec spec, std::vector<std::string> site_domains)
    : impl_(std::make_unique<Impl>(std::move(spec), std::move(site_domains))) {}

RequestPolicy::~RequestPolicy() = default;
RequestPolicy::RequestPolicy(RequestPolicy&&) noexcept = default;
RequestPolicy& RequestPolicy::operator=(RequestPolicy&&) noexcept = default;

std::optional<PolicyDecision> RequestPolicy::evaluate(
    const RequestView& request,
    std::string_view client_ip,
    std::string_view normalized_host,
    std::string_view scheme) {
    return impl_->evaluate(request, client_ip, normalized_host, scheme);
}

} // namespace webserver::policy
