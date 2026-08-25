#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace webserver::policy {

enum class UrlAuthScope {
    all,
    specified,
};

enum class UrlAuthMatch {
    exact,
    prefix,
};

struct UrlAuthUriSpec final {
    std::string path{"/"};
    UrlAuthMatch match{UrlAuthMatch::exact};
};

struct UrlAuthSpec final {
    bool enabled{false};
    UrlAuthScope scope{UrlAuthScope::all};
    std::string primary_key;
    std::string backup_key;
    std::uint32_t validity_seconds{1800};
    std::vector<UrlAuthUriSpec> protected_uris;
};

struct UrlAuthResult final {
    bool allowed{true};
    bool authentication_applied{false};
    std::string rewritten_target;
};

class UrlAuthenticator final {
public:
    explicit UrlAuthenticator(UrlAuthSpec spec);

    [[nodiscard]] UrlAuthResult authenticate(std::string_view target) const;
    [[nodiscard]] UrlAuthResult authenticate(
        std::string_view target,
        std::int64_t now_unix_seconds) const;

private:
    [[nodiscard]] bool protects(std::string_view path) const noexcept;

    UrlAuthSpec spec_;
};

} // namespace webserver::policy
