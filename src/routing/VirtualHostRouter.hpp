#pragma once

#include "policy/RequestPolicy.hpp"
#include "policy/UrlAuthenticator.hpp"

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace webserver::routing {

enum class BackendProtocol {
    http,
    https,
};

struct BackendConfig final {
    std::string address;
    std::uint16_t port{};
    BackendProtocol protocol{BackendProtocol::http};
    std::string host;
    std::string tls_sni;
    bool tls_verify_certificate{true};
    std::uint32_t connect_timeout_seconds{5};
    std::uint32_t response_timeout_seconds{60};
    bool keep_alive{true};
};

struct BackendOverloadConfig final {
    std::int64_t site_id{};
    std::string site_name;
    std::uint32_t maximum_active_connections{200};
    std::uint32_t maximum_queue{1000};
    std::uint32_t queue_timeout_seconds{5};
};

struct VirtualHostConfig final {
    VirtualHostConfig() = default;
    VirtualHostConfig(
        std::string site_name,
        std::vector<std::string> site_domains,
        BackendConfig site_backend,
        policy::SitePolicySpec site_policy = {},
        BackendOverloadConfig site_overload = {},
        policy::UrlAuthSpec site_url_auth = {})
        : name(std::move(site_name)),
          domains(std::move(site_domains)),
          backend(std::move(site_backend)),
          policy(std::move(site_policy)),
          overload(std::move(site_overload)),
          url_auth(std::move(site_url_auth)) {}

    std::string name;
    std::vector<std::string> domains;
    BackendConfig backend;
    policy::SitePolicySpec policy;
    BackendOverloadConfig overload;
    policy::UrlAuthSpec url_auth;
};

class VirtualHost final {
public:
    VirtualHost(
        std::string name,
        BackendConfig backend,
        std::shared_ptr<policy::RequestPolicy> request_policy,
        BackendOverloadConfig overload,
        std::shared_ptr<const policy::UrlAuthenticator> url_authenticator);

    [[nodiscard]] const std::string& name() const noexcept;
    [[nodiscard]] const BackendConfig& backend() const noexcept;
    [[nodiscard]] const std::shared_ptr<policy::RequestPolicy>& request_policy() const noexcept;
    [[nodiscard]] const BackendOverloadConfig& overload() const noexcept;
    [[nodiscard]] const std::shared_ptr<const policy::UrlAuthenticator>& url_authenticator()
        const noexcept;

private:
    std::string name_;
    BackendConfig backend_;
    std::shared_ptr<policy::RequestPolicy> request_policy_;
    BackendOverloadConfig overload_;
    std::shared_ptr<const policy::UrlAuthenticator> url_authenticator_;
};

class VirtualHostRouter final {
public:
    explicit VirtualHostRouter(std::vector<VirtualHostConfig> configs);

    [[nodiscard]] std::shared_ptr<const VirtualHost> find(
        std::string_view normalized_host) const;

    [[nodiscard]] std::size_t exact_host_count() const noexcept;
    [[nodiscard]] std::size_t wildcard_host_count() const noexcept;

private:
    using HostPtr = std::shared_ptr<const VirtualHost>;

    std::unordered_map<std::string, HostPtr> exact_hosts_;
    std::vector<std::pair<std::string, HostPtr>> wildcard_hosts_;
};

[[nodiscard]] std::vector<VirtualHostConfig> default_virtual_hosts();

} // namespace webserver::routing
