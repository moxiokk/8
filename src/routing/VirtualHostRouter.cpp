#include "routing/VirtualHostRouter.hpp"

#include "routing/HostNormalizer.hpp"

#include <boost/asio/ip/address.hpp>

#include <algorithm>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace webserver::routing {

VirtualHost::VirtualHost(
    std::string name,
    BackendConfig backend,
    std::shared_ptr<policy::RequestPolicy> request_policy,
    BackendOverloadConfig overload,
    std::shared_ptr<const policy::UrlAuthenticator> url_authenticator)
    : name_(std::move(name)),
      backend_(std::move(backend)),
      request_policy_(std::move(request_policy)),
      overload_(std::move(overload)),
      url_authenticator_(std::move(url_authenticator)) {}

const std::string& VirtualHost::name() const noexcept {
    return name_;
}

const BackendConfig& VirtualHost::backend() const noexcept {
    return backend_;
}

const std::shared_ptr<policy::RequestPolicy>& VirtualHost::request_policy() const noexcept {
    return request_policy_;
}

const BackendOverloadConfig& VirtualHost::overload() const noexcept {
    return overload_;
}

const std::shared_ptr<const policy::UrlAuthenticator>& VirtualHost::url_authenticator()
    const noexcept {
    return url_authenticator_;
}

VirtualHostRouter::VirtualHostRouter(std::vector<VirtualHostConfig> configs) {
    std::unordered_set<std::string> wildcard_suffixes;

    for (auto& config : configs) {
        if (config.name.empty()) {
            throw std::invalid_argument{"virtual host name cannot be empty"};
        }
        if (config.domains.empty()) {
            throw std::invalid_argument{"virtual host must bind at least one domain"};
        }

        if (config.backend.port == 0) {
            throw std::invalid_argument{"backend port cannot be zero"};
        }
        if (config.backend.connect_timeout_seconds == 0 ||
            config.backend.connect_timeout_seconds > 86400 ||
            config.backend.response_timeout_seconds == 0 ||
            config.backend.response_timeout_seconds > 86400) {
            throw std::invalid_argument{"backend timeouts must be between 1 and 86400 seconds"};
        }
        if (config.overload.maximum_active_connections == 0 ||
            config.overload.maximum_active_connections > 100000) {
            throw std::invalid_argument{"backend maximum active connections must be between 1 and 100000"};
        }
        if (config.overload.maximum_queue > 1000000) {
            throw std::invalid_argument{"backend maximum queue cannot exceed 1000000"};
        }
        if (config.overload.queue_timeout_seconds == 0 ||
            config.overload.queue_timeout_seconds > 86400) {
            throw std::invalid_argument{"backend queue timeout must be between 1 and 86400 seconds"};
        }

        boost::system::error_code address_error;
        static_cast<void>(boost::asio::ip::make_address(config.backend.address, address_error));
        if (address_error && !HostNormalizer::normalize_domain(config.backend.address)) {
            throw std::invalid_argument{"invalid backend address: " + config.backend.address};
        }
        if (!config.backend.host.empty() &&
            !HostNormalizer::normalize_authority(config.backend.host)) {
            throw std::invalid_argument{"invalid backend Host: " + config.backend.host};
        }
        if (!config.backend.tls_sni.empty() &&
            !HostNormalizer::normalize_domain(config.backend.tls_sni)) {
            throw std::invalid_argument{"invalid backend TLS SNI: " + config.backend.tls_sni};
        }
        if (config.backend.protocol == BackendProtocol::http &&
            !config.backend.tls_sni.empty()) {
            throw std::invalid_argument{"backend TLS SNI requires HTTPS protocol"};
        }

        auto request_policy = std::make_shared<policy::RequestPolicy>(
            std::move(config.policy), config.domains);
        auto url_authenticator = std::make_shared<const policy::UrlAuthenticator>(
            std::move(config.url_auth));
        const auto host = std::make_shared<const VirtualHost>(
            std::move(config.name),
            std::move(config.backend),
            std::move(request_policy),
            std::move(config.overload),
            std::move(url_authenticator));

        for (const auto& domain_pattern : config.domains) {
            const bool wildcard = domain_pattern.starts_with("*.");
            const auto domain = HostNormalizer::normalize_domain(
                wildcard ? std::string_view{domain_pattern}.substr(2) : domain_pattern);
            if (!domain) {
                throw std::invalid_argument{"invalid virtual host domain: " + domain_pattern};
            }

            if (wildcard) {
                if (domain->find('.') == std::string::npos) {
                    throw std::invalid_argument{"wildcard domain is too broad: " + domain_pattern};
                }
                if (!wildcard_suffixes.emplace(*domain).second) {
                    throw std::invalid_argument{"duplicate virtual host domain: " + domain_pattern};
                }
                wildcard_hosts_.emplace_back(*domain, host);
                continue;
            }

            if (!exact_hosts_.emplace(*domain, host).second) {
                throw std::invalid_argument{"duplicate virtual host domain: " + domain_pattern};
            }
        }
    }

    std::sort(
        wildcard_hosts_.begin(), wildcard_hosts_.end(), [](const auto& left, const auto& right) {
            return left.first.size() > right.first.size();
        });
}

std::shared_ptr<const VirtualHost> VirtualHostRouter::find(
    std::string_view normalized_host) const {
    const auto exact = exact_hosts_.find(std::string{normalized_host});
    if (exact != exact_hosts_.end()) {
        return exact->second;
    }

    for (const auto& [suffix, host] : wildcard_hosts_) {
        if (normalized_host.size() > suffix.size() &&
            normalized_host.ends_with(suffix) &&
            normalized_host[normalized_host.size() - suffix.size() - 1] == '.') {
            return host;
        }
    }
    return {};
}

std::size_t VirtualHostRouter::exact_host_count() const noexcept {
    return exact_hosts_.size();
}

std::size_t VirtualHostRouter::wildcard_host_count() const noexcept {
    return wildcard_hosts_.size();
}

std::vector<VirtualHostConfig> default_virtual_hosts() {
    return {
        VirtualHostConfig{
            "example.com",
            {"example.com", "www.example.com"},
            BackendConfig{"127.0.0.1", 8090}},
    };
}

} // namespace webserver::routing
