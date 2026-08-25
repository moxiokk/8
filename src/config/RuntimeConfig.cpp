#include "config/RuntimeConfig.hpp"

#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>

namespace webserver::config {
namespace {

using RoutesByPort =
    std::unordered_map<std::uint16_t, std::vector<routing::VirtualHostConfig>>;

std::vector<std::uint16_t> sorted_ports(const RoutesByPort& routes) {
    std::vector<std::uint16_t> ports;
    ports.reserve(routes.size());
    for (const auto& entry : routes) {
        ports.push_back(entry.first);
    }
    std::sort(ports.begin(), ports.end());
    return ports;
}

void build_routers(
    RoutesByPort routes,
    std::unordered_map<std::uint16_t, std::shared_ptr<const routing::VirtualHostRouter>>& output) {
    output.reserve(routes.size());
    for (auto& [port, hosts] : routes) {
        output.emplace(
            port,
            std::make_shared<const routing::VirtualHostRouter>(std::move(hosts)));
    }
}

} // namespace

RuntimeConfig::RuntimeConfig(RuntimeConfigSpec spec)
    : revision_(spec.revision),
      settings_(spec.settings),
      client_ip_resolver_(
          settings_.trusted_proxy_cidrs,
          settings_.real_ip_headers) {
    if (revision_ == 0) {
        throw std::invalid_argument{"runtime configuration revision cannot be zero"};
    }
    if (settings_.max_upload_bytes == 0 || settings_.max_upload_bytes > 16ULL * 1024 * 1024 * 1024) {
        throw std::invalid_argument{"maximum upload size must be between 1 byte and 16 GiB"};
    }
    if (settings_.backend_pool_size > 1024) {
        throw std::invalid_argument{"backend connection pool size cannot exceed 1024"};
    }
    const auto valid_timeout = [](std::uint32_t value) { return value >= 1 && value <= 86400; };
    if (!valid_timeout(settings_.client_header_timeout_seconds) ||
        !valid_timeout(settings_.client_body_timeout_seconds) ||
        !valid_timeout(settings_.client_write_timeout_seconds) ||
        !valid_timeout(settings_.backend_connect_timeout_seconds) ||
        !valid_timeout(settings_.backend_response_timeout_seconds) ||
        !valid_timeout(settings_.backend_idle_timeout_seconds) ||
        !valid_timeout(settings_.backend_idle_connection_ttl_seconds)) {
        throw std::invalid_argument{"timeouts must be between 1 and 86400 seconds"};
    }

    RoutesByPort http_routes;
    RoutesByPort https_routes;
    for (const auto& site : spec.sites) {
        if (!site.http_enabled && !site.https_enabled) {
            throw std::invalid_argument{
                "runtime site must enable at least one listener: " + site.virtual_host.name};
        }
        if (site.http_enabled) {
            http_routes[site.http_port].push_back(site.virtual_host);
        }
        if (site.https_enabled) {
            https_routes[site.https_port].push_back(site.virtual_host);
        }
    }

    for (const auto& [port, ignored] : http_routes) {
        static_cast<void>(ignored);
        if (port != 0 && https_routes.contains(port)) {
            throw std::invalid_argument{
                "HTTP and HTTPS cannot share listener port " + std::to_string(port)};
        }
    }

    http_ports_ = sorted_ports(http_routes);
    https_ports_ = sorted_ports(https_routes);
    for (const auto& [port, sites] : http_routes) http_site_counts_[port] = sites.size();
    for (const auto& [port, sites] : https_routes) https_site_counts_[port] = sites.size();
    build_routers(std::move(http_routes), http_routers_);
    build_routers(std::move(https_routes), https_routers_);

    if (!https_ports_.empty()) {
        tls_contexts_ = std::make_shared<tls::TlsContextManager>(
            std::move(spec.tls_certificates), spec.reject_unknown_sni);
        for (const auto& site : spec.sites) {
            if (!site.https_enabled) {
                continue;
            }
            for (const auto& domain : site.virtual_host.domains) {
                if (!tls_contexts_->can_serve_domain(domain)) {
                    throw std::invalid_argument{
                        "no TLS certificate covers HTTPS domain " + domain};
                }
            }
        }
    }
}

std::size_t RuntimeConfig::site_count(
    ListenerProtocol protocol,
    std::uint16_t port) const noexcept {
    const auto& counts = protocol == ListenerProtocol::https
                             ? https_site_counts_
                             : http_site_counts_;
    const auto found = counts.find(port);
    return found == counts.end() ? 0 : found->second;
}

std::uint64_t RuntimeConfig::revision() const noexcept {
    return revision_;
}

const std::vector<std::uint16_t>& RuntimeConfig::http_ports() const noexcept {
    return http_ports_;
}

const std::vector<std::uint16_t>& RuntimeConfig::https_ports() const noexcept {
    return https_ports_;
}

std::shared_ptr<const routing::VirtualHostRouter> RuntimeConfig::router(
    ListenerProtocol protocol,
    std::uint16_t port) const {
    const auto& routers = protocol == ListenerProtocol::https ? https_routers_ : http_routers_;
    const auto found = routers.find(port);
    return found == routers.end() ? nullptr : found->second;
}

std::shared_ptr<tls::TlsContextManager> RuntimeConfig::tls_contexts() const noexcept {
    return tls_contexts_;
}

const network::ClientIpResolver& RuntimeConfig::client_ip_resolver() const noexcept {
    return client_ip_resolver_;
}

const RuntimeSettings& RuntimeConfig::settings() const noexcept {
    return settings_;
}

RuntimeConfigStore::RuntimeConfigStore(std::shared_ptr<const RuntimeConfig> initial)
    : current_(std::move(initial)) {
    if (!current_.load(std::memory_order_relaxed)) {
        throw std::invalid_argument{"initial runtime configuration cannot be null"};
    }
}

std::shared_ptr<const RuntimeConfig> RuntimeConfigStore::load() const noexcept {
    return current_.load(std::memory_order_acquire);
}

void RuntimeConfigStore::publish(std::shared_ptr<const RuntimeConfig> next) noexcept {
    if (!next) return;
    current_.store(std::move(next), std::memory_order_release);
}

std::shared_ptr<const RuntimeConfig> build_runtime_config(RuntimeConfigSpec spec) {
    return std::make_shared<const RuntimeConfig>(std::move(spec));
}

} // namespace webserver::config
