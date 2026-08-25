#pragma once

#include "routing/VirtualHostRouter.hpp"
#include "tls/TlsContextManager.hpp"
#include "network/ClientIpResolver.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace webserver::config {

enum class ListenerProtocol {
    http,
    https,
};

struct RuntimeSiteConfig final {
    routing::VirtualHostConfig virtual_host;
    bool http_enabled{true};
    std::uint16_t http_port{80};
    bool https_enabled{false};
    std::uint16_t https_port{443};
};

struct RuntimeSettings final {
    std::vector<std::string> trusted_proxy_cidrs;
    std::vector<std::string> real_ip_headers{
        "EO-Connecting-IP", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For"};
    std::uint64_t max_upload_bytes{64ULL * 1024ULL * 1024ULL};
    bool backend_keep_alive{true};
    std::uint32_t backend_pool_size{32};
    std::uint32_t client_header_timeout_seconds{15};
    std::uint32_t client_body_timeout_seconds{120};
    std::uint32_t client_write_timeout_seconds{60};
    std::uint32_t backend_connect_timeout_seconds{5};
    std::uint32_t backend_response_timeout_seconds{60};
    std::uint32_t backend_idle_timeout_seconds{60};
    std::uint32_t backend_idle_connection_ttl_seconds{60};
};

struct RuntimeConfigSpec final {
    std::uint64_t revision{1};
    std::vector<RuntimeSiteConfig> sites;
    std::vector<tls::TlsCertificateConfig> tls_certificates;
    bool reject_unknown_sni{true};
    RuntimeSettings settings;
};

class RuntimeConfig final {
public:
    explicit RuntimeConfig(RuntimeConfigSpec spec);

    [[nodiscard]] std::uint64_t revision() const noexcept;
    [[nodiscard]] const std::vector<std::uint16_t>& http_ports() const noexcept;
    [[nodiscard]] const std::vector<std::uint16_t>& https_ports() const noexcept;
    [[nodiscard]] std::shared_ptr<const routing::VirtualHostRouter> router(
        ListenerProtocol protocol,
        std::uint16_t port) const;
    [[nodiscard]] std::size_t site_count(
        ListenerProtocol protocol,
        std::uint16_t port) const noexcept;
    [[nodiscard]] std::shared_ptr<tls::TlsContextManager> tls_contexts() const noexcept;
    [[nodiscard]] const network::ClientIpResolver& client_ip_resolver() const noexcept;
    [[nodiscard]] const RuntimeSettings& settings() const noexcept;

private:
    using RouterPtr = std::shared_ptr<const routing::VirtualHostRouter>;

    std::uint64_t revision_{};
    std::vector<std::uint16_t> http_ports_;
    std::vector<std::uint16_t> https_ports_;
    std::unordered_map<std::uint16_t, RouterPtr> http_routers_;
    std::unordered_map<std::uint16_t, RouterPtr> https_routers_;
    std::unordered_map<std::uint16_t, std::size_t> http_site_counts_;
    std::unordered_map<std::uint16_t, std::size_t> https_site_counts_;
    std::shared_ptr<tls::TlsContextManager> tls_contexts_;
    RuntimeSettings settings_;
    network::ClientIpResolver client_ip_resolver_;
};

class RuntimeConfigStore final {
public:
    explicit RuntimeConfigStore(std::shared_ptr<const RuntimeConfig> initial);

    [[nodiscard]] std::shared_ptr<const RuntimeConfig> load() const noexcept;
    void publish(std::shared_ptr<const RuntimeConfig> next) noexcept;

private:
    std::atomic<std::shared_ptr<const RuntimeConfig>> current_;
};

[[nodiscard]] std::shared_ptr<const RuntimeConfig> build_runtime_config(
    RuntimeConfigSpec spec);

} // namespace webserver::config
