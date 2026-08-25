#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace webserver::database {

class Database;

struct SiteRecord final {
    std::int64_t id{};
    std::string name;
    bool enabled{true};
    std::vector<std::string> domains;
    std::string backend_address;
    std::uint16_t backend_port{};
    std::string backend_protocol{"http"};
    std::string backend_host;
    std::string backend_tls_sni;
    bool backend_tls_verify_certificate{true};
    std::uint32_t backend_connect_timeout_seconds{5};
    std::uint32_t backend_response_timeout_seconds{60};
    bool backend_keep_alive{true};
    std::string url_auth_json{
        R"({"enabled":false,"scope":"all","primary_key":"","backup_key":"","validity_seconds":1800,"protected_uris":[]})"};
    bool http_enabled{true};
    std::uint16_t http_port{80};
    bool https_enabled{false};
    std::uint16_t https_port{443};
    bool force_https{false};
    std::string acl_rules_json{"[]"};
    bool rate_limit_enabled{false};
    std::uint32_t rate_limit_window_seconds{10};
    std::uint32_t rate_limit_max_requests{100};
    std::uint32_t rate_limit_ban_seconds{60};
    bool hotlink_enabled{false};
    std::string hotlink_extensions_json{"[\"jpg\",\"jpeg\",\"png\",\"gif\",\"webp\",\"mp4\",\"zip\"]"};
    std::string hotlink_allowed_hosts_json{"[]"};
    bool hotlink_allow_empty_referer{true};
    std::string hotlink_redirect_location;
    std::string redirect_rules_json{"[]"};
    std::uint32_t backend_max_active_connections{200};
    std::uint32_t backend_max_queue{1000};
    std::uint32_t backend_queue_timeout_seconds{5};
};

struct CertificateRecord final {
    std::int64_t id{};
    std::string name;
    bool enabled{true};
    bool is_default{false};
    std::vector<std::string> domains;
    std::string certificate_pem;
    std::string private_key_pem;
};

struct RuntimeSettingsRecord final {
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

struct AdminUserRecord final {
    std::int64_t id{};
    std::string username;
    std::vector<unsigned char> password_salt;
    std::vector<unsigned char> password_hash;
    int password_iterations{};
};

class ConfigRepository final {
public:
    explicit ConfigRepository(Database& database);

    void migrate();
    void seed_default_site();

    [[nodiscard]] std::vector<SiteRecord> list_sites() const;
    [[nodiscard]] std::int64_t next_site_id() const;
    [[nodiscard]] std::int64_t create_site(const SiteRecord& site);
    void update_site(const SiteRecord& site);
    void delete_site(std::int64_t id);

    [[nodiscard]] std::vector<CertificateRecord> list_certificates() const;
    [[nodiscard]] CertificateRecord find_certificate(std::int64_t id) const;
    [[nodiscard]] std::int64_t create_certificate(const CertificateRecord& certificate);
    void update_certificate(const CertificateRecord& certificate);
    void delete_certificate(std::int64_t id);
    [[nodiscard]] std::size_t certificate_count() const;

    [[nodiscard]] RuntimeSettingsRecord runtime_settings() const;
    void update_runtime_settings(const RuntimeSettingsRecord& settings);
    [[nodiscard]] std::uint64_t config_revision() const;
    void replace_configuration(
        const std::vector<SiteRecord>& sites,
        const std::vector<CertificateRecord>& certificates,
        const RuntimeSettingsRecord& settings);

    [[nodiscard]] std::size_t admin_user_count() const;
    [[nodiscard]] AdminUserRecord find_admin_user(const std::string& username) const;
    void create_admin_user(const AdminUserRecord& user);

private:
    Database& database_;
};

} // namespace webserver::database
