#include "database/ConfigRepository.hpp"

#include "database/Database.hpp"

#include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace webserver::database {
namespace {

class Statement final {
public:
    Statement(sqlite3* database, std::string_view sql) : database_(database) {
        if (sqlite3_prepare_v2(database, sql.data(), static_cast<int>(sql.size()), &value_, nullptr) !=
            SQLITE_OK) {
            throw std::runtime_error{"cannot prepare SQLite statement: " +
                                     std::string{sqlite3_errmsg(database)}};
        }
    }

    ~Statement() {
        sqlite3_finalize(value_);
    }

    Statement(const Statement&) = delete;
    Statement& operator=(const Statement&) = delete;

    [[nodiscard]] sqlite3_stmt* get() const noexcept { return value_; }

private:
    sqlite3* database_;
    sqlite3_stmt* value_{nullptr};
};

void bind_text(sqlite3_stmt* statement, int index, const std::string& value) {
    if (sqlite3_bind_text(
            statement, index, value.c_str(), static_cast<int>(value.size()), SQLITE_TRANSIENT) !=
        SQLITE_OK) {
        throw std::runtime_error{"cannot bind SQLite text value"};
    }
}

void bind_blob(sqlite3_stmt* statement, int index, const std::vector<unsigned char>& value) {
    if (sqlite3_bind_blob(
            statement,
            index,
            value.data(),
            static_cast<int>(value.size()),
            SQLITE_TRANSIENT) != SQLITE_OK) {
        throw std::runtime_error{"cannot bind SQLite blob value"};
    }
}

void expect_done(sqlite3* database, sqlite3_stmt* statement, std::string_view operation) {
    if (sqlite3_step(statement) != SQLITE_DONE) {
        throw std::runtime_error{std::string{operation} + ": " + sqlite3_errmsg(database)};
    }
}

std::string column_text(sqlite3_stmt* statement, int column) {
    const auto* value = sqlite3_column_text(statement, column);
    const auto bytes = sqlite3_column_bytes(statement, column);
    return value ? std::string{reinterpret_cast<const char*>(value), static_cast<std::size_t>(bytes)}
                 : std::string{};
}

std::vector<unsigned char> column_blob(sqlite3_stmt* statement, int column) {
    const auto* value = static_cast<const unsigned char*>(sqlite3_column_blob(statement, column));
    const auto bytes = sqlite3_column_bytes(statement, column);
    return value ? std::vector<unsigned char>{value, value + bytes} : std::vector<unsigned char>{};
}

class Transaction final {
public:
    explicit Transaction(Database& database) : database_(database) {
        database_.execute("BEGIN IMMEDIATE;");
    }

    ~Transaction() {
        if (!committed_) {
            try {
                database_.execute("ROLLBACK;");
            } catch (...) {
            }
        }
    }

    void commit() {
        database_.execute("COMMIT;");
        committed_ = true;
    }

private:
    Database& database_;
    bool committed_{false};
};

void insert_domains(sqlite3* database, std::int64_t site_id, const std::vector<std::string>& domains) {
    Statement statement{database, "INSERT INTO site_domains(site_id, hostname) VALUES(?, ?);"};
    for (const auto& domain : domains) {
        sqlite3_reset(statement.get());
        sqlite3_clear_bindings(statement.get());
        sqlite3_bind_int64(statement.get(), 1, site_id);
        bind_text(statement.get(), 2, domain);
        expect_done(database, statement.get(), "cannot insert site domain");
    }
}

void increment_revision(sqlite3* database) {
    Statement statement{
        database,
        "UPDATE runtime_metadata SET value = CAST(value AS INTEGER) + 1 WHERE key = 'config_revision';"};
    expect_done(database, statement.get(), "cannot increment configuration revision");
}

bool migration_exists(sqlite3* database, int version) {
    Statement statement{
        database, "SELECT 1 FROM schema_migrations WHERE version = ?;"};
    sqlite3_bind_int(statement.get(), 1, version);
    return sqlite3_step(statement.get()) == SQLITE_ROW;
}

} // namespace

ConfigRepository::ConfigRepository(Database& database) : database_(database) {}

void ConfigRepository::migrate() {
    {
        Transaction transaction{database_};
        database_.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations("
            "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
            "CREATE TABLE IF NOT EXISTS sites("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "name TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,"
            "backend_address TEXT NOT NULL, backend_port INTEGER NOT NULL,"
            "http_enabled INTEGER NOT NULL DEFAULT 1, http_port INTEGER NOT NULL DEFAULT 80,"
            "https_enabled INTEGER NOT NULL DEFAULT 0, https_port INTEGER NOT NULL DEFAULT 443,"
            "force_https INTEGER NOT NULL DEFAULT 0,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
            "CREATE TABLE IF NOT EXISTS site_domains("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, site_id INTEGER NOT NULL, hostname TEXT NOT NULL UNIQUE,"
            "FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE);"
            "CREATE TABLE IF NOT EXISTS admin_users("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
            "password_salt BLOB NOT NULL, password_hash BLOB NOT NULL, password_iterations INTEGER NOT NULL,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
            "CREATE TABLE IF NOT EXISTS runtime_metadata(key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "INSERT OR IGNORE INTO runtime_metadata(key, value) VALUES('config_revision', '1');"
            "INSERT OR IGNORE INTO runtime_metadata(key, value) VALUES('default_site_seeded', '0');"
            "INSERT OR IGNORE INTO schema_migrations(version) VALUES(1);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 2)) {
        Transaction transaction{database_};
        database_.execute(
            "ALTER TABLE sites ADD COLUMN acl_rules_json TEXT NOT NULL DEFAULT '[]';"
            "ALTER TABLE sites ADD COLUMN rate_limit_enabled INTEGER NOT NULL DEFAULT 0;"
            "ALTER TABLE sites ADD COLUMN rate_limit_window_seconds INTEGER NOT NULL DEFAULT 10;"
            "ALTER TABLE sites ADD COLUMN rate_limit_max_requests INTEGER NOT NULL DEFAULT 100;"
            "ALTER TABLE sites ADD COLUMN rate_limit_ban_seconds INTEGER NOT NULL DEFAULT 60;"
            "ALTER TABLE sites ADD COLUMN hotlink_enabled INTEGER NOT NULL DEFAULT 0;"
            "ALTER TABLE sites ADD COLUMN hotlink_extensions_json TEXT NOT NULL "
            "DEFAULT '[\"jpg\",\"jpeg\",\"png\",\"gif\",\"webp\",\"mp4\",\"zip\"]';"
            "ALTER TABLE sites ADD COLUMN hotlink_allowed_hosts_json TEXT NOT NULL DEFAULT '[]';"
            "ALTER TABLE sites ADD COLUMN hotlink_allow_empty_referer INTEGER NOT NULL DEFAULT 1;"
            "ALTER TABLE sites ADD COLUMN hotlink_redirect_location TEXT NOT NULL DEFAULT '';"
            "ALTER TABLE sites ADD COLUMN redirect_rules_json TEXT NOT NULL DEFAULT '[]';"
            "INSERT INTO schema_migrations(version) VALUES(2);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 3)) {
        Transaction transaction{database_};
        database_.execute(
            "CREATE TABLE tls_certificates("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,"
            "enabled INTEGER NOT NULL DEFAULT 1, is_default INTEGER NOT NULL DEFAULT 0,"
            "domains_json TEXT NOT NULL, certificate_pem TEXT NOT NULL, private_key_pem TEXT NOT NULL,"
            "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,"
            "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
            "CREATE UNIQUE INDEX one_default_tls_certificate "
            "ON tls_certificates(is_default) WHERE is_default = 1;"
            "CREATE TABLE runtime_settings("
            "id INTEGER PRIMARY KEY CHECK(id = 1), trusted_proxy_cidrs_json TEXT NOT NULL DEFAULT '[]',"
            "trust_cf_connecting_ip INTEGER NOT NULL DEFAULT 1,"
            "trust_x_forwarded_for INTEGER NOT NULL DEFAULT 1,"
            "max_upload_bytes INTEGER NOT NULL DEFAULT 67108864,"
            "backend_keep_alive INTEGER NOT NULL DEFAULT 1,"
            "backend_pool_size INTEGER NOT NULL DEFAULT 32);"
            "INSERT INTO runtime_settings(id) VALUES(1);"
            "INSERT INTO schema_migrations(version) VALUES(3);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 4)) {
        Transaction transaction{database_};
        database_.execute(
            "ALTER TABLE runtime_settings ADD COLUMN real_ip_headers_json TEXT NOT NULL "
            "DEFAULT '[\"EO-Connecting-IP\",\"CF-Connecting-IP\",\"True-Client-IP\",\"X-Forwarded-For\"]';"
            "ALTER TABLE runtime_settings ADD COLUMN client_header_timeout_seconds INTEGER NOT NULL DEFAULT 15;"
            "ALTER TABLE runtime_settings ADD COLUMN client_body_timeout_seconds INTEGER NOT NULL DEFAULT 120;"
            "ALTER TABLE runtime_settings ADD COLUMN client_write_timeout_seconds INTEGER NOT NULL DEFAULT 60;"
            "ALTER TABLE runtime_settings ADD COLUMN backend_connect_timeout_seconds INTEGER NOT NULL DEFAULT 5;"
            "ALTER TABLE runtime_settings ADD COLUMN backend_response_timeout_seconds INTEGER NOT NULL DEFAULT 60;"
            "ALTER TABLE runtime_settings ADD COLUMN backend_idle_timeout_seconds INTEGER NOT NULL DEFAULT 60;"
            "ALTER TABLE runtime_settings ADD COLUMN backend_idle_connection_ttl_seconds INTEGER NOT NULL DEFAULT 60;"
            "INSERT INTO schema_migrations(version) VALUES(4);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 5)) {
        Transaction transaction{database_};
        database_.execute(
            "ALTER TABLE sites ADD COLUMN backend_max_active_connections INTEGER NOT NULL DEFAULT 200;"
            "ALTER TABLE sites ADD COLUMN backend_max_queue INTEGER NOT NULL DEFAULT 1000;"
            "ALTER TABLE sites ADD COLUMN backend_queue_timeout_seconds INTEGER NOT NULL DEFAULT 5;"
            "INSERT INTO schema_migrations(version) VALUES(5);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 6)) {
        Transaction transaction{database_};
        database_.execute(
            "ALTER TABLE sites ADD COLUMN backend_protocol TEXT NOT NULL DEFAULT 'http';"
            "ALTER TABLE sites ADD COLUMN backend_host TEXT NOT NULL DEFAULT '';"
            "ALTER TABLE sites ADD COLUMN backend_tls_sni TEXT NOT NULL DEFAULT '';"
            "ALTER TABLE sites ADD COLUMN backend_tls_verify_certificate INTEGER NOT NULL DEFAULT 1;"
            "ALTER TABLE sites ADD COLUMN backend_connect_timeout_seconds INTEGER NOT NULL DEFAULT 5;"
            "ALTER TABLE sites ADD COLUMN backend_response_timeout_seconds INTEGER NOT NULL DEFAULT 60;"
            "ALTER TABLE sites ADD COLUMN backend_keep_alive INTEGER NOT NULL DEFAULT 1;"
            "UPDATE sites SET "
            "backend_connect_timeout_seconds = (SELECT backend_connect_timeout_seconds FROM runtime_settings WHERE id = 1), "
            "backend_response_timeout_seconds = (SELECT backend_response_timeout_seconds FROM runtime_settings WHERE id = 1), "
            "backend_keep_alive = (SELECT backend_keep_alive FROM runtime_settings WHERE id = 1);"
            "INSERT INTO schema_migrations(version) VALUES(6);");
        transaction.commit();
    }

    if (!migration_exists(database_.handle(), 7)) {
        Transaction transaction{database_};
        database_.execute(
            "ALTER TABLE sites ADD COLUMN url_auth_json TEXT NOT NULL DEFAULT "
            "'{\"enabled\":false,\"scope\":\"all\",\"primary_key\":\"\",\"backup_key\":\"\","
            "\"validity_seconds\":1800,\"protected_uris\":[]}';"
            "INSERT INTO schema_migrations(version) VALUES(7);");
        transaction.commit();
    }
}

void ConfigRepository::seed_default_site() {
    {
        Statement seeded{
            database_.handle(),
            "SELECT value FROM runtime_metadata WHERE key = 'default_site_seeded';"};
        if (sqlite3_step(seeded.get()) != SQLITE_ROW) {
            throw std::runtime_error{"default site seed state is missing"};
        }
        if (column_text(seeded.get(), 0) == "1") {
            return;
        }
    }

    bool has_sites = false;
    {
        Statement count{database_.handle(), "SELECT COUNT(*) FROM sites;"};
        if (sqlite3_step(count.get()) != SQLITE_ROW) {
            throw std::runtime_error{"cannot count configured sites"};
        }
        has_sites = sqlite3_column_int64(count.get(), 0) != 0;
    }
    if (!has_sites) {
        SiteRecord site;
        site.name = "Example site";
        site.domains = {"example.com", "www.example.com"};
        site.backend_address = "127.0.0.1";
        site.backend_port = 8090;
        site.http_port = 80;
        site.https_enabled = true;
        site.https_port = 443;
        static_cast<void>(create_site(site));
    }

    Statement mark_seeded{
        database_.handle(),
        "UPDATE runtime_metadata SET value = '1' WHERE key = 'default_site_seeded';"};
    expect_done(database_.handle(), mark_seeded.get(), "cannot record default site seed state");
}

std::vector<SiteRecord> ConfigRepository::list_sites() const {
    std::vector<SiteRecord> sites;
    Statement sites_statement{
        database_.handle(),
        "SELECT id, name, enabled, backend_address, backend_port, http_enabled, http_port, "
        "https_enabled, https_port, force_https, acl_rules_json, rate_limit_enabled, "
        "rate_limit_window_seconds, rate_limit_max_requests, rate_limit_ban_seconds, "
        "hotlink_enabled, hotlink_extensions_json, hotlink_allowed_hosts_json, "
        "hotlink_allow_empty_referer, hotlink_redirect_location, redirect_rules_json, "
        "backend_max_active_connections, backend_max_queue, backend_queue_timeout_seconds, "
        "backend_protocol, backend_host, backend_tls_sni, backend_tls_verify_certificate, "
        "backend_connect_timeout_seconds, backend_response_timeout_seconds, backend_keep_alive, "
        "url_auth_json "
        "FROM sites ORDER BY id;"};
    int site_result = SQLITE_OK;
    while ((site_result = sqlite3_step(sites_statement.get())) == SQLITE_ROW) {
        SiteRecord site;
        site.id = sqlite3_column_int64(sites_statement.get(), 0);
        site.name = column_text(sites_statement.get(), 1);
        site.enabled = sqlite3_column_int(sites_statement.get(), 2) != 0;
        site.backend_address = column_text(sites_statement.get(), 3);
        site.backend_port = static_cast<std::uint16_t>(sqlite3_column_int(sites_statement.get(), 4));
        site.http_enabled = sqlite3_column_int(sites_statement.get(), 5) != 0;
        site.http_port = static_cast<std::uint16_t>(sqlite3_column_int(sites_statement.get(), 6));
        site.https_enabled = sqlite3_column_int(sites_statement.get(), 7) != 0;
        site.https_port = static_cast<std::uint16_t>(sqlite3_column_int(sites_statement.get(), 8));
        site.force_https = sqlite3_column_int(sites_statement.get(), 9) != 0;
        site.acl_rules_json = column_text(sites_statement.get(), 10);
        site.rate_limit_enabled = sqlite3_column_int(sites_statement.get(), 11) != 0;
        site.rate_limit_window_seconds = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 12));
        site.rate_limit_max_requests = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 13));
        site.rate_limit_ban_seconds = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 14));
        site.hotlink_enabled = sqlite3_column_int(sites_statement.get(), 15) != 0;
        site.hotlink_extensions_json = column_text(sites_statement.get(), 16);
        site.hotlink_allowed_hosts_json = column_text(sites_statement.get(), 17);
        site.hotlink_allow_empty_referer = sqlite3_column_int(sites_statement.get(), 18) != 0;
        site.hotlink_redirect_location = column_text(sites_statement.get(), 19);
        site.redirect_rules_json = column_text(sites_statement.get(), 20);
        site.backend_max_active_connections = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 21));
        site.backend_max_queue = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 22));
        site.backend_queue_timeout_seconds = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 23));
        site.backend_protocol = column_text(sites_statement.get(), 24);
        site.backend_host = column_text(sites_statement.get(), 25);
        site.backend_tls_sni = column_text(sites_statement.get(), 26);
        site.backend_tls_verify_certificate = sqlite3_column_int(sites_statement.get(), 27) != 0;
        site.backend_connect_timeout_seconds = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 28));
        site.backend_response_timeout_seconds = static_cast<std::uint32_t>(
            sqlite3_column_int64(sites_statement.get(), 29));
        site.backend_keep_alive = sqlite3_column_int(sites_statement.get(), 30) != 0;
        site.url_auth_json = column_text(sites_statement.get(), 31);

        Statement domains_statement{
            database_.handle(),
            "SELECT hostname FROM site_domains WHERE site_id = ? ORDER BY id;"};
        sqlite3_bind_int64(domains_statement.get(), 1, site.id);
        int domain_result = SQLITE_OK;
        while ((domain_result = sqlite3_step(domains_statement.get())) == SQLITE_ROW) {
            site.domains.push_back(column_text(domains_statement.get(), 0));
        }
        if (domain_result != SQLITE_DONE) {
            throw std::runtime_error{"cannot read site domains: " +
                                     std::string{sqlite3_errmsg(database_.handle())}};
        }
        sites.push_back(std::move(site));
    }
    if (site_result != SQLITE_DONE) {
        throw std::runtime_error{"cannot read sites: " +
                                 std::string{sqlite3_errmsg(database_.handle())}};
    }
    return sites;
}

std::int64_t ConfigRepository::next_site_id() const {
    Statement statement{
        database_.handle(),
        "SELECT COALESCE((SELECT seq + 1 FROM sqlite_sequence WHERE name = 'sites'), "
        "(SELECT COALESCE(MAX(id), 0) + 1 FROM sites));"};
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error{"cannot determine the next site id"};
    }
    return sqlite3_column_int64(statement.get(), 0);
}

std::int64_t ConfigRepository::create_site(const SiteRecord& site) {
    Transaction transaction{database_};
    Statement statement{
        database_.handle(),
        "INSERT INTO sites(name, enabled, backend_address, backend_port, http_enabled, http_port, "
        "https_enabled, https_port, force_https, acl_rules_json, rate_limit_enabled, "
        "rate_limit_window_seconds, rate_limit_max_requests, rate_limit_ban_seconds, "
        "hotlink_enabled, hotlink_extensions_json, hotlink_allowed_hosts_json, "
        "hotlink_allow_empty_referer, hotlink_redirect_location, redirect_rules_json, "
        "backend_max_active_connections, backend_max_queue, backend_queue_timeout_seconds, "
        "backend_protocol, backend_host, backend_tls_sni, backend_tls_verify_certificate, "
        "backend_connect_timeout_seconds, backend_response_timeout_seconds, backend_keep_alive, "
        "url_auth_json) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"};
    bind_text(statement.get(), 1, site.name);
    sqlite3_bind_int(statement.get(), 2, site.enabled ? 1 : 0);
    bind_text(statement.get(), 3, site.backend_address);
    sqlite3_bind_int(statement.get(), 4, site.backend_port);
    sqlite3_bind_int(statement.get(), 5, site.http_enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 6, site.http_port);
    sqlite3_bind_int(statement.get(), 7, site.https_enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 8, site.https_port);
    sqlite3_bind_int(statement.get(), 9, site.force_https ? 1 : 0);
    bind_text(statement.get(), 10, site.acl_rules_json);
    sqlite3_bind_int(statement.get(), 11, site.rate_limit_enabled ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 12, site.rate_limit_window_seconds);
    sqlite3_bind_int64(statement.get(), 13, site.rate_limit_max_requests);
    sqlite3_bind_int64(statement.get(), 14, site.rate_limit_ban_seconds);
    sqlite3_bind_int(statement.get(), 15, site.hotlink_enabled ? 1 : 0);
    bind_text(statement.get(), 16, site.hotlink_extensions_json);
    bind_text(statement.get(), 17, site.hotlink_allowed_hosts_json);
    sqlite3_bind_int(statement.get(), 18, site.hotlink_allow_empty_referer ? 1 : 0);
    bind_text(statement.get(), 19, site.hotlink_redirect_location);
    bind_text(statement.get(), 20, site.redirect_rules_json);
    sqlite3_bind_int64(statement.get(), 21, site.backend_max_active_connections);
    sqlite3_bind_int64(statement.get(), 22, site.backend_max_queue);
    sqlite3_bind_int64(statement.get(), 23, site.backend_queue_timeout_seconds);
    bind_text(statement.get(), 24, site.backend_protocol);
    bind_text(statement.get(), 25, site.backend_host);
    bind_text(statement.get(), 26, site.backend_tls_sni);
    sqlite3_bind_int(statement.get(), 27, site.backend_tls_verify_certificate ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 28, site.backend_connect_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 29, site.backend_response_timeout_seconds);
    sqlite3_bind_int(statement.get(), 30, site.backend_keep_alive ? 1 : 0);
    bind_text(statement.get(), 31, site.url_auth_json);
    expect_done(database_.handle(), statement.get(), "cannot create site");

    const auto id = sqlite3_last_insert_rowid(database_.handle());
    insert_domains(database_.handle(), id, site.domains);
    increment_revision(database_.handle());
    transaction.commit();
    return id;
}

void ConfigRepository::update_site(const SiteRecord& site) {
    Transaction transaction{database_};
    Statement statement{
        database_.handle(),
        "UPDATE sites SET name = ?, enabled = ?, backend_address = ?, backend_port = ?, "
        "http_enabled = ?, http_port = ?, https_enabled = ?, https_port = ?, force_https = ?, "
        "acl_rules_json = ?, rate_limit_enabled = ?, rate_limit_window_seconds = ?, "
        "rate_limit_max_requests = ?, rate_limit_ban_seconds = ?, hotlink_enabled = ?, "
        "hotlink_extensions_json = ?, hotlink_allowed_hosts_json = ?, "
        "hotlink_allow_empty_referer = ?, hotlink_redirect_location = ?, "
        "redirect_rules_json = ?, backend_max_active_connections = ?, backend_max_queue = ?, "
        "backend_queue_timeout_seconds = ?, backend_protocol = ?, backend_host = ?, "
        "backend_tls_sni = ?, backend_tls_verify_certificate = ?, "
        "backend_connect_timeout_seconds = ?, backend_response_timeout_seconds = ?, "
        "backend_keep_alive = ?, url_auth_json = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;"};
    bind_text(statement.get(), 1, site.name);
    sqlite3_bind_int(statement.get(), 2, site.enabled ? 1 : 0);
    bind_text(statement.get(), 3, site.backend_address);
    sqlite3_bind_int(statement.get(), 4, site.backend_port);
    sqlite3_bind_int(statement.get(), 5, site.http_enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 6, site.http_port);
    sqlite3_bind_int(statement.get(), 7, site.https_enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 8, site.https_port);
    sqlite3_bind_int(statement.get(), 9, site.force_https ? 1 : 0);
    bind_text(statement.get(), 10, site.acl_rules_json);
    sqlite3_bind_int(statement.get(), 11, site.rate_limit_enabled ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 12, site.rate_limit_window_seconds);
    sqlite3_bind_int64(statement.get(), 13, site.rate_limit_max_requests);
    sqlite3_bind_int64(statement.get(), 14, site.rate_limit_ban_seconds);
    sqlite3_bind_int(statement.get(), 15, site.hotlink_enabled ? 1 : 0);
    bind_text(statement.get(), 16, site.hotlink_extensions_json);
    bind_text(statement.get(), 17, site.hotlink_allowed_hosts_json);
    sqlite3_bind_int(statement.get(), 18, site.hotlink_allow_empty_referer ? 1 : 0);
    bind_text(statement.get(), 19, site.hotlink_redirect_location);
    bind_text(statement.get(), 20, site.redirect_rules_json);
    sqlite3_bind_int64(statement.get(), 21, site.backend_max_active_connections);
    sqlite3_bind_int64(statement.get(), 22, site.backend_max_queue);
    sqlite3_bind_int64(statement.get(), 23, site.backend_queue_timeout_seconds);
    bind_text(statement.get(), 24, site.backend_protocol);
    bind_text(statement.get(), 25, site.backend_host);
    bind_text(statement.get(), 26, site.backend_tls_sni);
    sqlite3_bind_int(statement.get(), 27, site.backend_tls_verify_certificate ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 28, site.backend_connect_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 29, site.backend_response_timeout_seconds);
    sqlite3_bind_int(statement.get(), 30, site.backend_keep_alive ? 1 : 0);
    bind_text(statement.get(), 31, site.url_auth_json);
    sqlite3_bind_int64(statement.get(), 32, site.id);
    expect_done(database_.handle(), statement.get(), "cannot update site");
    if (sqlite3_changes(database_.handle()) != 1) {
        throw std::invalid_argument{"site does not exist"};
    }

    Statement delete_domains{database_.handle(), "DELETE FROM site_domains WHERE site_id = ?;"};
    sqlite3_bind_int64(delete_domains.get(), 1, site.id);
    expect_done(database_.handle(), delete_domains.get(), "cannot replace site domains");
    insert_domains(database_.handle(), site.id, site.domains);
    increment_revision(database_.handle());
    transaction.commit();
}

void ConfigRepository::delete_site(std::int64_t id) {
    Transaction transaction{database_};
    Statement statement{database_.handle(), "DELETE FROM sites WHERE id = ?;"};
    sqlite3_bind_int64(statement.get(), 1, id);
    expect_done(database_.handle(), statement.get(), "cannot delete site");
    if (sqlite3_changes(database_.handle()) != 1) {
        throw std::invalid_argument{"site does not exist"};
    }
    increment_revision(database_.handle());
    transaction.commit();
}

std::vector<CertificateRecord> ConfigRepository::list_certificates() const {
    std::vector<CertificateRecord> certificates;
    Statement statement{
        database_.handle(),
        "SELECT id, name, enabled, is_default, domains_json, certificate_pem, private_key_pem "
        "FROM tls_certificates ORDER BY is_default DESC, id;"};
    int result = SQLITE_OK;
    while ((result = sqlite3_step(statement.get())) == SQLITE_ROW) {
        CertificateRecord certificate;
        certificate.id = sqlite3_column_int64(statement.get(), 0);
        certificate.name = column_text(statement.get(), 1);
        certificate.enabled = sqlite3_column_int(statement.get(), 2) != 0;
        certificate.is_default = sqlite3_column_int(statement.get(), 3) != 0;
        try {
            certificate.domains = nlohmann::json::parse(
                column_text(statement.get(), 4)).get<std::vector<std::string>>();
        } catch (const nlohmann::json::exception&) {
            throw std::runtime_error{"stored TLS certificate domains are invalid"};
        }
        certificate.certificate_pem = column_text(statement.get(), 5);
        certificate.private_key_pem = column_text(statement.get(), 6);
        certificates.push_back(std::move(certificate));
    }
    if (result != SQLITE_DONE) {
        throw std::runtime_error{
            "cannot read TLS certificates: " + std::string{sqlite3_errmsg(database_.handle())}};
    }
    return certificates;
}

CertificateRecord ConfigRepository::find_certificate(std::int64_t id) const {
    for (auto& certificate : list_certificates()) {
        if (certificate.id == id) {
            return std::move(certificate);
        }
    }
    throw std::invalid_argument{"TLS certificate does not exist"};
}

std::int64_t ConfigRepository::create_certificate(const CertificateRecord& certificate) {
    Transaction transaction{database_};
    if (certificate.is_default) {
        database_.execute("UPDATE tls_certificates SET is_default = 0 WHERE is_default = 1;");
    }
    Statement statement{
        database_.handle(),
        "INSERT INTO tls_certificates(name, enabled, is_default, domains_json, certificate_pem, "
        "private_key_pem) VALUES(?, ?, ?, ?, ?, ?);"};
    bind_text(statement.get(), 1, certificate.name);
    sqlite3_bind_int(statement.get(), 2, certificate.enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 3, certificate.is_default ? 1 : 0);
    bind_text(statement.get(), 4, nlohmann::json(certificate.domains).dump());
    bind_text(statement.get(), 5, certificate.certificate_pem);
    bind_text(statement.get(), 6, certificate.private_key_pem);
    expect_done(database_.handle(), statement.get(), "cannot create TLS certificate");
    const auto id = sqlite3_last_insert_rowid(database_.handle());
    increment_revision(database_.handle());
    transaction.commit();
    return id;
}

void ConfigRepository::update_certificate(const CertificateRecord& certificate) {
    Transaction transaction{database_};
    if (certificate.is_default) {
        Statement clear_default{
            database_.handle(),
            "UPDATE tls_certificates SET is_default = 0 WHERE is_default = 1 AND id <> ?;"};
        sqlite3_bind_int64(clear_default.get(), 1, certificate.id);
        expect_done(database_.handle(), clear_default.get(), "cannot replace default certificate");
    }
    Statement statement{
        database_.handle(),
        "UPDATE tls_certificates SET name = ?, enabled = ?, is_default = ?, domains_json = ?, "
        "certificate_pem = ?, private_key_pem = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?;"};
    bind_text(statement.get(), 1, certificate.name);
    sqlite3_bind_int(statement.get(), 2, certificate.enabled ? 1 : 0);
    sqlite3_bind_int(statement.get(), 3, certificate.is_default ? 1 : 0);
    bind_text(statement.get(), 4, nlohmann::json(certificate.domains).dump());
    bind_text(statement.get(), 5, certificate.certificate_pem);
    bind_text(statement.get(), 6, certificate.private_key_pem);
    sqlite3_bind_int64(statement.get(), 7, certificate.id);
    expect_done(database_.handle(), statement.get(), "cannot update TLS certificate");
    if (sqlite3_changes(database_.handle()) != 1) {
        throw std::invalid_argument{"TLS certificate does not exist"};
    }
    increment_revision(database_.handle());
    transaction.commit();
}

void ConfigRepository::delete_certificate(std::int64_t id) {
    Transaction transaction{database_};
    Statement statement{database_.handle(), "DELETE FROM tls_certificates WHERE id = ?;"};
    sqlite3_bind_int64(statement.get(), 1, id);
    expect_done(database_.handle(), statement.get(), "cannot delete TLS certificate");
    if (sqlite3_changes(database_.handle()) != 1) {
        throw std::invalid_argument{"TLS certificate does not exist"};
    }
    increment_revision(database_.handle());
    transaction.commit();
}

std::size_t ConfigRepository::certificate_count() const {
    Statement statement{database_.handle(), "SELECT COUNT(*) FROM tls_certificates;"};
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error{"cannot count TLS certificates"};
    }
    return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

RuntimeSettingsRecord ConfigRepository::runtime_settings() const {
    Statement statement{
        database_.handle(),
        "SELECT trusted_proxy_cidrs_json, real_ip_headers_json, max_upload_bytes, "
        "backend_keep_alive, backend_pool_size, client_header_timeout_seconds, "
        "client_body_timeout_seconds, client_write_timeout_seconds, "
        "backend_connect_timeout_seconds, backend_response_timeout_seconds, "
        "backend_idle_timeout_seconds, backend_idle_connection_ttl_seconds "
        "FROM runtime_settings WHERE id = 1;"};
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error{"runtime settings are missing"};
    }
    RuntimeSettingsRecord settings;
    try {
        settings.trusted_proxy_cidrs = nlohmann::json::parse(
            column_text(statement.get(), 0)).get<std::vector<std::string>>();
        settings.real_ip_headers = nlohmann::json::parse(
            column_text(statement.get(), 1)).get<std::vector<std::string>>();
    } catch (const nlohmann::json::exception&) {
        throw std::runtime_error{"stored trusted proxy or real IP header settings are invalid"};
    }
    settings.max_upload_bytes = static_cast<std::uint64_t>(
        sqlite3_column_int64(statement.get(), 2));
    settings.backend_keep_alive = sqlite3_column_int(statement.get(), 3) != 0;
    settings.backend_pool_size = static_cast<std::uint32_t>(
        sqlite3_column_int64(statement.get(), 4));
    settings.client_header_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 5));
    settings.client_body_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 6));
    settings.client_write_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 7));
    settings.backend_connect_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 8));
    settings.backend_response_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 9));
    settings.backend_idle_timeout_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 10));
    settings.backend_idle_connection_ttl_seconds = static_cast<std::uint32_t>(sqlite3_column_int64(statement.get(), 11));
    return settings;
}

void ConfigRepository::update_runtime_settings(const RuntimeSettingsRecord& settings) {
    Transaction transaction{database_};
    Statement statement{
        database_.handle(),
        "UPDATE runtime_settings SET trusted_proxy_cidrs_json = ?, real_ip_headers_json = ?, "
        "max_upload_bytes = ?, backend_keep_alive = ?, backend_pool_size = ?, "
        "client_header_timeout_seconds = ?, client_body_timeout_seconds = ?, "
        "client_write_timeout_seconds = ?, backend_connect_timeout_seconds = ?, "
        "backend_response_timeout_seconds = ?, backend_idle_timeout_seconds = ?, "
        "backend_idle_connection_ttl_seconds = ? WHERE id = 1;"};
    bind_text(statement.get(), 1, nlohmann::json(settings.trusted_proxy_cidrs).dump());
    bind_text(statement.get(), 2, nlohmann::json(settings.real_ip_headers).dump());
    sqlite3_bind_int64(
        statement.get(), 3, static_cast<sqlite3_int64>(settings.max_upload_bytes));
    sqlite3_bind_int(statement.get(), 4, settings.backend_keep_alive ? 1 : 0);
    sqlite3_bind_int64(statement.get(), 5, settings.backend_pool_size);
    sqlite3_bind_int64(statement.get(), 6, settings.client_header_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 7, settings.client_body_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 8, settings.client_write_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 9, settings.backend_connect_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 10, settings.backend_response_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 11, settings.backend_idle_timeout_seconds);
    sqlite3_bind_int64(statement.get(), 12, settings.backend_idle_connection_ttl_seconds);
    expect_done(database_.handle(), statement.get(), "cannot update runtime settings");
    increment_revision(database_.handle());
    transaction.commit();
}

void ConfigRepository::replace_configuration(
    const std::vector<SiteRecord>& sites,
    const std::vector<CertificateRecord>& certificates,
    const RuntimeSettingsRecord& settings) {
    Transaction transaction{database_};
    database_.execute("DELETE FROM site_domains; DELETE FROM sites; DELETE FROM tls_certificates;");

    Statement site_statement{
        database_.handle(),
        "INSERT INTO sites(name, enabled, backend_address, backend_port, http_enabled, http_port, "
        "https_enabled, https_port, force_https, acl_rules_json, rate_limit_enabled, "
        "rate_limit_window_seconds, rate_limit_max_requests, rate_limit_ban_seconds, "
        "hotlink_enabled, hotlink_extensions_json, hotlink_allowed_hosts_json, "
        "hotlink_allow_empty_referer, hotlink_redirect_location, redirect_rules_json, "
        "backend_max_active_connections, backend_max_queue, backend_queue_timeout_seconds, "
        "backend_protocol, backend_host, backend_tls_sni, backend_tls_verify_certificate, "
        "backend_connect_timeout_seconds, backend_response_timeout_seconds, backend_keep_alive, "
        "url_auth_json) "
        "VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"};
    for (const auto& site : sites) {
        sqlite3_reset(site_statement.get());
        sqlite3_clear_bindings(site_statement.get());
        bind_text(site_statement.get(), 1, site.name);
        sqlite3_bind_int(site_statement.get(), 2, site.enabled ? 1 : 0);
        bind_text(site_statement.get(), 3, site.backend_address);
        sqlite3_bind_int(site_statement.get(), 4, site.backend_port);
        sqlite3_bind_int(site_statement.get(), 5, site.http_enabled ? 1 : 0);
        sqlite3_bind_int(site_statement.get(), 6, site.http_port);
        sqlite3_bind_int(site_statement.get(), 7, site.https_enabled ? 1 : 0);
        sqlite3_bind_int(site_statement.get(), 8, site.https_port);
        sqlite3_bind_int(site_statement.get(), 9, site.force_https ? 1 : 0);
        bind_text(site_statement.get(), 10, site.acl_rules_json);
        sqlite3_bind_int(site_statement.get(), 11, site.rate_limit_enabled ? 1 : 0);
        sqlite3_bind_int64(site_statement.get(), 12, site.rate_limit_window_seconds);
        sqlite3_bind_int64(site_statement.get(), 13, site.rate_limit_max_requests);
        sqlite3_bind_int64(site_statement.get(), 14, site.rate_limit_ban_seconds);
        sqlite3_bind_int(site_statement.get(), 15, site.hotlink_enabled ? 1 : 0);
        bind_text(site_statement.get(), 16, site.hotlink_extensions_json);
        bind_text(site_statement.get(), 17, site.hotlink_allowed_hosts_json);
        sqlite3_bind_int(site_statement.get(), 18, site.hotlink_allow_empty_referer ? 1 : 0);
        bind_text(site_statement.get(), 19, site.hotlink_redirect_location);
        bind_text(site_statement.get(), 20, site.redirect_rules_json);
        sqlite3_bind_int64(site_statement.get(), 21, site.backend_max_active_connections);
        sqlite3_bind_int64(site_statement.get(), 22, site.backend_max_queue);
        sqlite3_bind_int64(site_statement.get(), 23, site.backend_queue_timeout_seconds);
        bind_text(site_statement.get(), 24, site.backend_protocol);
        bind_text(site_statement.get(), 25, site.backend_host);
        bind_text(site_statement.get(), 26, site.backend_tls_sni);
        sqlite3_bind_int(site_statement.get(), 27, site.backend_tls_verify_certificate ? 1 : 0);
        sqlite3_bind_int64(site_statement.get(), 28, site.backend_connect_timeout_seconds);
        sqlite3_bind_int64(site_statement.get(), 29, site.backend_response_timeout_seconds);
        sqlite3_bind_int(site_statement.get(), 30, site.backend_keep_alive ? 1 : 0);
        bind_text(site_statement.get(), 31, site.url_auth_json);
        expect_done(database_.handle(), site_statement.get(), "cannot restore site");
        insert_domains(database_.handle(), sqlite3_last_insert_rowid(database_.handle()), site.domains);
    }

    Statement certificate_statement{
        database_.handle(),
        "INSERT INTO tls_certificates(name, enabled, is_default, domains_json, certificate_pem, "
        "private_key_pem) VALUES(?, ?, ?, ?, ?, ?);"};
    for (const auto& certificate : certificates) {
        sqlite3_reset(certificate_statement.get());
        sqlite3_clear_bindings(certificate_statement.get());
        bind_text(certificate_statement.get(), 1, certificate.name);
        sqlite3_bind_int(certificate_statement.get(), 2, certificate.enabled ? 1 : 0);
        sqlite3_bind_int(certificate_statement.get(), 3, certificate.is_default ? 1 : 0);
        bind_text(certificate_statement.get(), 4, nlohmann::json(certificate.domains).dump());
        bind_text(certificate_statement.get(), 5, certificate.certificate_pem);
        bind_text(certificate_statement.get(), 6, certificate.private_key_pem);
        expect_done(database_.handle(), certificate_statement.get(), "cannot restore TLS certificate");
    }

    Statement settings_statement{
        database_.handle(),
        "UPDATE runtime_settings SET trusted_proxy_cidrs_json = ?, real_ip_headers_json = ?, "
        "max_upload_bytes = ?, backend_keep_alive = ?, backend_pool_size = ?, "
        "client_header_timeout_seconds = ?, client_body_timeout_seconds = ?, "
        "client_write_timeout_seconds = ?, backend_connect_timeout_seconds = ?, "
        "backend_response_timeout_seconds = ?, backend_idle_timeout_seconds = ?, "
        "backend_idle_connection_ttl_seconds = ? WHERE id = 1;"};
    bind_text(settings_statement.get(), 1, nlohmann::json(settings.trusted_proxy_cidrs).dump());
    bind_text(settings_statement.get(), 2, nlohmann::json(settings.real_ip_headers).dump());
    sqlite3_bind_int64(settings_statement.get(), 3, static_cast<sqlite3_int64>(settings.max_upload_bytes));
    sqlite3_bind_int(settings_statement.get(), 4, settings.backend_keep_alive ? 1 : 0);
    sqlite3_bind_int64(settings_statement.get(), 5, settings.backend_pool_size);
    sqlite3_bind_int64(settings_statement.get(), 6, settings.client_header_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 7, settings.client_body_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 8, settings.client_write_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 9, settings.backend_connect_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 10, settings.backend_response_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 11, settings.backend_idle_timeout_seconds);
    sqlite3_bind_int64(settings_statement.get(), 12, settings.backend_idle_connection_ttl_seconds);
    expect_done(database_.handle(), settings_statement.get(), "cannot restore runtime settings");

    increment_revision(database_.handle());
    transaction.commit();
}

std::uint64_t ConfigRepository::config_revision() const {
    Statement statement{
        database_.handle(),
        "SELECT CAST(value AS INTEGER) FROM runtime_metadata WHERE key = 'config_revision';"};
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error{"configuration revision is missing"};
    }
    return static_cast<std::uint64_t>(sqlite3_column_int64(statement.get(), 0));
}

std::size_t ConfigRepository::admin_user_count() const {
    Statement statement{database_.handle(), "SELECT COUNT(*) FROM admin_users;"};
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::runtime_error{"cannot count administrator accounts"};
    }
    return static_cast<std::size_t>(sqlite3_column_int64(statement.get(), 0));
}

AdminUserRecord ConfigRepository::find_admin_user(const std::string& username) const {
    Statement statement{
        database_.handle(),
        "SELECT id, username, password_salt, password_hash, password_iterations "
        "FROM admin_users WHERE username = ? COLLATE NOCASE;"};
    bind_text(statement.get(), 1, username);
    if (sqlite3_step(statement.get()) != SQLITE_ROW) {
        throw std::invalid_argument{"invalid username or password"};
    }

    AdminUserRecord user;
    user.id = sqlite3_column_int64(statement.get(), 0);
    user.username = column_text(statement.get(), 1);
    user.password_salt = column_blob(statement.get(), 2);
    user.password_hash = column_blob(statement.get(), 3);
    user.password_iterations = sqlite3_column_int(statement.get(), 4);
    return user;
}

void ConfigRepository::create_admin_user(const AdminUserRecord& user) {
    Statement statement{
        database_.handle(),
        "INSERT INTO admin_users(username, password_salt, password_hash, password_iterations) "
        "VALUES(?, ?, ?, ?);"};
    bind_text(statement.get(), 1, user.username);
    bind_blob(statement.get(), 2, user.password_salt);
    bind_blob(statement.get(), 3, user.password_hash);
    sqlite3_bind_int(statement.get(), 4, user.password_iterations);
    expect_done(database_.handle(), statement.get(), "cannot create administrator account");
}

} // namespace webserver::database
