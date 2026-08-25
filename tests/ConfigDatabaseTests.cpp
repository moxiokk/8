#include "config/ConfigService.hpp"
#include "database/ConfigRepository.hpp"
#include "database/Database.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace {

using json = nlohmann::json;

static_assert(!std::is_constructible_v<
              webserver::config::ConfigService::Activation,
              decltype([] {})>);
static_assert(std::is_constructible_v<
              webserver::config::ConfigService::Activation,
              decltype([]() noexcept {})>);

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

std::filesystem::path unique_database_path() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("webserver-config-test-" + std::to_string(stamp) + ".db");
}

void remove_database_files(const std::filesystem::path& path) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);
}

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) {
        throw std::runtime_error{"cannot open test certificate file: " + path.string()};
    }
    return {
        std::istreambuf_iterator<char>{input},
        std::istreambuf_iterator<char>{}};
}

void run_test(
    const std::filesystem::path& certificate_path,
    const std::filesystem::path& private_key_path) {
    const auto database_path = unique_database_path();
    try {
        {
            webserver::database::Database legacy_database{database_path};
            legacy_database.execute(
                "CREATE TABLE schema_migrations("
                "version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
                "INSERT INTO schema_migrations(version) VALUES(1);"
                "CREATE TABLE sites("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, "
                "enabled INTEGER NOT NULL DEFAULT 1, backend_address TEXT NOT NULL, "
                "backend_port INTEGER NOT NULL, http_enabled INTEGER NOT NULL DEFAULT 1, "
                "http_port INTEGER NOT NULL DEFAULT 80, https_enabled INTEGER NOT NULL DEFAULT 0, "
                "https_port INTEGER NOT NULL DEFAULT 443, force_https INTEGER NOT NULL DEFAULT 0, "
                "created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, "
                "updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);"
            );
        }

        {
            webserver::database::Database database{database_path};
            webserver::database::ConfigRepository repository{database};
            webserver::config::ConfigService service{repository};
            service.initialize();
            service.seed_default_certificate(
                "example.com test certificate",
                {"example.com", "www.example.com"},
                read_text_file(certificate_path),
                read_text_file(private_key_path));

            std::uint64_t published_revision = 0;
            std::vector<webserver::config::RuntimeSiteConfig> published_sites;
            const auto install_capture_handler = [&] {
                service.set_reload_handler(
                    [&published_revision, &published_sites](
                        webserver::config::RuntimeConfigSpec spec) {
                        return [&published_revision, &published_sites,
                                spec = std::move(spec)]() mutable noexcept {
                            published_revision = spec.revision;
                            published_sites = std::move(spec.sites);
                        };
                    });
            };
            install_capture_handler();

            const auto seeded = service.list_sites();
            require(seeded.size() == 1, "default site was not seeded");
            require(
                service.load_runtime_sites().front().domains.size() == 2,
                "default site did not enter the runtime configuration");
            require(!service.restart_required(), "freshly loaded configuration requires restart");

            const auto before_rejected_revision = service.stored_revision();
            webserver::database::SiteRecord missing_certificate;
            missing_certificate.name = "invalid secure site";
            missing_certificate.domains = {"secure-without-cert.test"};
            missing_certificate.backend_address = "127.0.0.1";
            missing_certificate.backend_port = 9443;
            missing_certificate.http_enabled = false;
            missing_certificate.https_enabled = true;
            missing_certificate.https_port = 8443;
            bool invalid_candidate_rejected = false;
            try {
                static_cast<void>(service.create_site(missing_certificate));
            } catch (const std::invalid_argument&) {
                invalid_candidate_rejected = true;
            }
            require(invalid_candidate_rejected,
                    "HTTPS site without a certificate passed candidate validation");
            require(service.list_sites().size() == 1 &&
                        service.stored_revision() == before_rejected_revision,
                    "candidate validation failure was persisted to SQLite");

            service.set_reload_handler([](webserver::config::RuntimeConfigSpec spec) {
                for (const auto& runtime_site : spec.sites) {
                    if (runtime_site.virtual_host.name == "preflight failure") {
                        throw std::runtime_error{"simulated listener preflight failure"};
                    }
                }
                return webserver::config::ConfigService::Activation{[]() noexcept {}};
            });
            webserver::database::SiteRecord preflight_failure;
            preflight_failure.name = "preflight failure";
            preflight_failure.domains = {"preflight-failure.test"};
            preflight_failure.backend_address = "127.0.0.1";
            preflight_failure.backend_port = 8098;
            preflight_failure.http_port = 8088;
            bool preflight_rejected = false;
            try {
                static_cast<void>(service.create_site(preflight_failure));
            } catch (const std::runtime_error&) {
                preflight_rejected = true;
            }
            require(preflight_rejected, "runtime preflight failure was not reported");
            require(service.list_sites().size() == 1 &&
                        service.stored_revision() == before_rejected_revision,
                    "runtime preflight failure was persisted to SQLite");
            install_capture_handler();

            webserver::database::SiteRecord site;
            site.name = "API site";
            site.domains = {"API.Example.Test.", "*.Edge.Example.Test"};
            site.backend_address = "Origin.Example.Test.";
            site.backend_port = 443;
            site.backend_protocol = "HTTPS";
            site.backend_host = "www.example.test";
            site.backend_tls_sni = "WWW.Example.Test.";
            site.backend_tls_verify_certificate = true;
            site.backend_connect_timeout_seconds = 8;
            site.backend_response_timeout_seconds = 75;
            site.backend_keep_alive = false;
            site.http_port = 8081;
            site.acl_rules_json =
                R"([{"name":"Block env","conditions":[{"field":"uri","operator":"contains","value":"/.env"}],"action":"deny","status":403}])";
            site.rate_limit_enabled = true;
            site.rate_limit_window_seconds = 10;
            site.rate_limit_max_requests = 50;
            site.rate_limit_ban_seconds = 30;
            site.url_auth_json =
                R"({"enabled":true,"scope":"specified","primary_key":"PrimaryKey123","backup_key":"BackupKey123","validity_seconds":900,"protected_uris":[{"path":"/video/","match":"prefix"}]})";
            site.hotlink_enabled = true;
            site.hotlink_extensions_json = R"(["jpg","png"])";
            site.hotlink_allowed_hosts_json = R"(["media.example.test"])";
            site.hotlink_allow_empty_referer = false;
            site.redirect_rules_json =
                R"([{"name":"Legacy","source_path":"/old","match":"exact","destination":"/new","status":301}])";
            site.backend_max_active_connections = 17;
            site.backend_max_queue = 29;
            site.backend_queue_timeout_seconds = 7;
            const auto created = service.create_site(site);
            require(created.id > 0, "created site has no database id");
            require(
                created.domains[0] == "api.example.test" &&
                    created.domains[1] == "*.edge.example.test",
                "site domains were not normalized before persistence");
            require(!service.restart_required(), "hot-reloaded update was left pending");
            require(
                published_revision == service.stored_revision() && published_sites.size() == 2,
                "stored update was not published to the runtime handler");
            require(
                published_sites.back().virtual_host.policy.acl_rules.size() == 1 &&
                    published_sites.back().virtual_host.policy.rate_limit.enabled &&
                    published_sites.back().virtual_host.url_auth.enabled &&
                    published_sites.back().virtual_host.url_auth.scope ==
                        webserver::policy::UrlAuthScope::specified &&
                    published_sites.back().virtual_host.url_auth.protected_uris.size() == 1 &&
                    published_sites.back().virtual_host.policy.hotlink.enabled &&
                    published_sites.back().virtual_host.policy.redirects.size() == 1 &&
                    published_sites.back().virtual_host.backend.protocol ==
                        webserver::routing::BackendProtocol::https &&
                    published_sites.back().virtual_host.backend.address == "origin.example.test" &&
                    published_sites.back().virtual_host.backend.tls_sni == "www.example.test" &&
                    !published_sites.back().virtual_host.backend.keep_alive &&
                    published_sites.back().virtual_host.overload.site_id == created.id &&
                    published_sites.back().virtual_host.overload.maximum_active_connections == 17 &&
                    published_sites.back().virtual_host.overload.maximum_queue == 29,
                "site policies did not enter the runtime configuration");

            bool duplicate_rejected = false;
            try {
                site.name = "Duplicate";
                site.domains = {"api.example.test"};
                static_cast<void>(service.create_site(site));
            } catch (const std::exception&) {
                duplicate_rejected = true;
            }
            require(duplicate_rejected, "duplicate domain was accepted");

            auto updated = created;
            updated.backend_port = 9091;
            updated.enabled = false;
            static_cast<void>(service.update_site(updated));
            const auto all_sites = service.list_sites();
            require(all_sites.size() == 2, "site update changed row count");
            require(
                all_sites[1].backend_port == 9091 && !all_sites[1].enabled,
                "site update was not persisted");
            require(
                published_sites.size() == 1,
                "disabled site remained in the published runtime snapshot");
        }

        {
            webserver::database::Database database{database_path};
            webserver::database::ConfigRepository repository{database};
            webserver::config::ConfigService service{repository};
            service.initialize();
            require(service.list_sites().size() == 2, "SQLite configuration did not survive reopen");
            const auto persisted = service.list_sites();
            require(
                persisted[1].rate_limit_enabled && persisted[1].rate_limit_max_requests == 50 &&
                    persisted[1].hotlink_enabled &&
                    persisted[1].acl_rules_json.find("Block env") != std::string::npos &&
                    persisted[1].url_auth_json.find("PrimaryKey123") != std::string::npos &&
                    persisted[1].url_auth_json.find("/video/") != std::string::npos &&
                    persisted[1].redirect_rules_json.find("Legacy") != std::string::npos &&
                    persisted[1].backend_max_active_connections == 17 &&
                    persisted[1].backend_max_queue == 29 &&
                    persisted[1].backend_queue_timeout_seconds == 7 &&
                    persisted[1].backend_protocol == "https" &&
                    persisted[1].backend_address == "origin.example.test" &&
                    persisted[1].backend_host == "www.example.test" &&
                    persisted[1].backend_tls_sni == "www.example.test" &&
                    persisted[1].backend_connect_timeout_seconds == 8 &&
                    persisted[1].backend_response_timeout_seconds == 75 &&
                    !persisted[1].backend_keep_alive,
                "site policy or upstream TLS configuration did not survive SQLite reopen");
            require(
                service.load_runtime_sites().size() == 1,
                "disabled site entered the runtime configuration");
            require(
                service.export_configuration().find("PrimaryKey123") != std::string::npos,
                "URL authentication configuration was omitted from the backup");

            for (const auto& site : service.list_sites()) {
                service.delete_site(site.id);
            }
        }

        {
            webserver::database::Database database{database_path};
            webserver::database::ConfigRepository repository{database};
            webserver::config::ConfigService service{repository};
            service.initialize();
            require(
                service.list_sites().empty(),
                "default site was recreated after the administrator deleted all sites");
            const auto empty_backup = service.export_configuration();
            webserver::database::SiteRecord temporary;
            temporary.name = "temporary";
            temporary.domains = {"temporary.test"};
            temporary.backend_address = "127.0.0.1";
            temporary.backend_port = 8099;
            temporary.https_enabled = false;
            static_cast<void>(service.create_site(temporary));
            require(service.list_sites().size() == 1, "backup restore fixture was not created");

            auto invalid_runtime_backup = json::parse(service.export_configuration());
            auto& invalid_site = invalid_runtime_backup.at("sites").at(0);
            invalid_site["http_enabled"] = false;
            invalid_site["https_enabled"] = true;
            invalid_site["https_port"] = 8443;
            bool invalid_import_rejected = false;
            try {
                service.import_configuration(invalid_runtime_backup.dump());
            } catch (const std::invalid_argument&) {
                invalid_import_rejected = true;
            }
            require(invalid_import_rejected,
                    "import accepted an HTTPS runtime without a certificate");
            require(service.list_sites().size() == 1 &&
                        service.list_sites().front().name == "temporary",
                    "failed runtime import replaced the stored configuration");

            auto duplicate_domain_backup = json::parse(service.export_configuration());
            auto duplicate_site = duplicate_domain_backup.at("sites").at(0);
            duplicate_site["name"] = "duplicate domain";
            duplicate_domain_backup.at("sites").push_back(std::move(duplicate_site));
            bool duplicate_import_rejected = false;
            try {
                service.import_configuration(duplicate_domain_backup.dump());
            } catch (const std::invalid_argument&) {
                duplicate_import_rejected = true;
            }
            require(duplicate_import_rejected,
                    "import accepted a duplicate global site domain");
            require(service.list_sites().size() == 1,
                    "failed duplicate-domain import changed stored sites");

            service.import_configuration(empty_backup);
            require(
                service.list_sites().empty(),
                "configuration restore did not atomically replace the site collection");
        }
    } catch (...) {
        remove_database_files(database_path);
        throw;
    }
    remove_database_files(database_path);
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 3) {
            throw std::invalid_argument{"expected certificate and private key paths"};
        }
        run_test(argv[1], argv[2]);
        std::cout << "Config database tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Config database tests failed: " << error.what() << '\n';
        return 1;
    }
}
