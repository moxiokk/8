#include "config/ConfigService.hpp"

#include "routing/HostNormalizer.hpp"

#include <boost/asio/ip/address.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <limits>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace webserver::config {
namespace {

using json = nlohmann::json;
constexpr std::size_t maximum_configuration_backup_bytes = 16 * 1024 * 1024;

std::uint32_t checked_u32(
    std::uint32_t value,
    std::uint32_t minimum,
    std::uint32_t maximum,
    std::string_view name) {
    if (value < minimum || value > maximum) {
        throw std::invalid_argument{
            std::string{name} + " must be between " + std::to_string(minimum) + " and " +
            std::to_string(maximum)};
    }
    return value;
}

routing::BackendConfig runtime_backend(const database::SiteRecord& site) {
    routing::BackendConfig backend;
    backend.address = site.backend_address;
    backend.port = site.backend_port;
    backend.protocol = site.backend_protocol == "https"
                           ? routing::BackendProtocol::https
                           : routing::BackendProtocol::http;
    backend.host = site.backend_host;
    backend.tls_sni = site.backend_tls_sni;
    backend.tls_verify_certificate = site.backend_tls_verify_certificate;
    backend.connect_timeout_seconds = site.backend_connect_timeout_seconds;
    backend.response_timeout_seconds = site.backend_response_timeout_seconds;
    backend.keep_alive = site.backend_keep_alive;
    return backend;
}

policy::AclField parse_acl_field(std::string_view value) {
    if (value == "ip") return policy::AclField::ip;
    if (value == "uri") return policy::AclField::uri;
    if (value == "host") return policy::AclField::host;
    if (value == "method") return policy::AclField::method;
    if (value == "user_agent") return policy::AclField::user_agent;
    if (value == "referer") return policy::AclField::referer;
    if (value == "header") return policy::AclField::header;
    throw std::invalid_argument{"unsupported ACL field: " + std::string{value}};
}

policy::MatchOperator parse_match_operator(std::string_view value) {
    if (value == "equal") return policy::MatchOperator::equal;
    if (value == "not_equal") return policy::MatchOperator::not_equal;
    if (value == "contains") return policy::MatchOperator::contains;
    if (value == "not_contains") return policy::MatchOperator::not_contains;
    if (value == "starts_with") return policy::MatchOperator::starts_with;
    if (value == "ends_with") return policy::MatchOperator::ends_with;
    if (value == "regex") return policy::MatchOperator::regex;
    if (value == "in_cidr") return policy::MatchOperator::in_cidr;
    if (value == "not_in_cidr") return policy::MatchOperator::not_in_cidr;
    throw std::invalid_argument{"unsupported ACL operator: " + std::string{value}};
}

policy::AclAction parse_acl_action(std::string_view value) {
    if (value == "allow") return policy::AclAction::allow;
    if (value == "deny") return policy::AclAction::deny;
    if (value == "redirect") return policy::AclAction::redirect;
    if (value == "return") return policy::AclAction::return_status;
    throw std::invalid_argument{"unsupported ACL action: " + std::string{value}};
}

policy::AclConditionSpec parse_acl_condition(const json& source) {
    policy::AclConditionSpec condition;
    condition.field = parse_acl_field(source.at("field").get<std::string>());
    condition.operation = parse_match_operator(source.at("operator").get<std::string>());
    condition.value = source.at("value").get<std::string>();
    condition.header_name = source.value("header_name", std::string{});
    condition.case_sensitive = source.value("case_sensitive", false);
    return condition;
}

std::vector<policy::AclRuleSpec> parse_acl_rules(const std::string& encoded) {
    const auto source = json::parse(encoded);
    if (!source.is_array()) {
        throw std::invalid_argument{"ACL rules must be a JSON array"};
    }

    std::vector<policy::AclRuleSpec> rules;
    rules.reserve(source.size());
    for (const auto& item : source) {
        policy::AclRuleSpec rule;
        rule.name = item.at("name").get<std::string>();
        rule.enabled = item.value("enabled", true);
        if (item.contains("conditions")) {
            for (const auto& condition : item.at("conditions")) {
                rule.conditions.push_back(parse_acl_condition(condition));
            }
        } else {
            rule.conditions.push_back(parse_acl_condition(item));
        }
        rule.action = parse_acl_action(item.value("action", std::string{"deny"}));
        rule.status = item.value("status", rule.action == policy::AclAction::redirect ? 302U : 403U);
        rule.redirect_location = item.value("redirect_location", std::string{});
        rules.push_back(std::move(rule));
    }
    return rules;
}

std::vector<policy::RedirectRuleSpec> parse_redirect_rules(const std::string& encoded) {
    const auto source = json::parse(encoded);
    if (!source.is_array()) {
        throw std::invalid_argument{"redirect rules must be a JSON array"};
    }

    std::vector<policy::RedirectRuleSpec> rules;
    rules.reserve(source.size());
    for (const auto& item : source) {
        policy::RedirectRuleSpec rule;
        rule.name = item.at("name").get<std::string>();
        rule.enabled = item.value("enabled", true);
        rule.source_host = item.value("source_host", std::string{});
        rule.source_path = item.value("source_path", std::string{"/"});
        const auto match = item.value("match", std::string{"exact"});
        if (match == "exact") {
            rule.match = policy::RedirectMatch::exact;
        } else if (match == "prefix") {
            rule.match = policy::RedirectMatch::prefix;
        } else {
            throw std::invalid_argument{"redirect match must be exact or prefix"};
        }
        rule.destination = item.at("destination").get<std::string>();
        rule.status = item.value("status", 301U);
        rule.preserve_path = item.value("preserve_path", false);
        rule.preserve_query = item.value("preserve_query", true);
        rules.push_back(std::move(rule));
    }
    return rules;
}

policy::UrlAuthSpec parse_url_auth(const std::string& encoded) {
    const auto source = json::parse(encoded);
    if (!source.is_object()) {
        throw std::invalid_argument{"URL authentication configuration must be a JSON object"};
    }

    policy::UrlAuthSpec result;
    result.enabled = source.value("enabled", false);
    const auto scope = source.value("scope", std::string{"all"});
    if (scope == "all") {
        result.scope = policy::UrlAuthScope::all;
    } else if (scope == "specified") {
        result.scope = policy::UrlAuthScope::specified;
    } else {
        throw std::invalid_argument{"URL authentication scope must be all or specified"};
    }
    result.primary_key = source.value("primary_key", std::string{});
    result.backup_key = source.value("backup_key", std::string{});
    const auto validity = source.value("validity_seconds", std::int64_t{1800});
    if (validity < 0 || validity > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument{"URL authentication validity is out of range"};
    }
    result.validity_seconds = static_cast<std::uint32_t>(validity);

    const auto protected_uris = source.value("protected_uris", json::array());
    if (!protected_uris.is_array()) {
        throw std::invalid_argument{"URL authentication protected URIs must be an array"};
    }
    if (protected_uris.size() > 200) {
        throw std::invalid_argument{
            "URL authentication cannot contain more than 200 protected URI rules"};
    }
    result.protected_uris.reserve(protected_uris.size());
    for (const auto& item : protected_uris) {
        policy::UrlAuthUriSpec rule;
        rule.path = item.at("path").get<std::string>();
        const auto match = item.value("match", std::string{"exact"});
        if (match == "exact") {
            rule.match = policy::UrlAuthMatch::exact;
        } else if (match == "prefix") {
            rule.match = policy::UrlAuthMatch::prefix;
        } else {
            throw std::invalid_argument{
                "URL authentication URI match must be exact or prefix"};
        }
        result.protected_uris.push_back(std::move(rule));
    }
    return result;
}

std::vector<std::string> parse_string_array(
    const std::string& encoded,
    std::string_view name,
    std::size_t maximum) {
    const auto source = json::parse(encoded);
    if (!source.is_array() || source.size() > maximum) {
        throw std::invalid_argument{
            std::string{name} + " must be a JSON array with at most " + std::to_string(maximum) +
            " entries"};
    }
    return source.get<std::vector<std::string>>();
}

void canonicalize_json(database::SiteRecord& site) {
    auto acl = json::parse(site.acl_rules_json);
    auto redirects = json::parse(site.redirect_rules_json);
    auto extensions = json::parse(site.hotlink_extensions_json);
    auto allowed_hosts = json::parse(site.hotlink_allowed_hosts_json);
    auto url_auth = json::parse(site.url_auth_json);
    if (!acl.is_array() || !redirects.is_array() || !extensions.is_array() ||
        !allowed_hosts.is_array() || !url_auth.is_object()) {
        throw std::invalid_argument{"site policy JSON values have invalid types"};
    }
    site.acl_rules_json = acl.dump();
    site.redirect_rules_json = redirects.dump();
    site.hotlink_extensions_json = extensions.dump();
    site.hotlink_allowed_hosts_json = allowed_hosts.dump();
    site.url_auth_json = url_auth.dump();
}

} // namespace

ConfigService::ConfigService(database::ConfigRepository& repository) : repository_(repository) {}

void ConfigService::initialize() {
    std::scoped_lock lock{mutex_};
    repository_.migrate();
    repository_.seed_default_site();
    active_revision_ = repository_.config_revision();
}

void ConfigService::set_reload_handler(ReloadHandler handler) {
    if (!handler) {
        throw std::invalid_argument{"runtime reload handler cannot be empty"};
    }
    std::scoped_lock lock{mutex_};
    reload_handler_ = std::move(handler);
}

void ConfigService::mark_runtime_unavailable() {
    std::scoped_lock lock{mutex_};
    active_revision_ = 0;
    reload_handler_ = {};
}

void ConfigService::reload_runtime() {
    std::scoped_lock lock{mutex_};
    if (!reload_handler_) {
        throw std::logic_error{"runtime hot reload is not configured"};
    }
    activate_latest_locked();
}

std::vector<routing::VirtualHostConfig> ConfigService::load_runtime_sites() {
    std::scoped_lock lock{mutex_};
    std::vector<routing::VirtualHostConfig> runtime_sites;
    for (auto& site : load_runtime_site_configs_locked()) {
        runtime_sites.push_back(std::move(site.virtual_host));
    }
    return runtime_sites;
}

std::vector<RuntimeSiteConfig> ConfigService::load_runtime_site_configs() {
    std::scoped_lock lock{mutex_};
    return load_runtime_site_configs_locked();
}

RuntimeConfigSpec ConfigService::load_runtime_config() {
    std::scoped_lock lock{mutex_};
    return build_runtime_spec_locked(repository_.config_revision());
}

std::vector<database::SiteRecord> ConfigService::list_sites() {
    std::scoped_lock lock{mutex_};
    return repository_.list_sites();
}

database::SiteRecord ConfigService::create_site(database::SiteRecord site) {
    validate_and_normalize(site);
    std::scoped_lock lock{mutex_};
    const auto revision = repository_.config_revision() + 1;
    site.id = repository_.next_site_id();
    auto sites = repository_.list_sites();
    sites.push_back(site);
    auto candidate = build_runtime_spec(
        sites, repository_.list_certificates(), repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    site.id = repository_.create_site(site);
    commit_candidate_locked(std::move(activation), revision);
    return site;
}

database::SiteRecord ConfigService::update_site(database::SiteRecord site) {
    if (site.id <= 0) {
        throw std::invalid_argument{"site id must be positive"};
    }
    validate_and_normalize(site);
    std::scoped_lock lock{mutex_};
    const auto revision = repository_.config_revision() + 1;
    auto sites = repository_.list_sites();
    const auto existing = std::find_if(
        sites.begin(), sites.end(), [&site](const auto& item) { return item.id == site.id; });
    if (existing == sites.end()) throw std::invalid_argument{"site does not exist"};
    *existing = site;
    auto candidate = build_runtime_spec(
        sites, repository_.list_certificates(), repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.update_site(site);
    commit_candidate_locked(std::move(activation), revision);
    return site;
}

void ConfigService::delete_site(std::int64_t id) {
    if (id <= 0) {
        throw std::invalid_argument{"site id must be positive"};
    }
    std::scoped_lock lock{mutex_};
    const auto revision = repository_.config_revision() + 1;
    auto sites = repository_.list_sites();
    const auto original_size = sites.size();
    sites.erase(std::remove_if(sites.begin(), sites.end(), [id](const auto& site) {
        return site.id == id;
    }), sites.end());
    if (sites.size() == original_size) throw std::invalid_argument{"site does not exist"};
    auto candidate = build_runtime_spec(
        sites, repository_.list_certificates(), repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.delete_site(id);
    commit_candidate_locked(std::move(activation), revision);
}

void ConfigService::seed_default_certificate(
    std::string name,
    std::vector<std::string> domains,
    std::string certificate_pem,
    std::string private_key_pem) {
    std::scoped_lock lock{mutex_};
    if (repository_.certificate_count() != 0) return;
    database::CertificateRecord certificate;
    certificate.name = std::move(name);
    certificate.domains = std::move(domains);
    certificate.certificate_pem = std::move(certificate_pem);
    certificate.private_key_pem = std::move(private_key_pem);
    certificate.is_default = true;
    validate_and_normalize_certificate(certificate);
    const auto revision = repository_.config_revision() + 1;
    auto candidate = build_runtime_spec(
        repository_.list_sites(), {certificate}, repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    static_cast<void>(repository_.create_certificate(certificate));
    if (activation) {
        commit_candidate_locked(std::move(activation), revision);
    } else {
        // Startup seeding happens before the initial ServerCore snapshot is
        // constructed, so this revision will be active on that first load.
        active_revision_ = revision;
    }
}

std::vector<database::CertificateRecord> ConfigService::list_certificates() {
    std::scoped_lock lock{mutex_};
    return repository_.list_certificates();
}

database::CertificateRecord ConfigService::find_certificate(std::int64_t id) {
    std::scoped_lock lock{mutex_};
    return repository_.find_certificate(id);
}

database::CertificateRecord ConfigService::create_certificate(
    database::CertificateRecord certificate) {
    validate_and_normalize_certificate(certificate);
    std::scoped_lock lock{mutex_};
    const auto revision = repository_.config_revision() + 1;
    auto certificates = repository_.list_certificates();
    if (certificate.is_default) {
        for (auto& configured : certificates) configured.is_default = false;
    }
    certificates.push_back(certificate);
    auto candidate = build_runtime_spec(
        repository_.list_sites(), certificates, repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    certificate.id = repository_.create_certificate(certificate);
    commit_candidate_locked(std::move(activation), revision);
    return certificate;
}

database::CertificateRecord ConfigService::update_certificate(
    database::CertificateRecord certificate) {
    if (certificate.id <= 0) throw std::invalid_argument{"TLS certificate id must be positive"};
    validate_and_normalize_certificate(certificate);
    std::scoped_lock lock{mutex_};
    auto records = repository_.list_certificates();
    bool found = false;
    for (auto& current : records) {
        if (current.id == certificate.id) {
            current = certificate;
            found = true;
        } else if (certificate.is_default) {
            current.is_default = false;
        }
    }
    if (!found) throw std::invalid_argument{"TLS certificate does not exist"};
    const auto revision = repository_.config_revision() + 1;
    auto candidate = build_runtime_spec(
        repository_.list_sites(), records, repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.update_certificate(certificate);
    commit_candidate_locked(std::move(activation), revision);
    return certificate;
}

void ConfigService::delete_certificate(std::int64_t id) {
    if (id <= 0) throw std::invalid_argument{"TLS certificate id must be positive"};
    std::scoped_lock lock{mutex_};
    auto certificates = repository_.list_certificates();
    const auto original_size = certificates.size();
    certificates.erase(
        std::remove_if(certificates.begin(), certificates.end(),
            [id](const auto& certificate) { return certificate.id == id; }),
        certificates.end());
    if (certificates.size() == original_size) {
        throw std::invalid_argument{"TLS certificate does not exist"};
    }
    const auto revision = repository_.config_revision() + 1;
    auto candidate = build_runtime_spec(
        repository_.list_sites(), certificates, repository_.runtime_settings(), revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.delete_certificate(id);
    commit_candidate_locked(std::move(activation), revision);
}

database::RuntimeSettingsRecord ConfigService::runtime_settings() {
    std::scoped_lock lock{mutex_};
    return repository_.runtime_settings();
}

database::RuntimeSettingsRecord ConfigService::update_runtime_settings(
    database::RuntimeSettingsRecord settings) {
    validate_runtime_settings(settings);
    std::scoped_lock lock{mutex_};
    const auto revision = repository_.config_revision() + 1;
    auto candidate = build_runtime_spec(
        repository_.list_sites(), repository_.list_certificates(), settings, revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.update_runtime_settings(settings);
    commit_candidate_locked(std::move(activation), revision);
    return settings;
}

std::string ConfigService::export_configuration() {
    std::scoped_lock lock{mutex_};
    json site_items = json::array();
    for (const auto& site : repository_.list_sites()) {
        site_items.push_back(json{
            {"name", site.name},
            {"enabled", site.enabled},
            {"domains", site.domains},
            {"backend_address", site.backend_address},
            {"backend_port", site.backend_port},
            {"backend_protocol", site.backend_protocol},
            {"backend_host", site.backend_host},
            {"backend_tls_sni", site.backend_tls_sni},
            {"backend_tls_verify_certificate", site.backend_tls_verify_certificate},
            {"backend_connect_timeout_seconds", site.backend_connect_timeout_seconds},
            {"backend_response_timeout_seconds", site.backend_response_timeout_seconds},
            {"backend_keep_alive", site.backend_keep_alive},
            {"url_auth", json::parse(site.url_auth_json)},
            {"http_enabled", site.http_enabled},
            {"http_port", site.http_port},
            {"https_enabled", site.https_enabled},
            {"https_port", site.https_port},
            {"force_https", site.force_https},
            {"acl_rules", json::parse(site.acl_rules_json)},
            {"rate_limit_enabled", site.rate_limit_enabled},
            {"rate_limit_window_seconds", site.rate_limit_window_seconds},
            {"rate_limit_max_requests", site.rate_limit_max_requests},
            {"rate_limit_ban_seconds", site.rate_limit_ban_seconds},
            {"hotlink_enabled", site.hotlink_enabled},
            {"hotlink_extensions", json::parse(site.hotlink_extensions_json)},
            {"hotlink_allowed_hosts", json::parse(site.hotlink_allowed_hosts_json)},
            {"hotlink_allow_empty_referer", site.hotlink_allow_empty_referer},
            {"hotlink_redirect_location", site.hotlink_redirect_location},
            {"redirect_rules", json::parse(site.redirect_rules_json)},
            {"backend_max_active_connections", site.backend_max_active_connections},
            {"backend_max_queue", site.backend_max_queue},
            {"backend_queue_timeout_seconds", site.backend_queue_timeout_seconds}});
    }

    json certificate_items = json::array();
    for (const auto& certificate : repository_.list_certificates()) {
        certificate_items.push_back(json{
            {"name", certificate.name},
            {"enabled", certificate.enabled},
            {"is_default", certificate.is_default},
            {"domains", certificate.domains},
            {"certificate_pem", certificate.certificate_pem},
            {"private_key_pem", certificate.private_key_pem}});
    }

    const auto settings = repository_.runtime_settings();
    const auto exported_at = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    auto encoded = json{
        {"format", "webserver-config-backup"},
        {"version", 1},
        {"exported_at_unix", exported_at},
        {"config_revision", repository_.config_revision()},
        {"sites", std::move(site_items)},
        {"certificates", std::move(certificate_items)},
        {"settings", json{
            {"trusted_proxy_cidrs", settings.trusted_proxy_cidrs},
            {"real_ip_headers", settings.real_ip_headers},
            {"max_upload_bytes", settings.max_upload_bytes},
            {"backend_keep_alive", settings.backend_keep_alive},
            {"backend_pool_size", settings.backend_pool_size},
            {"client_header_timeout_seconds", settings.client_header_timeout_seconds},
            {"client_body_timeout_seconds", settings.client_body_timeout_seconds},
            {"client_write_timeout_seconds", settings.client_write_timeout_seconds},
            {"backend_connect_timeout_seconds", settings.backend_connect_timeout_seconds},
            {"backend_response_timeout_seconds", settings.backend_response_timeout_seconds},
            {"backend_idle_timeout_seconds", settings.backend_idle_timeout_seconds},
            {"backend_idle_connection_ttl_seconds", settings.backend_idle_connection_ttl_seconds}}}}
        .dump(2);
    if (encoded.size() > maximum_configuration_backup_bytes) {
        throw std::runtime_error{
            "configuration backup exceeds the 16 MiB import limit"};
    }
    return encoded;
}

void ConfigService::import_configuration(std::string_view encoded) {
    if (encoded.empty() || encoded.size() > maximum_configuration_backup_bytes) {
        throw std::invalid_argument{"configuration backup must be between 1 byte and 16 MiB"};
    }
    const auto source = json::parse(encoded);
    if (!source.is_object() || source.value("format", std::string{}) != "webserver-config-backup" ||
        source.value("version", 0) != 1) {
        throw std::invalid_argument{"unsupported configuration backup format or version"};
    }
    if (!source.contains("sites") || !source.contains("certificates") ||
        !source.contains("settings")) {
        throw std::invalid_argument{"configuration backup is missing required sections"};
    }
    const auto& site_items = source.at("sites");
    const auto& certificate_items = source.at("certificates");
    if (!site_items.is_array() || site_items.size() > 10000) {
        throw std::invalid_argument{"configuration backup cannot contain more than 10000 sites"};
    }
    if (!certificate_items.is_array() || certificate_items.size() > 1000) {
        throw std::invalid_argument{"configuration backup cannot contain more than 1000 certificates"};
    }
    const auto backup_u32 = [](const json& item, std::string_view key, std::uint32_t fallback) {
        const auto found = item.find(std::string{key});
        if (found == item.end()) return fallback;
        const auto value = found->get<std::int64_t>();
        if (value < 0 || value > std::numeric_limits<std::uint32_t>::max()) {
            throw std::invalid_argument{"configuration backup numeric value is out of range: " +
                                        std::string{key}};
        }
        return static_cast<std::uint32_t>(value);
    };
    const auto backup_port = [&backup_u32](
        const json& item, std::string_view key, std::uint16_t fallback) {
        const auto value = backup_u32(item, key, fallback);
        if (value == 0 || value > std::numeric_limits<std::uint16_t>::max()) {
            throw std::invalid_argument{"configuration backup port is out of range: " +
                                        std::string{key}};
        }
        return static_cast<std::uint16_t>(value);
    };

    std::vector<database::SiteRecord> sites;
    sites.reserve(site_items.size());
    std::unordered_set<std::string> global_domains;
    for (const auto& item : site_items) {
        if (!item.is_object()) {
            throw std::invalid_argument{"configuration backup site entries must be objects"};
        }
        database::SiteRecord site;
        site.name = item.at("name").get<std::string>();
        site.enabled = item.value("enabled", true);
        site.domains = item.at("domains").get<std::vector<std::string>>();
        site.backend_address = item.at("backend_address").get<std::string>();
        site.backend_port = backup_port(item, "backend_port", 0);
        site.backend_protocol = item.value("backend_protocol", std::string{"http"});
        site.backend_host = item.value("backend_host", std::string{});
        site.backend_tls_sni = item.value("backend_tls_sni", std::string{});
        site.backend_tls_verify_certificate = item.value("backend_tls_verify_certificate", true);
        site.backend_connect_timeout_seconds = backup_u32(item, "backend_connect_timeout_seconds", 5);
        site.backend_response_timeout_seconds = backup_u32(item, "backend_response_timeout_seconds", 60);
        site.backend_keep_alive = item.value("backend_keep_alive", true);
        site.url_auth_json = item.value("url_auth", json{
            {"enabled", false},
            {"scope", "all"},
            {"primary_key", ""},
            {"backup_key", ""},
            {"validity_seconds", 1800},
            {"protected_uris", json::array()}}).dump();
        site.http_enabled = item.value("http_enabled", true);
        site.http_port = backup_port(item, "http_port", 80);
        site.https_enabled = item.value("https_enabled", false);
        site.https_port = backup_port(item, "https_port", 443);
        site.force_https = item.value("force_https", false);
        site.acl_rules_json = item.value("acl_rules", json::array()).dump();
        site.rate_limit_enabled = item.value("rate_limit_enabled", false);
        site.rate_limit_window_seconds = backup_u32(item, "rate_limit_window_seconds", 10);
        site.rate_limit_max_requests = backup_u32(item, "rate_limit_max_requests", 100);
        site.rate_limit_ban_seconds = backup_u32(item, "rate_limit_ban_seconds", 60);
        site.hotlink_enabled = item.value("hotlink_enabled", false);
        site.hotlink_extensions_json = item.value(
            "hotlink_extensions", json{"jpg", "jpeg", "png", "gif", "webp", "mp4", "zip"}).dump();
        site.hotlink_allowed_hosts_json = item.value("hotlink_allowed_hosts", json::array()).dump();
        site.hotlink_allow_empty_referer = item.value("hotlink_allow_empty_referer", true);
        site.hotlink_redirect_location = item.value("hotlink_redirect_location", std::string{});
        site.redirect_rules_json = item.value("redirect_rules", json::array()).dump();
        site.backend_max_active_connections = backup_u32(item, "backend_max_active_connections", 200);
        site.backend_max_queue = backup_u32(item, "backend_max_queue", 1000);
        site.backend_queue_timeout_seconds = backup_u32(item, "backend_queue_timeout_seconds", 5);
        validate_and_normalize(site);
        for (const auto& domain : site.domains) {
            if (!global_domains.emplace(domain).second) {
                throw std::invalid_argument{
                    "duplicate site domain in configuration backup: " + domain};
            }
        }
        sites.push_back(std::move(site));
    }

    std::vector<database::CertificateRecord> certificates;
    certificates.reserve(certificate_items.size());
    std::unordered_set<std::string> certificate_names;
    std::size_t default_certificate_count = 0;
    for (const auto& item : certificate_items) {
        if (!item.is_object()) {
            throw std::invalid_argument{
                "configuration backup certificate entries must be objects"};
        }
        database::CertificateRecord certificate;
        certificate.name = item.at("name").get<std::string>();
        certificate.enabled = item.value("enabled", true);
        certificate.is_default = item.value("is_default", false);
        if (certificate.is_default && ++default_certificate_count > 1) {
            throw std::invalid_argument{"configuration backup contains multiple default TLS certificates"};
        }
        certificate.domains = item.at("domains").get<std::vector<std::string>>();
        certificate.certificate_pem = item.at("certificate_pem").get<std::string>();
        certificate.private_key_pem = item.at("private_key_pem").get<std::string>();
        validate_and_normalize_certificate(certificate);
        if (!certificate_names.emplace(certificate.name).second) {
            throw std::invalid_argument{"duplicate TLS certificate name: " + certificate.name};
        }
        certificates.push_back(std::move(certificate));
    }

    const auto& settings_item = source.at("settings");
    if (!settings_item.is_object()) {
        throw std::invalid_argument{"configuration backup settings must be an object"};
    }
    database::RuntimeSettingsRecord settings;
    settings.trusted_proxy_cidrs = settings_item.value(
        "trusted_proxy_cidrs", std::vector<std::string>{});
    settings.real_ip_headers = settings_item.value(
        "real_ip_headers",
        std::vector<std::string>{
            "EO-Connecting-IP", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For"});
    settings.max_upload_bytes = settings_item.value(
        "max_upload_bytes", 64ULL * 1024ULL * 1024ULL);
    settings.backend_keep_alive = settings_item.value("backend_keep_alive", true);
    settings.backend_pool_size = backup_u32(settings_item, "backend_pool_size", 32);
    settings.client_header_timeout_seconds = backup_u32(settings_item, "client_header_timeout_seconds", 15);
    settings.client_body_timeout_seconds = backup_u32(settings_item, "client_body_timeout_seconds", 120);
    settings.client_write_timeout_seconds = backup_u32(settings_item, "client_write_timeout_seconds", 60);
    settings.backend_connect_timeout_seconds = backup_u32(settings_item, "backend_connect_timeout_seconds", 5);
    settings.backend_response_timeout_seconds = backup_u32(settings_item, "backend_response_timeout_seconds", 60);
    settings.backend_idle_timeout_seconds = backup_u32(settings_item, "backend_idle_timeout_seconds", 60);
    settings.backend_idle_connection_ttl_seconds = backup_u32(
        settings_item, "backend_idle_connection_ttl_seconds", 60);
    validate_runtime_settings(settings);

    std::scoped_lock lock{mutex_};
    auto next_site_id = repository_.next_site_id();
    for (auto& site : sites) site.id = next_site_id++;
    const auto revision = repository_.config_revision() + 1;
    auto candidate = build_runtime_spec(sites, certificates, settings, revision);
    auto activation = prepare_candidate_locked(std::move(candidate));
    repository_.replace_configuration(sites, certificates, settings);
    commit_candidate_locked(std::move(activation), revision);
}

std::uint64_t ConfigService::active_revision() const {
    std::scoped_lock lock{mutex_};
    return active_revision_;
}

std::uint64_t ConfigService::stored_revision() {
    std::scoped_lock lock{mutex_};
    return repository_.config_revision();
}

bool ConfigService::restart_required() {
    std::scoped_lock lock{mutex_};
    return repository_.config_revision() != active_revision_;
}

bool ConfigService::hot_reload_enabled() const {
    std::scoped_lock lock{mutex_};
    return static_cast<bool>(reload_handler_);
}

std::vector<RuntimeSiteConfig> ConfigService::load_runtime_site_configs_locked() {
    std::vector<RuntimeSiteConfig> runtime_sites;
    for (auto site : repository_.list_sites()) {
        validate_and_normalize(site);
        if (!site.enabled) {
            continue;
        }

        RuntimeSiteConfig runtime_site;
        runtime_site.virtual_host = routing::VirtualHostConfig{
            site.name,
            site.domains,
            runtime_backend(site),
            runtime_policy(site),
            routing::BackendOverloadConfig{
                site.id,
                site.name,
                site.backend_max_active_connections,
                site.backend_max_queue,
                site.backend_queue_timeout_seconds},
            runtime_url_auth(site)};
        runtime_site.http_enabled = site.http_enabled;
        runtime_site.http_port = site.http_port;
        runtime_site.https_enabled = site.https_enabled;
        runtime_site.https_port = site.https_port;
        runtime_sites.push_back(std::move(runtime_site));
    }
    return runtime_sites;
}

RuntimeConfigSpec ConfigService::build_runtime_spec_locked(std::uint64_t revision) {
    return build_runtime_spec(
        repository_.list_sites(),
        repository_.list_certificates(),
        repository_.runtime_settings(),
        revision);
}

RuntimeConfigSpec ConfigService::build_runtime_spec(
    const std::vector<database::SiteRecord>& sites,
    const std::vector<database::CertificateRecord>& certificates,
    const database::RuntimeSettingsRecord& stored_settings,
    std::uint64_t revision) {
    RuntimeConfigSpec spec;
    spec.revision = revision;
    for (auto site : sites) {
        validate_and_normalize(site);
        if (!site.enabled) continue;
        RuntimeSiteConfig runtime_site;
        runtime_site.virtual_host = routing::VirtualHostConfig{
            site.name,
            site.domains,
            runtime_backend(site),
            runtime_policy(site),
            routing::BackendOverloadConfig{
                site.id,
                site.name,
                site.backend_max_active_connections,
                site.backend_max_queue,
                site.backend_queue_timeout_seconds},
            runtime_url_auth(site)};
        runtime_site.http_enabled = site.http_enabled;
        runtime_site.http_port = site.http_port;
        runtime_site.https_enabled = site.https_enabled;
        runtime_site.https_port = site.https_port;
        spec.sites.push_back(std::move(runtime_site));
    }
    for (const auto& certificate : certificates) {
        if (!certificate.enabled) continue;
        spec.tls_certificates.push_back(tls::TlsCertificateConfig{
            certificate.name,
            certificate.domains,
            {},
            {},
            certificate.is_default,
            certificate.certificate_pem,
            certificate.private_key_pem});
    }
    spec.reject_unknown_sni = true;
    auto settings = stored_settings;
    validate_runtime_settings(settings);
    spec.settings.trusted_proxy_cidrs = settings.trusted_proxy_cidrs;
    spec.settings.real_ip_headers = settings.real_ip_headers;
    spec.settings.max_upload_bytes = settings.max_upload_bytes;
    spec.settings.backend_keep_alive = settings.backend_keep_alive;
    spec.settings.backend_pool_size = settings.backend_pool_size;
    spec.settings.client_header_timeout_seconds = settings.client_header_timeout_seconds;
    spec.settings.client_body_timeout_seconds = settings.client_body_timeout_seconds;
    spec.settings.client_write_timeout_seconds = settings.client_write_timeout_seconds;
    spec.settings.backend_connect_timeout_seconds = settings.backend_connect_timeout_seconds;
    spec.settings.backend_response_timeout_seconds = settings.backend_response_timeout_seconds;
    spec.settings.backend_idle_timeout_seconds = settings.backend_idle_timeout_seconds;
    spec.settings.backend_idle_connection_ttl_seconds =
        settings.backend_idle_connection_ttl_seconds;
    return spec;
}

ConfigService::Activation ConfigService::prepare_candidate_locked(
    RuntimeConfigSpec candidate) {
    // Materialize the entire immutable runtime graph before durable state is
    // touched. This validates routers, listener collisions, policies and TLS.
    static_cast<void>(build_runtime_config(candidate));
    if (!reload_handler_) return {};
    auto activation = reload_handler_(std::move(candidate));
    if (!activation) {
        throw std::logic_error{"runtime reload handler returned no activation"};
    }
    return activation;
}

void ConfigService::commit_candidate_locked(
    Activation activation,
    std::uint64_t revision) noexcept {
    if (!activation) return;
    activation();
    active_revision_ = revision;
}

void ConfigService::activate_latest_locked() {
    if (!reload_handler_) {
        return;
    }

    const auto revision = repository_.config_revision();
    auto activation = prepare_candidate_locked(build_runtime_spec_locked(revision));
    commit_candidate_locked(std::move(activation), revision);
}

void ConfigService::validate_and_normalize_certificate(
    database::CertificateRecord& certificate) {
    if (certificate.name.empty() || certificate.name.size() > 128) {
        throw std::invalid_argument{"TLS certificate name must contain 1 to 128 characters"};
    }
    if (certificate.certificate_pem.size() > 1024 * 1024 ||
        certificate.private_key_pem.size() > 1024 * 1024) {
        throw std::invalid_argument{"TLS certificate and private key must each be at most 1 MiB"};
    }
    std::vector<std::string> normalized_domains;
    std::unordered_set<std::string> unique;
    for (const auto& pattern : certificate.domains) {
        const bool wildcard = pattern.starts_with("*.");
        const auto domain = routing::HostNormalizer::normalize_domain(
            wildcard ? std::string_view{pattern}.substr(2) : std::string_view{pattern});
        if (!domain) throw std::invalid_argument{"invalid TLS certificate domain: " + pattern};
        const auto normalized = wildcard ? "*." + *domain : *domain;
        if (!unique.emplace(normalized).second) {
            throw std::invalid_argument{"duplicate TLS certificate domain: " + normalized};
        }
        normalized_domains.push_back(normalized);
    }
    certificate.domains = std::move(normalized_domains);
    tls::TlsCertificateConfig test{
        certificate.name, certificate.domains, {}, {}, true,
        certificate.certificate_pem, certificate.private_key_pem};
    static_cast<void>(tls::TlsContextManager{{std::move(test)}, true});
}

void ConfigService::validate_runtime_settings(database::RuntimeSettingsRecord& settings) {
    if (settings.trusted_proxy_cidrs.size() > 512) {
        throw std::invalid_argument{"at most 512 trusted proxy CIDRs are allowed"};
    }
    static_cast<void>(network::ClientIpResolver{
        settings.trusted_proxy_cidrs,
        settings.real_ip_headers});
    if (settings.max_upload_bytes == 0 ||
        settings.max_upload_bytes > 16ULL * 1024 * 1024 * 1024) {
        throw std::invalid_argument{"maximum upload size must be between 1 byte and 16 GiB"};
    }
    if (settings.backend_pool_size > 1024) {
        throw std::invalid_argument{"backend connection pool size cannot exceed 1024"};
    }
    if (settings.real_ip_headers.empty() || settings.real_ip_headers.size() > 32) {
        throw std::invalid_argument{"real IP header priority must contain 1 to 32 entries"};
    }
    std::unordered_set<std::string> header_names;
    for (auto& name : settings.real_ip_headers) {
        if (name.empty() || name.size() > 128 ||
            !std::all_of(name.begin(), name.end(), [](unsigned char c) {
                return std::isalnum(c) || c == '-' || c == '_';
            })) {
            throw std::invalid_argument{"invalid real IP header name: " + name};
        }
        std::string folded = name;
        std::transform(folded.begin(), folded.end(), folded.begin(),
            [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (!header_names.emplace(std::move(folded)).second) {
            throw std::invalid_argument{"duplicate real IP header name: " + name};
        }
    }
    const auto validate_timeout = [](std::uint32_t value, std::string_view name) {
        if (value < 1 || value > 86400) {
            throw std::invalid_argument{std::string{name} + " must be between 1 and 86400 seconds"};
        }
    };
    validate_timeout(settings.client_header_timeout_seconds, "client header timeout");
    validate_timeout(settings.client_body_timeout_seconds, "client body timeout");
    validate_timeout(settings.client_write_timeout_seconds, "client write timeout");
    validate_timeout(settings.backend_connect_timeout_seconds, "backend connect timeout");
    validate_timeout(settings.backend_response_timeout_seconds, "backend response timeout");
    validate_timeout(settings.backend_idle_timeout_seconds, "backend idle timeout");
    validate_timeout(settings.backend_idle_connection_ttl_seconds, "backend idle connection TTL");
}

void ConfigService::validate_and_normalize(database::SiteRecord& site) {
    if (site.name.empty() || site.name.size() > 128) {
        throw std::invalid_argument{"site name must contain 1 to 128 characters"};
    }
    if (site.domains.empty() || site.domains.size() > 50) {
        throw std::invalid_argument{"site must contain 1 to 50 domains"};
    }
    if (site.backend_port == 0) {
        throw std::invalid_argument{"backend port must be between 1 and 65535"};
    }
    if (site.http_enabled && site.http_port == 0) {
        throw std::invalid_argument{"HTTP port must be between 1 and 65535"};
    }
    if (site.https_enabled && site.https_port == 0) {
        throw std::invalid_argument{"HTTPS port must be between 1 and 65535"};
    }
    if (!site.http_enabled && !site.https_enabled) {
        throw std::invalid_argument{"at least one listener must be enabled"};
    }
    if (site.force_https && !site.https_enabled) {
        throw std::invalid_argument{"HTTPS must be enabled before forcing HTTPS"};
    }
    checked_u32(
        site.backend_max_active_connections, 1, 100000,
        "backend maximum active connections");
    checked_u32(site.backend_max_queue, 0, 1000000, "backend maximum queue");
    checked_u32(site.backend_queue_timeout_seconds, 1, 86400, "backend queue timeout");
    checked_u32(site.backend_connect_timeout_seconds, 1, 86400, "backend connect timeout");
    checked_u32(site.backend_response_timeout_seconds, 1, 86400, "backend response timeout");

    std::transform(site.backend_protocol.begin(), site.backend_protocol.end(),
        site.backend_protocol.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
    if (site.backend_protocol != "http" && site.backend_protocol != "https") {
        throw std::invalid_argument{"backend protocol must be http or https"};
    }

    boost::system::error_code address_error;
    static_cast<void>(boost::asio::ip::make_address(site.backend_address, address_error));
    if (address_error) {
        const auto normalized = routing::HostNormalizer::normalize_domain(site.backend_address);
        if (!normalized) {
            throw std::invalid_argument{"backend address must be an IP address or DNS hostname"};
        }
        site.backend_address = *normalized;
    }
    if (!site.backend_host.empty() &&
        !routing::HostNormalizer::normalize_authority(site.backend_host)) {
        throw std::invalid_argument{"invalid backend Host"};
    }
    if (!site.backend_tls_sni.empty()) {
        const auto normalized = routing::HostNormalizer::normalize_domain(site.backend_tls_sni);
        if (!normalized) throw std::invalid_argument{"invalid backend TLS SNI"};
        site.backend_tls_sni = *normalized;
    }
    if (site.backend_protocol == "http" && !site.backend_tls_sni.empty()) {
        throw std::invalid_argument{"backend TLS SNI requires HTTPS protocol"};
    }

    std::unordered_set<std::string> unique_domains;
    std::vector<std::string> normalized_domains;
    normalized_domains.reserve(site.domains.size());
    for (const auto& pattern : site.domains) {
        const bool wildcard = pattern.starts_with("*.");
        const auto domain = routing::HostNormalizer::normalize_domain(
            wildcard ? std::string_view{pattern}.substr(2) : std::string_view{pattern});
        if (!domain) {
            throw std::invalid_argument{"invalid site domain: " + pattern};
        }
        if (wildcard && domain->find('.') == std::string::npos) {
            throw std::invalid_argument{"wildcard domain is too broad: " + pattern};
        }
        const auto normalized = wildcard ? "*." + *domain : *domain;
        if (!unique_domains.emplace(normalized).second) {
            throw std::invalid_argument{"duplicate site domain: " + normalized};
        }
        normalized_domains.push_back(normalized);
    }
    site.domains = std::move(normalized_domains);

    try {
        canonicalize_json(site);
        const auto parsed_policy = runtime_policy(site);
        static_cast<void>(policy::RequestPolicy{parsed_policy, site.domains});
        static_cast<void>(policy::UrlAuthenticator{runtime_url_auth(site)});
    } catch (const nlohmann::json::exception&) {
        throw std::invalid_argument{"site policy contains invalid JSON"};
    }
}

policy::SitePolicySpec ConfigService::runtime_policy(const database::SiteRecord& site) {
    policy::SitePolicySpec result;
    result.force_https = site.force_https;
    result.https_port = site.https_port;
    result.acl_rules = parse_acl_rules(site.acl_rules_json);
    result.rate_limit.enabled = site.rate_limit_enabled;
    result.rate_limit.window_seconds = checked_u32(
        site.rate_limit_window_seconds, 1, 3600, "rate limit window");
    result.rate_limit.max_requests = checked_u32(
        site.rate_limit_max_requests, 1, 1000000, "rate limit maximum");
    result.rate_limit.ban_seconds = checked_u32(
        site.rate_limit_ban_seconds, 0, 86400, "rate limit ban");
    result.hotlink.enabled = site.hotlink_enabled;
    result.hotlink.protected_extensions = parse_string_array(
        site.hotlink_extensions_json, "hotlink extensions", 50);
    result.hotlink.allowed_hosts = parse_string_array(
        site.hotlink_allowed_hosts_json, "hotlink allowed hosts", 100);
    result.hotlink.allow_empty_referer = site.hotlink_allow_empty_referer;
    result.hotlink.redirect_location = site.hotlink_redirect_location;
    result.redirects = parse_redirect_rules(site.redirect_rules_json);
    return result;
}

policy::UrlAuthSpec ConfigService::runtime_url_auth(const database::SiteRecord& site) {
    return parse_url_auth(site.url_auth_json);
}

} // namespace webserver::config
