#include "admin/AdminApi.hpp"

#include "admin/AuthService.hpp"
#include "config/ConfigService.hpp"
#include "core/ConnectionRegistry.hpp"
#include "database/ConfigRepository.hpp"
#include "logging/LogManager.hpp"
#include "proxy/BackendConcurrencyLimiter.hpp"
#include "proxy/BackendProbe.hpp"
#include "routing/HostNormalizer.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/beast/http/field.hpp>
#include <boost/beast/http/status.hpp>
#include <boost/beast/http/verb.hpp>
#include <nlohmann/json.hpp>

#include <charconv>
#include <cctype>
#include <deque>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>

namespace webserver::admin {
namespace http = boost::beast::http;
using json = nlohmann::json;

namespace {

AdminApi::Response json_response(
    const AdminApi::Request& request,
    http::status status,
    const json& body) {
    AdminApi::Response response{status, request.version()};
    response.set(http::field::content_type, "application/json; charset=utf-8");
    response.set(http::field::cache_control, "no-store");
    response.set("X-Content-Type-Options", "nosniff");
    response.set("Referrer-Policy", "no-referrer");
    response.keep_alive(request.keep_alive());
    response.body() = body.dump();
    response.prepare_payload();
    return response;
}

AdminApi::Response configuration_response(
    const AdminApi::Request& request,
    std::string body) {
    AdminApi::Response response{http::status::ok, request.version()};
    response.set(http::field::content_type, "application/json; charset=utf-8");
    response.set("Content-Disposition", "attachment; filename=webserver-config-backup.json");
    response.set(http::field::cache_control, "no-store");
    response.set("X-Content-Type-Options", "nosniff");
    response.keep_alive(request.keep_alive());
    response.body() = std::move(body);
    response.prepare_payload();
    return response;
}

std::string request_path(const AdminApi::Request& request) {
    const auto target = request.target();
    const auto query = target.find('?');
    const auto path = target.substr(0, query);
    return std::string{path.data(), path.size()};
}

std::string percent_decode(std::string_view value) {
    std::string result;
    result.reserve(value.size());
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (value[index] == '+') {
            result.push_back(' ');
        } else if (value[index] == '%' && index + 2 < value.size()) {
            unsigned decoded{};
            const auto [end, error] = std::from_chars(
                value.data() + index + 1, value.data() + index + 3, decoded, 16);
            if (error == std::errc{} && end == value.data() + index + 3) {
                result.push_back(static_cast<char>(decoded));
                index += 2;
            } else {
                result.push_back(value[index]);
            }
        } else {
            result.push_back(value[index]);
        }
    }
    return result;
}

std::unordered_map<std::string, std::string> query_parameters(const AdminApi::Request& request) {
    std::unordered_map<std::string, std::string> result;
    const auto target = request.target();
    const auto query = target.find('?');
    if (query == boost::beast::string_view::npos) return result;
    std::string_view remaining{target.data() + query + 1, target.size() - query - 1};
    while (!remaining.empty()) {
        const auto ampersand = remaining.find('&');
        const auto part = remaining.substr(0, ampersand);
        const auto equals = part.find('=');
        result[percent_decode(part.substr(0, equals))] =
            equals == std::string_view::npos ? std::string{} : percent_decode(part.substr(equals + 1));
        if (ampersand == std::string_view::npos) break;
        remaining.remove_prefix(ampersand + 1);
    }
    return result;
}

std::string lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return value;
}

bool contains_folded(const json& item, std::string_view field, const std::string& needle) {
    if (needle.empty()) return true;
    const auto found = item.find(std::string{field});
    if (found == item.end() || !found->is_string()) return false;
    return lower(found->get<std::string>()).find(lower(needle)) != std::string::npos;
}

std::string session_token(const AdminApi::Request& request) {
    const auto cookie = request[http::field::cookie];
    constexpr std::string_view name = "ws_admin_session=";
    std::string_view remaining{cookie.data(), cookie.size()};
    while (!remaining.empty()) {
        const auto separator = remaining.find(';');
        auto part = remaining.substr(0, separator);
        while (!part.empty() && part.front() == ' ') {
            part.remove_prefix(1);
        }
        if (part.starts_with(name)) {
            return std::string{part.substr(name.size())};
        }
        if (separator == std::string_view::npos) {
            break;
        }
        remaining.remove_prefix(separator + 1);
    }
    return {};
}

bool has_mutation_guard(const AdminApi::Request& request) {
    const auto value = request["X-WebServer-Admin"];
    return value == "1";
}

std::uint16_t parse_port(const json& source, std::string_view key, std::uint16_t fallback) {
    const std::string key_text{key};
    if (!source.contains(key_text)) {
        return fallback;
    }
    const auto value = source.at(key_text).get<int>();
    if (value <= 0 || value > std::numeric_limits<std::uint16_t>::max()) {
        throw std::invalid_argument{std::string{key} + " must be between 1 and 65535"};
    }
    return static_cast<std::uint16_t>(value);
}

std::uint32_t parse_u32(
    const json& source,
    std::string_view key,
    std::uint32_t fallback) {
    const std::string key_text{key};
    if (!source.contains(key_text)) {
        return fallback;
    }
    const auto value = source.at(key_text).get<std::int64_t>();
    if (value < 0 || value > std::numeric_limits<std::uint32_t>::max()) {
        throw std::invalid_argument{std::string{key} + " is out of range"};
    }
    return static_cast<std::uint32_t>(value);
}

database::SiteRecord parse_site(const json& source) {
    database::SiteRecord site;
    site.name = source.at("name").get<std::string>();
    site.enabled = source.value("enabled", true);
    site.domains = source.at("domains").get<std::vector<std::string>>();
    site.backend_address = source.at("backend_address").get<std::string>();
    site.backend_port = parse_port(source, "backend_port", 0);
    site.backend_protocol = lower(source.value("backend_protocol", std::string{"http"}));
    site.backend_host = source.value("backend_host", std::string{});
    site.backend_tls_sni = source.value("backend_tls_sni", std::string{});
    site.backend_tls_verify_certificate = source.value("backend_tls_verify_certificate", true);
    site.backend_connect_timeout_seconds = parse_u32(
        source, "backend_connect_timeout_seconds", 5);
    site.backend_response_timeout_seconds = parse_u32(
        source, "backend_response_timeout_seconds", 60);
    site.backend_keep_alive = source.value("backend_keep_alive", true);
    site.url_auth_json = json{
        {"enabled", source.value("url_auth_enabled", false)},
        {"scope", source.value("url_auth_scope", std::string{"all"})},
        {"primary_key", source.value("url_auth_primary_key", std::string{})},
        {"backup_key", source.value("url_auth_backup_key", std::string{})},
        {"validity_seconds", parse_u32(source, "url_auth_validity_seconds", 1800)},
        {"protected_uris", source.value("url_auth_protected_uris", json::array())}}
        .dump();
    site.http_enabled = source.value("http_enabled", true);
    site.http_port = parse_port(source, "http_port", 80);
    site.https_enabled = source.value("https_enabled", false);
    site.https_port = parse_port(source, "https_port", 443);
    site.force_https = source.value("force_https", false);
    site.acl_rules_json = source.value("acl_rules", json::array()).dump();
    site.rate_limit_enabled = source.value("rate_limit_enabled", false);
    site.rate_limit_window_seconds = parse_u32(source, "rate_limit_window_seconds", 10);
    site.rate_limit_max_requests = parse_u32(source, "rate_limit_max_requests", 100);
    site.rate_limit_ban_seconds = parse_u32(source, "rate_limit_ban_seconds", 60);
    site.hotlink_enabled = source.value("hotlink_enabled", false);
    site.hotlink_extensions_json = source.value(
        "hotlink_extensions",
        json{"jpg", "jpeg", "png", "gif", "webp", "mp4", "zip"}).dump();
    site.hotlink_allowed_hosts_json = source.value(
        "hotlink_allowed_hosts", json::array()).dump();
    site.hotlink_allow_empty_referer = source.value("hotlink_allow_empty_referer", true);
    site.hotlink_redirect_location = source.value(
        "hotlink_redirect_location", std::string{});
    site.redirect_rules_json = source.value("redirect_rules", json::array()).dump();
    site.backend_max_active_connections = parse_u32(
        source, "backend_max_active_connections", 200);
    site.backend_max_queue = parse_u32(source, "backend_max_queue", 1000);
    site.backend_queue_timeout_seconds = parse_u32(
        source, "backend_queue_timeout_seconds", 5);
    return site;
}

json site_json(const database::SiteRecord& site) {
    const auto url_auth = json::parse(site.url_auth_json);
    return json{
        {"id", site.id},
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
        {"url_auth_enabled", url_auth.value("enabled", false)},
        {"url_auth_scope", url_auth.value("scope", std::string{"all"})},
        {"url_auth_primary_key", url_auth.value("primary_key", std::string{})},
        {"url_auth_backup_key", url_auth.value("backup_key", std::string{})},
        {"url_auth_validity_seconds", url_auth.value("validity_seconds", 1800)},
        {"url_auth_protected_uris", url_auth.value("protected_uris", json::array())},
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
        {"backend_queue_timeout_seconds", site.backend_queue_timeout_seconds}};
}

std::optional<std::int64_t> site_id_from_path(std::string_view path) {
    constexpr std::string_view prefix = "/api/sites/";
    if (!path.starts_with(prefix)) {
        return std::nullopt;
    }
    path.remove_prefix(prefix.size());
    std::int64_t id{};
    const auto [end, error] = std::from_chars(path.data(), path.data() + path.size(), id);
    if (error != std::errc{} || end != path.data() + path.size() || id <= 0) {
        return std::nullopt;
    }
    return id;
}

std::optional<std::int64_t> certificate_id_from_path(std::string_view path) {
    constexpr std::string_view prefix = "/api/certificates/";
    if (!path.starts_with(prefix)) return std::nullopt;
    path.remove_prefix(prefix.size());
    std::int64_t id{};
    const auto [end, error] = std::from_chars(path.data(), path.data() + path.size(), id);
    if (error != std::errc{} || end != path.data() + path.size() || id <= 0) return std::nullopt;
    return id;
}

database::CertificateRecord parse_certificate(const json& source) {
    database::CertificateRecord certificate;
    certificate.name = source.at("name").get<std::string>();
    certificate.enabled = source.value("enabled", true);
    certificate.is_default = source.value("is_default", false);
    certificate.domains = source.at("domains").get<std::vector<std::string>>();
    certificate.certificate_pem = source.value("certificate_pem", std::string{});
    certificate.private_key_pem = source.value("private_key_pem", std::string{});
    return certificate;
}

json certificate_json(const database::CertificateRecord& certificate) {
    return json{{"id", certificate.id},
                {"name", certificate.name},
                {"enabled", certificate.enabled},
                {"is_default", certificate.is_default},
                {"domains", certificate.domains},
                {"certificate_pem", certificate.certificate_pem},
                {"has_private_key", !certificate.private_key_pem.empty()}};
}

json settings_json(const database::RuntimeSettingsRecord& settings) {
    return json{{"trusted_proxy_cidrs", settings.trusted_proxy_cidrs},
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
                {"backend_idle_connection_ttl_seconds", settings.backend_idle_connection_ttl_seconds}};
}

database::RuntimeSettingsRecord parse_settings(const json& source) {
    database::RuntimeSettingsRecord settings;
    settings.trusted_proxy_cidrs = source.value(
        "trusted_proxy_cidrs", std::vector<std::string>{});
    settings.real_ip_headers = source.value(
        "real_ip_headers",
        std::vector<std::string>{
            "EO-Connecting-IP", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For"});
    settings.max_upload_bytes = source.value(
        "max_upload_bytes", 64ULL * 1024ULL * 1024ULL);
    settings.backend_keep_alive = source.value("backend_keep_alive", true);
    settings.backend_pool_size = parse_u32(source, "backend_pool_size", 32);
    settings.client_header_timeout_seconds = parse_u32(source, "client_header_timeout_seconds", 15);
    settings.client_body_timeout_seconds = parse_u32(source, "client_body_timeout_seconds", 120);
    settings.client_write_timeout_seconds = parse_u32(source, "client_write_timeout_seconds", 60);
    settings.backend_connect_timeout_seconds = parse_u32(source, "backend_connect_timeout_seconds", 5);
    settings.backend_response_timeout_seconds = parse_u32(source, "backend_response_timeout_seconds", 60);
    settings.backend_idle_timeout_seconds = parse_u32(source, "backend_idle_timeout_seconds", 60);
    settings.backend_idle_connection_ttl_seconds = parse_u32(
        source, "backend_idle_connection_ttl_seconds", 60);
    return settings;
}

routing::BackendConfig parse_backend_probe(const json& payload) {
    auto backend = routing::BackendConfig{};
    backend.address = payload.at("backend_address").get<std::string>();
    backend.port = parse_port(payload, "backend_port", 0);
    const auto protocol = lower(payload.value("backend_protocol", std::string{"http"}));
    if (protocol != "http" && protocol != "https") {
        throw std::invalid_argument{"backend protocol must be http or https"};
    }
    backend.protocol = protocol == "https"
                           ? routing::BackendProtocol::https
                           : routing::BackendProtocol::http;
    backend.host = payload.value("backend_host", std::string{});
    backend.tls_sni = payload.value("backend_tls_sni", std::string{});
    backend.tls_verify_certificate = payload.value(
        "backend_tls_verify_certificate", true);
    backend.connect_timeout_seconds = parse_u32(
        payload, "backend_connect_timeout_seconds", 5);
    if (backend.connect_timeout_seconds == 0 ||
        backend.connect_timeout_seconds > 86400) {
        throw std::invalid_argument{
            "backend connect timeout must be between 1 and 86400 seconds"};
    }
    boost::system::error_code address_error;
    static_cast<void>(boost::asio::ip::make_address(backend.address, address_error));
    if (address_error && !routing::HostNormalizer::normalize_domain(backend.address)) {
        throw std::invalid_argument{"backend address must be an IP address or DNS hostname"};
    }
    if (!backend.host.empty() &&
        !routing::HostNormalizer::normalize_authority(backend.host)) {
        throw std::invalid_argument{"invalid backend Host"};
    }
    if (!backend.tls_sni.empty() &&
        !routing::HostNormalizer::normalize_domain(backend.tls_sni)) {
        throw std::invalid_argument{"invalid backend TLS SNI"};
    }
    if (backend.protocol == routing::BackendProtocol::http && !backend.tls_sni.empty()) {
        throw std::invalid_argument{"backend TLS SNI requires HTTPS protocol"};
    }
    return backend;
}

AdminApi::Response backend_probe_response(
    const AdminApi::Request& request,
    const proxy::BackendProbeResult& result) {
    return json_response(request, http::status::ok, json{
        {"success", result.success},
        {"protocol", result.protocol},
        {"remote_address", result.remote_address},
        {"remote_port", result.remote_port},
        {"latency_ms", result.latency_ms},
        {"tls_verified", result.tls_verified},
        {"error", result.error}});
}

} // namespace

AdminApi::AdminApi(
    config::ConfigService& config_service,
    AuthService& auth_service,
    std::shared_ptr<logging::LogManager> logger,
    std::function<std::vector<core::ListenerStatus>()> listener_status_provider)
    : config_service_(config_service),
      auth_service_(auth_service),
      logger_(std::move(logger)),
      listener_status_provider_(std::move(listener_status_provider)),
      started_at_(std::chrono::steady_clock::now()) {}

AdminApi::Response AdminApi::handle(const Request& request, std::string_view remote_ip) {
    const auto path = request_path(request);

    try {
        if (request.method() == http::verb::get && path == "/api/auth/setup-state") {
            return json_response(
                request,
                http::status::ok,
                json{{"setup_required", auth_service_.setup_required()}});
        }

        if (request.method() == http::verb::post &&
            (path == "/api/auth/setup" || path == "/api/auth/login")) {
            if (!has_mutation_guard(request)) {
                return json_response(
                    request,
                    http::status::forbidden,
                    json{{"error", "missing admin request guard"}});
            }
            const auto payload = json::parse(request.body());
            const auto username = payload.at("username").get<std::string>();
            const auto password = payload.at("password").get<std::string>();
            std::string token;
            if (path == "/api/auth/setup") {
                token = auth_service_.create_first_admin(username, password, remote_ip);
            } else {
                try {
                    token = auth_service_.login(username, password, remote_ip);
                } catch (const std::invalid_argument&) {
                    return json_response(
                        request,
                        http::status::unauthorized,
                        json{{"error", "invalid username or password"}});
                }
            }
            auto response = json_response(
                request, http::status::ok, json{{"authenticated", true}});
            response.set(http::field::set_cookie, AuthService::session_cookie(token));
            return response;
        }

        const auto token = session_token(request);
        if (!auth_service_.authorize(token)) {
            return json_response(
                request,
                http::status::unauthorized,
                json{{"error", "authentication required"}});
        }
        return handle_authenticated(request, path, token);
    } catch (const nlohmann::json::exception&) {
        return json_response(
            request, http::status::bad_request, json{{"error", "invalid JSON request"}});
    } catch (const std::invalid_argument& error) {
        return json_response(
            request, http::status::bad_request, json{{"error", error.what()}});
    } catch (const std::logic_error& error) {
        return json_response(
            request, http::status::conflict, json{{"error", error.what()}});
    } catch (const std::runtime_error& error) {
        const std::string_view message{error.what()};
        const auto status = message.starts_with("too many login attempts")
                                ? http::status::too_many_requests
                                : http::status::conflict;
        return json_response(request, status, json{{"error", error.what()}});
    }
}

std::shared_ptr<proxy::BackendProbeOperation> AdminApi::handle_async(
    Request request,
    std::string remote_ip,
    boost::asio::any_io_executor executor,
    ResponseHandler completion,
    FailureHandler failure) {
    if (!completion) {
        throw std::invalid_argument{"admin response handler cannot be empty"};
    }
    const auto path = request_path(request);
    if (request.method() != http::verb::post || path != "/api/backends/test") {
        completion(handle(request, remote_ip));
        return {};
    }

    try {
        const auto token = session_token(request);
        if (!auth_service_.authorize(token)) {
            completion(json_response(
                request,
                http::status::unauthorized,
                json{{"error", "authentication required"}}));
            return {};
        }
        if (!has_mutation_guard(request)) {
            completion(json_response(
                request,
                http::status::forbidden,
                json{{"error", "missing admin request guard"}}));
            return {};
        }
        auto backend = parse_backend_probe(json::parse(request.body()));
        return proxy::async_probe_backend(
            std::move(backend),
            std::move(executor),
            [request, completion, failure = std::move(failure)](
                proxy::BackendProbeResult result) mutable noexcept {
                try {
                    completion(backend_probe_response(request, result));
                } catch (...) {
                    if (failure) {
                        try {
                            failure();
                        } catch (...) {
                        }
                    }
                }
            });
    } catch (const nlohmann::json::exception&) {
        completion(json_response(
            request, http::status::bad_request, json{{"error", "invalid JSON request"}}));
    } catch (const std::invalid_argument& error) {
        completion(json_response(
            request, http::status::bad_request, json{{"error", error.what()}}));
    } catch (const std::logic_error& error) {
        completion(json_response(
            request, http::status::conflict, json{{"error", error.what()}}));
    } catch (const std::runtime_error& error) {
        completion(json_response(
            request, http::status::conflict, json{{"error", error.what()}}));
    }
    return {};
}

AdminApi::Response AdminApi::handle_authenticated(
    const Request& request,
    std::string_view path,
    std::string_view token) {
    if (request.method() == http::verb::post && path == "/api/auth/logout") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        auth_service_.logout(token);
        auto response = json_response(
            request, http::status::ok, json{{"authenticated", false}});
        response.set(http::field::set_cookie, AuthService::expired_session_cookie());
        return response;
    }

    if (request.method() == http::verb::get && path == "/api/status") {
        const auto sites = config_service_.list_sites();
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started_at_);
        return json_response(
            request,
            http::status::ok,
            json{{"uptime_seconds", uptime.count()},
                 {"site_count", sites.size()},
                 {"active_revision", config_service_.active_revision()},
                 {"stored_revision", config_service_.stored_revision()},
                 {"restart_required", config_service_.restart_required()},
                 {"hot_reload_enabled", config_service_.hot_reload_enabled()}});
    }

    if (request.method() == http::verb::get && path == "/api/listeners") {
        json listeners = json::array();
        if (listener_status_provider_) {
            for (const auto& listener : listener_status_provider_()) {
                listeners.push_back(json{
                    {"protocol", listener.protocol},
                    {"address", listener.address},
                    {"configured_port", listener.configured_port},
                    {"bound_port", listener.bound_port},
                    {"site_count", listener.site_count},
                    {"status", listener.status}});
            }
        }
        return json_response(request, http::status::ok, json{{"listeners", std::move(listeners)}});
    }

    if (request.method() == http::verb::get && path == "/api/connections") {
        auto& registry = core::ConnectionRegistry::instance();
        const auto total = registry.size();
        json connections = json::array();
        for (const auto& connection : registry.snapshot()) {
            connections.push_back(json{
                {"id", connection.id},
                {"protocol", connection.protocol},
                {"source_address", connection.source_address},
                {"connected_at_unix_ms", connection.connected_at_unix_ms},
                {"connected_seconds", connection.connected_seconds},
                {"status", connection.status},
                {"method", connection.method},
                {"url", connection.url},
                {"referer", connection.referer}});
        }
        return json_response(
            request,
            http::status::ok,
            json{{"connections", std::move(connections)}, {"total", total}});
    }

    if (request.method() == http::verb::get && path == "/api/http-connections") {
        std::optional<std::int64_t> site_id;
        const auto parameters = query_parameters(request);
        if (const auto found = parameters.find("site_id");
            found != parameters.end() && !found->second.empty()) {
            std::int64_t parsed{};
            const auto* begin = found->second.data();
            const auto* end = begin + found->second.size();
            const auto [position, error] = std::from_chars(begin, end, parsed);
            if (error != std::errc{} || position != end || parsed <= 0) {
                throw std::invalid_argument{"site_id must be a positive integer"};
            }
            site_id = parsed;
        }

        auto& registry = core::HttpRequestRegistry::instance();
        const auto total = registry.size(site_id);
        json connections = json::array();
        for (const auto& connection : registry.snapshot(site_id)) {
            connections.push_back(json{
                {"id", connection.id},
                {"site_id", connection.site_id},
                {"site_name", connection.site_name},
                {"host", connection.host},
                {"protocol", connection.protocol},
                {"client_ip", connection.client_ip},
                {"connected_at_unix_ms", connection.connected_at_unix_ms},
                {"connected_seconds", connection.connected_seconds},
                {"status", connection.status},
                {"method", connection.method},
                {"url", connection.url},
                {"referer", connection.referer}});
        }
        return json_response(
            request,
            http::status::ok,
            json{{"connections", std::move(connections)}, {"total", total}});
    }

    if (request.method() == http::verb::get && path == "/api/backends/metrics") {
        json metrics = json::array();
        std::unordered_map<std::int64_t, proxy::BackendConcurrencyMetrics> live;
        for (auto item : proxy::BackendConcurrencyLimiter::instance().metrics()) {
            live.emplace(item.site_id, std::move(item));
        }
        for (const auto& site : config_service_.list_sites()) {
            const auto found = live.find(site.id);
            const auto active = found == live.end() ? 0ULL : found->second.active_connections;
            const auto queued = found == live.end() ? 0ULL : found->second.queue_length;
            const auto rejected = found == live.end() ? 0ULL : found->second.rejected_requests;
            const auto timeouts = found == live.end() ? 0ULL : found->second.queue_timeouts;
            metrics.push_back(json{
                {"site_id", site.id},
                {"site_name", site.name},
                {"backend", site.backend_protocol + "://" + site.backend_address + ':' +
                                std::to_string(site.backend_port)},
                {"maximum_active", site.backend_max_active_connections},
                {"maximum_queue", site.backend_max_queue},
                {"queue_timeout_seconds", site.backend_queue_timeout_seconds},
                {"active_connections", active},
                {"queue_length", queued},
                {"rejected_requests", rejected},
                {"queue_timeouts", timeouts}});
        }
        return json_response(request, http::status::ok, json{{"backends", std::move(metrics)}});
    }

    if (request.method() == http::verb::get && path == "/api/config/backup") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        return configuration_response(request, config_service_.export_configuration());
    }
    if (request.method() == http::verb::post && path == "/api/config/restore") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        config_service_.import_configuration(request.body());
        return json_response(
            request,
            http::status::ok,
            json{{"restored", true}, {"active_revision", config_service_.active_revision()}});
    }

    if (request.method() == http::verb::get &&
        (path == "/api/logs/access" || path == "/api/logs/error")) {
        if (!logger_) {
            return json_response(
                request, http::status::service_unavailable, json{{"error", "logging is unavailable"}});
        }
        const auto parameters = query_parameters(request);
        std::size_t limit = 100;
        if (const auto found = parameters.find("limit"); found != parameters.end()) {
            const auto [end, error] = std::from_chars(
                found->second.data(), found->second.data() + found->second.size(), limit);
            if (error != std::errc{} || end != found->second.data() + found->second.size() ||
                (limit != 100 && limit != 500 && limit != 1000)) {
                throw std::invalid_argument{"log limit must be 100, 500, or 1000"};
            }
        }
        const bool access = path == "/api/logs/access";
        const auto value = [&parameters](std::string_view key) -> std::string {
            const auto found = parameters.find(std::string{key});
            return found == parameters.end() ? std::string{} : found->second;
        };
        std::deque<json> matches;
        for (const auto& line : logger_->recent_lines(
                 access ? logging::LogKind::access : logging::LogKind::error)) {
            const auto item = json::parse(line, nullptr, false);
            if (item.is_discarded() || !item.is_object()) continue;
            bool matched{};
            if (access) {
                matched = contains_folded(item, "host", value("host")) &&
                          contains_folded(item, "client_ip", value("ip")) &&
                          contains_folded(item, "request_id", value("request_id")) &&
                          contains_folded(item, "path", value("path"));
                if (matched && !value("status").empty()) {
                    unsigned requested_status{};
                    const auto status_text = value("status");
                    const auto [end, error] = std::from_chars(
                        status_text.data(), status_text.data() + status_text.size(), requested_status);
                    if (error != std::errc{} || end != status_text.data() + status_text.size()) {
                        throw std::invalid_argument{"status filter must be numeric"};
                    }
                    matched = item.value("status", 0U) == requested_status;
                }
            } else {
                const auto level = value("level");
                matched = (level.empty() || item.value("level", std::string{}) == level) &&
                          contains_folded(item, "request_id", value("request_id")) &&
                          (contains_folded(item, "component", value("search")) ||
                           contains_folded(item, "message", value("search")));
            }
            if (!matched) continue;
            matches.push_back(item);
            if (matches.size() > limit) matches.pop_front();
        }
        json entries = json::array();
        for (auto iterator = matches.rbegin(); iterator != matches.rend(); ++iterator) {
            entries.push_back(std::move(*iterator));
        }
        return json_response(request, http::status::ok, json{{"entries", std::move(entries)}});
    }

    if (request.method() == http::verb::post && path == "/api/runtime/reload") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        config_service_.reload_runtime();
        return json_response(
            request,
            http::status::ok,
            json{{"reloaded", true}, {"active_revision", config_service_.active_revision()}});
    }

    if (request.method() == http::verb::get && path == "/api/sites") {
        json sites = json::array();
        for (const auto& site : config_service_.list_sites()) {
            sites.push_back(site_json(site));
        }
        return json_response(request, http::status::ok, json{{"sites", std::move(sites)}});
    }

    if (request.method() == http::verb::post && path == "/api/backends/test") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        const auto backend = parse_backend_probe(json::parse(request.body()));
        const auto result = proxy::probe_backend(backend);
        return backend_probe_response(request, result);
    }

    if (request.method() == http::verb::get && path == "/api/certificates") {
        json certificates = json::array();
        for (const auto& certificate : config_service_.list_certificates()) {
            certificates.push_back(certificate_json(certificate));
        }
        return json_response(
            request, http::status::ok, json{{"certificates", std::move(certificates)}});
    }

    if (request.method() == http::verb::post && path == "/api/certificates") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        const auto certificate = config_service_.create_certificate(
            parse_certificate(json::parse(request.body())));
        return json_response(request, http::status::created, certificate_json(certificate));
    }

    const auto certificate_id = certificate_id_from_path(path);
    if (certificate_id && request.method() == http::verb::put) {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        auto certificate = parse_certificate(json::parse(request.body()));
        certificate.id = *certificate_id;
        const auto current = config_service_.find_certificate(*certificate_id);
        if (certificate.certificate_pem.empty()) {
            certificate.certificate_pem = current.certificate_pem;
        }
        if (certificate.private_key_pem.empty()) {
            certificate.private_key_pem = current.private_key_pem;
        }
        return json_response(
            request,
            http::status::ok,
            certificate_json(config_service_.update_certificate(std::move(certificate))));
    }
    if (certificate_id && request.method() == http::verb::delete_) {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        config_service_.delete_certificate(*certificate_id);
        return json_response(request, http::status::ok, json{{"deleted", true}});
    }

    if (request.method() == http::verb::get && path == "/api/settings") {
        return json_response(request, http::status::ok, settings_json(config_service_.runtime_settings()));
    }
    if (request.method() == http::verb::put && path == "/api/settings") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        return json_response(
            request,
            http::status::ok,
            settings_json(config_service_.update_runtime_settings(
                parse_settings(json::parse(request.body())))));
    }

    if (request.method() == http::verb::post && path == "/api/sites") {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        const auto site = config_service_.create_site(parse_site(json::parse(request.body())));
        return json_response(request, http::status::created, site_json(site));
    }

    const auto id = site_id_from_path(path);
    if (id && request.method() == http::verb::put) {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        auto site = parse_site(json::parse(request.body()));
        site.id = *id;
        return json_response(
            request, http::status::ok, site_json(config_service_.update_site(std::move(site))));
    }
    if (id && request.method() == http::verb::delete_) {
        if (!has_mutation_guard(request)) {
            return json_response(
                request, http::status::forbidden, json{{"error", "missing admin request guard"}});
        }
        config_service_.delete_site(*id);
        return json_response(request, http::status::ok, json{{"deleted", true}});
    }

    return json_response(
        request, http::status::not_found, json{{"error", "admin API endpoint not found"}});
}

} // namespace webserver::admin
