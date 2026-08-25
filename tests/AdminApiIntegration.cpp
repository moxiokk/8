#include "admin/AdminServer.hpp"
#include "admin/AuthService.hpp"
#include "config/ConfigService.hpp"
#include "core/ConnectionRegistry.hpp"
#include "database/ConfigRepository.hpp"
#include "database/Database.hpp"
#include "logging/LogManager.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http/read.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/write.hpp>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <exception>
#include <future>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
using tcp = asio::ip::tcp;
using json = nlohmann::json;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

class StalledTlsBackend final {
public:
    StalledTlsBackend()
        : acceptor_(io_context_, tcp::endpoint{asio::ip::address_v4::loopback(), 0}),
          socket_(io_context_),
          worker_([this] {
              boost::system::error_code error;
              acceptor_.accept(socket_, error);
              if (error) return;
              accepted_.store(true, std::memory_order_release);
              std::array<char, 1024> input{};
              while (socket_.read_some(asio::buffer(input), error) != 0 && !error) {
              }
          }) {}

    ~StalledTlsBackend() {
        boost::system::error_code ignored;
        socket_.close(ignored);
        acceptor_.close(ignored);
        if (worker_.joinable()) worker_.join();
    }

    [[nodiscard]] tcp::endpoint endpoint() const { return acceptor_.local_endpoint(); }

    void wait_until_accepted() const {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
        while (!accepted_.load(std::memory_order_acquire) &&
               std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
        require(accepted_.load(std::memory_order_acquire),
                "stalled TLS backend did not accept the probe connection");
    }

private:
    asio::io_context io_context_;
    tcp::acceptor acceptor_;
    tcp::socket socket_;
    std::atomic_bool accepted_{false};
    std::thread worker_;
};

std::filesystem::path unique_database_path() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    return std::filesystem::temp_directory_path() /
           ("webserver-admin-test-" + std::to_string(stamp) + ".db");
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

http::response<http::string_body> send(
    const tcp::endpoint& endpoint,
    http::verb method,
    const std::string& target,
    const std::string& body = {},
    const std::string& cookie = {},
    bool mutation_guard = false) {
    asio::io_context io_context;
    beast::tcp_stream stream{io_context};
    stream.connect(endpoint);

    http::request<http::string_body> request{method, target, 11};
    request.set(http::field::host, "127.0.0.1");
    if (!body.empty()) {
        request.set(http::field::content_type, "application/json");
        request.body() = body;
        request.prepare_payload();
    }
    if (!cookie.empty()) request.set(http::field::cookie, cookie);
    if (mutation_guard) request.set("X-WebServer-Admin", "1");
    request.keep_alive(false);
    http::write(stream, request);

    beast::flat_buffer buffer;
    http::response<http::string_body> response;
    http::read(stream, buffer, response);
    return response;
}

std::string cookie_from(const http::response<http::string_body>& response) {
    const auto header = response[http::field::set_cookie];
    const std::string value{header.data(), header.size()};
    return value.substr(0, value.find(';'));
}

void run_test(
    const std::filesystem::path& static_root,
    const std::filesystem::path& certificate_path,
    const std::filesystem::path& private_key_path) {
    require(
        std::filesystem::exists(static_root / "index.html"),
        "built Vue admin assets are missing");
    const auto database_path = unique_database_path();
    const auto log_directory = std::filesystem::path{database_path.string() + ".logs"};

    try {
        webserver::database::Database database{database_path};
        webserver::database::ConfigRepository repository{database};
        webserver::config::ConfigService config_service{repository};
        config_service.initialize();
        config_service.seed_default_certificate(
            "example.com test certificate",
            {"example.com", "www.example.com"},
            read_text_file(certificate_path),
            read_text_file(private_key_path));
        std::uint64_t published_revision = 0;
        config_service.set_reload_handler(
            [&published_revision](
                webserver::config::RuntimeConfigSpec spec) {
                return [&published_revision, revision = spec.revision]() noexcept {
                    published_revision = revision;
                };
            });
        webserver::admin::AuthService auth_service{repository};
        auto logger = std::make_shared<webserver::logging::LogManager>(
            webserver::logging::LogOptions{log_directory});
        webserver::logging::AccessLogEntry access_entry;
        access_entry.request_id = "admin-log-query-request";
        access_entry.client_ip = "198.51.100.12";
        access_entry.host = "logs.test";
        access_entry.method = "GET";
        access_entry.path = "/health";
        access_entry.status = 200;
        access_entry.duration = std::chrono::microseconds{23000};
        logger->log_access(std::move(access_entry));
        logger->log_error(
            webserver::logging::ErrorSeverity::warning,
            "admin_api_test",
            "filterable warning",
            "admin-log-query-request");
        logger->flush();
        webserver::admin::AdminServer server{
            config_service, auth_service, static_root, 0, logger};
        server.start();
        const auto endpoint = server.local_endpoint();

        std::promise<void> admin_worker_resumed;
        auto admin_worker_resumed_future = admin_worker_resumed.get_future();
        asio::post(server.io_context(), [] {
            throw std::runtime_error{"intentional admin-handler failure"};
        });
        asio::post(server.io_context(), [&admin_worker_resumed] {
            admin_worker_resumed.set_value();
        });
        require(
            admin_worker_resumed_future.wait_for(std::chrono::seconds{2}) ==
                std::future_status::ready,
            "Admin worker did not resume after a handler exception");

        const auto index = send(endpoint, http::verb::get, "/");
        require(index.result() == http::status::ok, "admin index did not return 200");
        require(
            index[http::field::content_type].starts_with("text/html"),
            "admin index has wrong content type");

        const auto setup_state = send(endpoint, http::verb::get, "/api/auth/setup-state");
        require(
            json::parse(setup_state.body()).at("setup_required").get<bool>(),
            "first-run setup was not required");

        const auto setup = send(
            endpoint,
            http::verb::post,
            "/api/auth/setup",
            R"({"username":"admin","password":"correct horse battery staple"})",
            {},
            true);
        require(setup.result() == http::status::ok, "administrator setup failed");
        const auto cookie = cookie_from(setup);
        require(cookie.starts_with("ws_admin_session="), "setup did not issue a session cookie");

        const auto access_logs = send(
            endpoint, http::verb::get,
            "/api/logs/access?limit=100&host=logs.test&status=200&path=%2Fhealth", {}, cookie);
        require(
            access_logs.result() == http::status::ok &&
                json::parse(access_logs.body()).at("entries").size() == 1 &&
                json::parse(access_logs.body()).at("entries").at(0).at("request_id") ==
                    "admin-log-query-request",
            "access log query API did not filter structured logs");
        const auto error_logs = send(
            endpoint, http::verb::get,
            "/api/logs/error?limit=100&level=warning&search=filterable", {}, cookie);
        require(
            error_logs.result() == http::status::ok &&
                json::parse(error_logs.body()).at("entries").size() == 1,
            "error log query API did not filter warning events");

        const auto listeners = send(endpoint, http::verb::get, "/api/listeners", {}, cookie);
        require(
            listeners.result() == http::status::ok &&
                json::parse(listeners.body()).at("listeners").is_array(),
            "listener status API failed");
        auto& connection_registry = webserver::core::ConnectionRegistry::instance();
        connection_registry.clear();
        const auto connection_id = connection_registry.add(
            "HTTPS", "203.0.113.7:51820", "TLS Handshake");
        connection_registry.update_request(
            connection_id,
            "POST",
            "/upload/video.mp4?part=1",
            "https://portal.test/videos",
            "Proxying");
        const auto connections = send(
            endpoint, http::verb::get, "/api/connections", {}, cookie);
        const auto connections_json = json::parse(connections.body()).at("connections");
        require(
            connections.result() == http::status::ok && connections_json.size() == 1 &&
                json::parse(connections.body()).at("total") == 1 &&
                connections_json.at(0).at("source_address") == "203.0.113.7:51820" &&
                connections_json.at(0).at("method") == "POST" &&
                connections_json.at(0).at("url") == "/upload/video.mp4?part=1" &&
                connections_json.at(0).at("referer") == "https://portal.test/videos" &&
                connections_json.at(0).at("status") == "Proxying",
            "live connection information API failed");
        connection_registry.remove(connection_id);
        auto& http_registry = webserver::core::HttpRequestRegistry::instance();
        http_registry.clear();
        const auto seeded_site = config_service.list_sites().front();
        const auto http_connection_id = http_registry.add(
            "HTTPS",
            "203.0.113.7",
            "POST",
            "/upload/video.mp4?part=1",
            "https://portal.test/videos",
            "example.com",
            "Routing");
        http_registry.update_site(
            http_connection_id,
            seeded_site.id,
            seeded_site.name,
            "example.com",
            "Proxying");
        const auto other_http_connection_id = http_registry.add(
            "HTTP", "198.51.100.9", "GET", "/health", {}, "other.test", "Routing");
        http_registry.update_site(
            other_http_connection_id, seeded_site.id + 1000, "Other", "other.test", "Proxying");

        const auto http_connections = send(
            endpoint, http::verb::get, "/api/http-connections", {}, cookie);
        const auto http_connections_json = json::parse(http_connections.body());
        require(
            http_connections.result() == http::status::ok &&
                http_connections_json.at("total") == 2 &&
                http_connections_json.at("connections").size() == 2,
            "HTTP live connection API did not return the all-sites view");
        const auto filtered_http_connections = send(
            endpoint,
            http::verb::get,
            "/api/http-connections?site_id=" + std::to_string(seeded_site.id),
            {},
            cookie);
        const auto filtered_http_json = json::parse(filtered_http_connections.body());
        require(
            filtered_http_connections.result() == http::status::ok &&
                filtered_http_json.at("total") == 1 &&
                filtered_http_json.at("connections").at(0).at("site_id") == seeded_site.id &&
                filtered_http_json.at("connections").at(0).at("client_ip") == "203.0.113.7" &&
                filtered_http_json.at("connections").at(0).at("method") == "POST" &&
                filtered_http_json.at("connections").at(0).at("status") == "Proxying",
            "HTTP live connection API site filter or fields are incorrect");
        const auto invalid_http_filter = send(
            endpoint, http::verb::get, "/api/http-connections?site_id=invalid", {}, cookie);
        require(
            invalid_http_filter.result() == http::status::bad_request,
            "HTTP live connection API accepted an invalid site filter");
        http_registry.remove(http_connection_id);
        http_registry.remove(other_http_connection_id);
        const auto backend_metrics = send(
            endpoint, http::verb::get, "/api/backends/metrics", {}, cookie);
        require(
            backend_metrics.result() == http::status::ok &&
                json::parse(backend_metrics.body()).at("backends").size() == 1,
            "backend concurrency metrics API failed");
        const auto backup = send(endpoint, http::verb::get, "/api/config/backup", {}, cookie, true);
        const auto backup_json = json::parse(backup.body());
        require(
            backup.result() == http::status::ok &&
                backup_json.at("format") == "webserver-config-backup" &&
                backup_json.at("version") == 1 &&
                backup_json.at("sites").size() == 1 &&
                backup["Content-Disposition"].find("attachment") != boost::beast::string_view::npos,
            "configuration backup API failed");

        const auto status = send(endpoint, http::verb::get, "/api/status", {}, cookie);
        require(status.result() == http::status::ok, "authenticated status request failed");
        require(
            json::parse(status.body()).at("site_count").get<int>() == 1,
            "status returned wrong seeded site count");
        require(
            json::parse(status.body()).at("hot_reload_enabled").get<bool>(),
            "status did not report hot reload as enabled");

        const auto initial_settings = send(
            endpoint, http::verb::get, "/api/settings", {}, cookie);
        require(
            initial_settings.result() == http::status::ok &&
                json::parse(initial_settings.body()).at("backend_keep_alive").get<bool>() &&
                json::parse(initial_settings.body()).at("max_upload_bytes").get<std::uint64_t>() ==
                    64ULL * 1024ULL * 1024ULL,
            "runtime settings API did not return secure defaults");
        const auto settings_update = send(
            endpoint,
            http::verb::put,
            "/api/settings",
            R"({"trusted_proxy_cidrs":["127.0.0.0/8","2400:cb00::/32"],"real_ip_headers":["EO-Connecting-IP","CF-Connecting-IP","True-Client-IP","X-Forwarded-For"],"max_upload_bytes":134217728,"backend_keep_alive":true,"backend_pool_size":16,"client_header_timeout_seconds":20,"client_body_timeout_seconds":180,"client_write_timeout_seconds":90,"backend_connect_timeout_seconds":6,"backend_response_timeout_seconds":90,"backend_idle_timeout_seconds":75,"backend_idle_connection_ttl_seconds":45})",
            cookie,
            true);
        require(
            settings_update.result() == http::status::ok &&
                json::parse(settings_update.body()).at("trusted_proxy_cidrs").size() == 2 &&
                json::parse(settings_update.body()).at("backend_pool_size").get<int>() == 16 &&
                json::parse(settings_update.body()).at("client_body_timeout_seconds").get<int>() == 180 &&
                json::parse(settings_update.body()).at("real_ip_headers").at(0) == "EO-Connecting-IP",
            "runtime settings update API failed");

        const auto missing_guard = send(
            endpoint,
            http::verb::post,
            "/api/sites",
            R"({"name":"blocked"})",
            cookie,
            false);
        require(
            missing_guard.result() == http::status::forbidden,
            "state-changing API accepted a request without its guard header");

        const auto backend_probe = send(
            endpoint,
            http::verb::post,
            "/api/backends/test",
            R"({"backend_protocol":"http","backend_address":"127.0.0.1","backend_port":1,"backend_connect_timeout_seconds":1})",
            cookie,
            true);
        require(
            backend_probe.result() == http::status::ok &&
                !json::parse(backend_probe.body()).at("success").get<bool>(),
            "backend connection test API did not return a structured failure");

        StalledTlsBackend stalled_backend;
        const auto stalled_endpoint = stalled_backend.endpoint();
        std::optional<http::response<http::string_body>> stalled_probe_response;
        std::exception_ptr stalled_probe_failure;
        std::jthread stalled_probe([&] {
            try {
                stalled_probe_response.emplace(send(
                    endpoint,
                    http::verb::post,
                    "/api/backends/test",
                    json{{"backend_protocol", "https"},
                         {"backend_address", "127.0.0.1"},
                         {"backend_port", stalled_endpoint.port()},
                         {"backend_tls_verify_certificate", false},
                         {"backend_connect_timeout_seconds", 1}}
                        .dump(),
                    cookie,
                    true));
            } catch (...) {
                stalled_probe_failure = std::current_exception();
            }
        });
        stalled_backend.wait_until_accepted();
        const auto status_started = std::chrono::steady_clock::now();
        const auto status_during_probe = send(
            endpoint, http::verb::get, "/api/status", {}, cookie);
        const auto status_latency = std::chrono::steady_clock::now() - status_started;
        require(status_during_probe.result() == http::status::ok,
                "Admin did not serve status during a backend probe");
        require(status_latency < std::chrono::milliseconds{500},
                "backend probe blocked the Admin event-loop thread");
        stalled_probe.join();
        if (stalled_probe_failure) std::rethrow_exception(stalled_probe_failure);
        require(stalled_probe_response &&
                    stalled_probe_response->result() == http::status::ok &&
                    !json::parse(stalled_probe_response->body()).at("success").get<bool>(),
                "stalled backend probe did not time out with a structured failure");

        const auto created = send(
            endpoint,
            http::verb::post,
            "/api/sites",
            R"({"name":"API site","enabled":true,"domains":["api.test"],"backend_protocol":"https","backend_address":"origin.api.test","backend_port":443,"backend_host":"www.api.test","backend_tls_sni":"www.api.test","backend_tls_verify_certificate":true,"backend_connect_timeout_seconds":7,"backend_response_timeout_seconds":80,"backend_keep_alive":true,"url_auth_enabled":true,"url_auth_scope":"specified","url_auth_primary_key":"PrimaryKey123","url_auth_backup_key":"BackupKey123","url_auth_validity_seconds":900,"url_auth_protected_uris":[{"path":"/video/","match":"prefix"}],"http_enabled":true,"http_port":8081,"https_enabled":false,"https_port":443,"force_https":false,"acl_rules":[{"name":"Block internal Git","conditions":[{"field":"uri","operator":"contains","value":"/.git"},{"field":"ip","operator":"in_cidr","value":"192.168.0.0/16"}],"action":"deny","status":403}],"rate_limit_enabled":true,"rate_limit_window_seconds":10,"rate_limit_max_requests":100,"rate_limit_ban_seconds":60,"hotlink_enabled":true,"hotlink_extensions":["jpg","png"],"hotlink_allowed_hosts":["media.api.test"],"hotlink_allow_empty_referer":false,"hotlink_redirect_location":"","redirect_rules":[{"name":"Old path","source_path":"/old","match":"exact","destination":"/new","status":301,"preserve_query":true}],"backend_max_active_connections":25,"backend_max_queue":80,"backend_queue_timeout_seconds":9})",
            cookie,
            true);
        require(created.result() == http::status::created, "site create API failed");
        require(
            json::parse(created.body()).at("domains").at(0) == "api.test",
            "created site response is incorrect");
        const auto created_json = json::parse(created.body());
        require(
            created_json.at("acl_rules").size() == 1 &&
                created_json.at("acl_rules").at(0).at("conditions").at(1).at("operator") ==
                    "in_cidr" &&
                created_json.at("rate_limit_enabled").get<bool>() &&
                created_json.at("url_auth_enabled").get<bool>() &&
                created_json.at("url_auth_scope") == "specified" &&
                created_json.at("url_auth_validity_seconds") == 900 &&
                created_json.at("url_auth_protected_uris").size() == 1 &&
                created_json.at("hotlink_enabled").get<bool>() &&
                created_json.at("redirect_rules").size() == 1 &&
                created_json.at("backend_max_active_connections").get<int>() == 25 &&
                created_json.at("backend_max_queue").get<int>() == 80 &&
                created_json.at("backend_queue_timeout_seconds").get<int>() == 9 &&
                created_json.at("backend_protocol") == "https" &&
                created_json.at("backend_host") == "www.api.test" &&
                created_json.at("backend_tls_sni") == "www.api.test" &&
                created_json.at("backend_connect_timeout_seconds").get<int>() == 7 &&
                created_json.at("backend_response_timeout_seconds").get<int>() == 80,
            "site policy or upstream TLS fields were not returned by the Admin API");
        require(
            published_revision == config_service.stored_revision() &&
                !config_service.restart_required(),
            "site create API did not hot reload the stored revision");

        const auto reloaded = send(
            endpoint, http::verb::post, "/api/runtime/reload", {}, cookie, true);
        require(
            reloaded.result() == http::status::ok &&
                json::parse(reloaded.body()).at("reloaded").get<bool>(),
            "manual runtime reload API failed");

        const auto sites = send(endpoint, http::verb::get, "/api/sites", {}, cookie);
        require(
            json::parse(sites.body()).at("sites").size() == 2,
            "site list did not include persisted API update");

        const auto logout = send(
            endpoint, http::verb::post, "/api/auth/logout", {}, cookie, true);
        require(logout.result() == http::status::ok, "logout failed");
        const auto unauthorized = send(endpoint, http::verb::get, "/api/status", {}, cookie);
        require(
            unauthorized.result() == http::status::unauthorized,
            "logged-out session remained authorized");

        const auto bad_login = send(
            endpoint,
            http::verb::post,
            "/api/auth/login",
            R"({"username":"admin","password":"this password is wrong"})",
            {},
            true);
        require(
            bad_login.result() == http::status::unauthorized,
            "invalid credentials did not return 401");
        const auto login = send(
            endpoint,
            http::verb::post,
            "/api/auth/login",
            R"({"username":"admin","password":"correct horse battery staple"})",
            {},
            true);
        require(login.result() == http::status::ok, "valid login failed after logout");

        server.stop();
        server.wait();
    } catch (...) {
        remove_database_files(database_path);
        std::error_code ignored;
        std::filesystem::remove_all(log_directory, ignored);
        throw;
    }
    remove_database_files(database_path);
    std::error_code ignored;
    std::filesystem::remove_all(log_directory, ignored);
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 4) {
            throw std::invalid_argument{
                "expected admin asset directory, certificate and private key paths"};
        }
        run_test(argv[1], argv[2], argv[3]);
        std::cout << "Admin API integration tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Admin API integration tests failed: " << error.what() << '\n';
        return 1;
    }
}
