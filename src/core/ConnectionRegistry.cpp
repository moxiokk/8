#include "core/ConnectionRegistry.hpp"

#include <algorithm>
#include <utility>

namespace webserver::core {
namespace {

std::string bounded(std::string_view value, std::size_t maximum) {
    return std::string{value.substr(0, maximum)};
}

} // namespace

ConnectionRegistry& ConnectionRegistry::instance() {
    static ConnectionRegistry registry;
    return registry;
}

std::uint64_t ConnectionRegistry::add(
    std::string protocol,
    std::string source_address,
    std::string status) {
    const auto system_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    std::scoped_lock lock{mutex_};
    const auto id = next_id_++;
    ConnectionInfo info;
    info.id = id;
    info.protocol = bounded(protocol, 16);
    info.source_address = bounded(source_address, 128);
    info.connected_at_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        system_now.time_since_epoch()).count();
    info.status = bounded(status, 64);
    connections_.emplace(id, StoredConnection{std::move(info), steady_now});
    return id;
}

void ConnectionRegistry::update_request(
    std::uint64_t id,
    std::string_view method,
    std::string_view url,
    std::string_view referer,
    std::string_view status) {
    std::scoped_lock lock{mutex_};
    const auto found = connections_.find(id);
    if (found == connections_.end()) return;
    found->second.info.method = bounded(method, 32);
    found->second.info.url = bounded(url, 8192);
    found->second.info.referer = bounded(referer, 4096);
    found->second.info.status = bounded(status, 64);
}

void ConnectionRegistry::update_status(std::uint64_t id, std::string_view status) {
    std::scoped_lock lock{mutex_};
    const auto found = connections_.find(id);
    if (found == connections_.end()) return;
    found->second.info.status = bounded(status, 64);
}

void ConnectionRegistry::remove(std::uint64_t id) {
    std::scoped_lock lock{mutex_};
    connections_.erase(id);
}

std::vector<ConnectionInfo> ConnectionRegistry::snapshot(std::size_t limit) const {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock{mutex_};
    std::vector<ConnectionInfo> result;
    result.reserve(std::min(limit, connections_.size()));
    for (const auto& [id, stored] : connections_) {
        if (result.size() == limit) break;
        static_cast<void>(id);
        auto info = stored.info;
        info.connected_seconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                now - stored.connected_at).count());
        result.push_back(std::move(info));
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        if (left.connected_at_unix_ms != right.connected_at_unix_ms) {
            return left.connected_at_unix_ms < right.connected_at_unix_ms;
        }
        return left.id < right.id;
    });
    return result;
}

std::size_t ConnectionRegistry::size() const {
    std::scoped_lock lock{mutex_};
    return connections_.size();
}

void ConnectionRegistry::clear() {
    std::scoped_lock lock{mutex_};
    connections_.clear();
}

HttpRequestRegistry& HttpRequestRegistry::instance() {
    static HttpRequestRegistry registry;
    return registry;
}

std::uint64_t HttpRequestRegistry::add(
    std::string protocol,
    std::string client_ip,
    std::string_view method,
    std::string_view url,
    std::string_view referer,
    std::string_view host,
    std::string_view status) {
    const auto system_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    std::scoped_lock lock{mutex_};
    const auto id = next_id_++;
    HttpRequestInfo info;
    info.id = id;
    info.protocol = bounded(protocol, 16);
    info.client_ip = bounded(client_ip, 128);
    info.method = bounded(method, 32);
    info.url = bounded(url, 8192);
    info.referer = bounded(referer, 4096);
    info.host = bounded(host, 512);
    info.connected_at_unix_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        system_now.time_since_epoch()).count();
    info.status = bounded(status, 64);
    requests_.emplace(id, StoredRequest{std::move(info), steady_now});
    return id;
}

void HttpRequestRegistry::update_site(
    std::uint64_t id,
    std::int64_t site_id,
    std::string_view site_name,
    std::string_view host,
    std::string_view status) {
    std::scoped_lock lock{mutex_};
    const auto found = requests_.find(id);
    if (found == requests_.end()) return;
    found->second.info.site_id = site_id;
    found->second.info.site_name = bounded(site_name, 256);
    found->second.info.host = bounded(host, 512);
    found->second.info.status = bounded(status, 64);
}

void HttpRequestRegistry::update_status(std::uint64_t id, std::string_view status) {
    std::scoped_lock lock{mutex_};
    const auto found = requests_.find(id);
    if (found == requests_.end()) return;
    found->second.info.status = bounded(status, 64);
}

void HttpRequestRegistry::remove(std::uint64_t id) {
    std::scoped_lock lock{mutex_};
    requests_.erase(id);
}

std::vector<HttpRequestInfo> HttpRequestRegistry::snapshot(
    std::optional<std::int64_t> site_id,
    std::size_t limit) const {
    const auto now = std::chrono::steady_clock::now();
    std::scoped_lock lock{mutex_};
    std::vector<HttpRequestInfo> result;
    result.reserve(std::min(limit, requests_.size()));
    for (const auto& [id, stored] : requests_) {
        if (site_id && stored.info.site_id != *site_id) continue;
        if (result.size() == limit) break;
        static_cast<void>(id);
        auto info = stored.info;
        info.connected_seconds = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                now - stored.connected_at).count());
        result.push_back(std::move(info));
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        if (left.connected_at_unix_ms != right.connected_at_unix_ms) {
            return left.connected_at_unix_ms < right.connected_at_unix_ms;
        }
        return left.id < right.id;
    });
    return result;
}

std::size_t HttpRequestRegistry::size(std::optional<std::int64_t> site_id) const {
    std::scoped_lock lock{mutex_};
    if (!site_id) return requests_.size();
    return static_cast<std::size_t>(std::count_if(
        requests_.begin(), requests_.end(), [site_id](const auto& item) {
            return item.second.info.site_id == *site_id;
        }));
}

void HttpRequestRegistry::clear() {
    std::scoped_lock lock{mutex_};
    requests_.clear();
}

} // namespace webserver::core
