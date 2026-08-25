#include "proxy/BackendConnectionPool.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/socket_base.hpp>
#include <boost/beast/core/stream_traits.hpp>
#include <boost/system/error_code.hpp>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#endif

#include <array>
#include <stdexcept>
#include <utility>

namespace webserver::proxy {
namespace {

#ifdef _WIN32
void load_windows_root_certificates(boost::asio::ssl::context& context) {
    const auto store = CertOpenSystemStoreW(0, L"ROOT");
    if (!store) return;
    auto* openssl_store = SSL_CTX_get_cert_store(context.native_handle());
    PCCERT_CONTEXT certificate = nullptr;
    while ((certificate = CertEnumCertificatesInStore(store, certificate)) != nullptr) {
        const unsigned char* encoded = certificate->pbCertEncoded;
        auto* parsed = d2i_X509(nullptr, &encoded, certificate->cbCertEncoded);
        if (!parsed) continue;
        if (X509_STORE_add_cert(openssl_store, parsed) != 1) ERR_clear_error();
        X509_free(parsed);
    }
    CertCloseStore(store, 0);
}
#endif

bool reusable(BackendStream& stream) {
    return std::visit([](auto& candidate) {
        auto& socket = boost::beast::get_lowest_layer(candidate).socket();
        if (!socket.is_open()) return false;
        boost::system::error_code error;
        const auto available = socket.available(error);
        if (error) return false;
        if (available != 0) return false;
        if (available == 0) {
            socket.non_blocking(true, error);
            if (error) return false;
            std::array<char, 1> probe{};
            boost::system::error_code receive_error;
            const auto received = socket.receive(
                boost::asio::buffer(probe),
                boost::asio::socket_base::message_peek,
                receive_error);
            socket.non_blocking(false, error);
            if (error) return false;
            if (received == 0 && receive_error != boost::asio::error::would_block &&
                receive_error != boost::asio::error::try_again) return false;
        }
        return true;
    }, stream);
}

void close_stream(BackendStream& stream) {
    std::visit([](auto& candidate) {
        auto& lowest = boost::beast::get_lowest_layer(candidate);
        lowest.expires_never();
        boost::system::error_code ignored;
        lowest.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
        lowest.socket().close(ignored);
    }, stream);
}

} // namespace

boost::asio::ssl::context& outbound_tls_context() {
    static boost::asio::ssl::context context = [] {
        boost::asio::ssl::context value{boost::asio::ssl::context::tls_client};
        value.set_options(boost::asio::ssl::context::default_workarounds);
        if (SSL_CTX_set_min_proto_version(value.native_handle(), TLS1_2_VERSION) != 1) {
            throw std::runtime_error{"cannot enforce TLS 1.2 for outbound connections"};
        }
        boost::system::error_code ignored;
        value.set_default_verify_paths(ignored);
#ifdef _WIN32
        load_windows_root_certificates(value);
#endif
        return value;
    }();
    return context;
}

BackendConnectionPool& BackendConnectionPool::instance() {
    static BackendConnectionPool pool;
    return pool;
}

BackendConnectionPool::BackendConnectionPool()
    : reaper_([this] { run_reaper(); }) {}

BackendConnectionPool::~BackendConnectionPool() {
    {
        std::scoped_lock lock{mutex_};
        stopping_ = true;
    }
    reaper_wakeup_.notify_all();
    if (reaper_.joinable()) reaper_.join();
    clear();
}

std::optional<BackendStream> BackendConnectionPool::acquire(
    const std::string& pool_key,
    std::chrono::seconds idle_ttl) {
    for (;;) {
        std::optional<IdleConnection> connection;
        bool wake_reaper = false;
        {
            std::scoped_lock lock{mutex_};
            const auto found = idle_.find(pool_key);
            if (found == idle_.end()) return std::nullopt;
            auto& connections = found->second;
            connection.emplace(std::move(connections.back()));
            connections.pop_back();
            if (connections.empty()) idle_.erase(found);
            if (next_expiration_ && connection->expires_at <= *next_expiration_) {
                next_expiration_.reset();
                wake_reaper = true;
            }
        }
        if (wake_reaper) reaper_wakeup_.notify_one();

        const auto now = std::chrono::steady_clock::now();
        if (idle_ttl > std::chrono::seconds::zero() &&
            now <= connection->expires_at &&
            now - connection->released_at <= idle_ttl &&
            reusable(connection->stream)) {
            return std::move(connection->stream);
        }
        close_stream(connection->stream);
    }
}

void BackendConnectionPool::release(
    std::string pool_key,
    BackendStream stream,
    std::size_t maximum_idle,
    std::chrono::seconds idle_ttl) {
    if (maximum_idle == 0 || idle_ttl <= std::chrono::seconds::zero() ||
        !reusable(stream)) {
        close_stream(stream);
        return;
    }

    bool retained = false;
    bool wake_reaper = false;
    {
        std::scoped_lock lock{mutex_};
        if (!stopping_) {
            auto& connections = idle_[std::move(pool_key)];
            if (connections.size() < maximum_idle) {
                const auto now = std::chrono::steady_clock::now();
                const auto expires_at = now + idle_ttl;
                connections.push_back(IdleConnection{
                    std::move(stream), now, expires_at});
                if (!next_expiration_ || expires_at < *next_expiration_) {
                    next_expiration_ = expires_at;
                    wake_reaper = true;
                }
                retained = true;
            }
        }
    }
    if (!retained) {
        close_stream(stream);
        return;
    }
    if (wake_reaper) reaper_wakeup_.notify_one();
}

void BackendConnectionPool::clear() {
    decltype(idle_) connections_to_close;
    {
        std::scoped_lock lock{mutex_};
        connections_to_close = std::move(idle_);
        next_expiration_.reset();
    }
    reaper_wakeup_.notify_one();
    for (auto& [ignored_key, connections] : connections_to_close) {
        static_cast<void>(ignored_key);
        for (auto& connection : connections) close_stream(connection.stream);
    }
}

void BackendConnectionPool::run_reaper() noexcept {
    std::list<IdleConnection> expired;
    std::unique_lock lock{mutex_};
    for (;;) {
        if (stopping_) return;

        if (!next_expiration_) {
            for (const auto& [ignored_key, connections] : idle_) {
                static_cast<void>(ignored_key);
                for (const auto& connection : connections) {
                    if (!next_expiration_ || connection.expires_at < *next_expiration_) {
                        next_expiration_ = connection.expires_at;
                    }
                }
            }
        }

        // Sleep until the nearest deadline; releases and acquires wake the
        // thread so it can recompute an earlier or removed deadline.
        if (!next_expiration_) {
            reaper_wakeup_.wait(lock);
            continue;
        }
        if (reaper_wakeup_.wait_until(lock, *next_expiration_) !=
            std::cv_status::timeout) {
            continue;
        }

        const auto now = std::chrono::steady_clock::now();
        for (auto pool = idle_.begin(); pool != idle_.end();) {
            auto& connections = pool->second;
            for (auto connection = connections.begin(); connection != connections.end();) {
                if (connection->expires_at > now) {
                    ++connection;
                    continue;
                }
                const auto current = connection++;
                expired.splice(expired.end(), connections, current);
            }
            if (connections.empty()) {
                pool = idle_.erase(pool);
            } else {
                ++pool;
            }
        }
        next_expiration_.reset();

        lock.unlock();
        for (auto& connection : expired) close_stream(connection.stream);
        expired.clear();
        lock.lock();
    }
}

} // namespace webserver::proxy
