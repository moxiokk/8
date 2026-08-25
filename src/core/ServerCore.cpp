#include "core/ServerCore.hpp"

#include "network/HttpListener.hpp"
#include "network/TlsListener.hpp"
#include "core/ConnectionRegistry.hpp"
#include "logging/LogManager.hpp"
#include "network/ConnectionAdmission.hpp"
#include "proxy/BackendConnectionPool.hpp"
#include "proxy/BackendConcurrencyLimiter.hpp"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/post.hpp>

#include <algorithm>
#include <exception>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

namespace webserver::core {
namespace {

std::size_t choose_worker_count(std::size_t requested) noexcept {
    if (requested != 0) {
        return requested;
    }

    return std::max<std::size_t>(1, std::thread::hardware_concurrency());
}

std::shared_ptr<const config::RuntimeConfig> initial_runtime_config(
    const ServerOptions& options) {
    if (options.runtime_config) {
        return config::build_runtime_config(*options.runtime_config);
    }

    config::RuntimeConfigSpec spec;
    spec.revision = options.config_revision;
    spec.tls_certificates = options.tls_certificates;
    spec.reject_unknown_sni = options.reject_unknown_sni;
    spec.sites.reserve(options.virtual_hosts.size());
    for (const auto& virtual_host : options.virtual_hosts) {
        config::RuntimeSiteConfig site;
        site.virtual_host = virtual_host;
        site.http_enabled = true;
        site.http_port = options.port;
        site.https_enabled = options.https_port.has_value();
        site.https_port = options.https_port.value_or(443);
        spec.sites.push_back(std::move(site));
    }
    return config::build_runtime_config(std::move(spec));
}

template <typename Container>
bool contains_port(const Container& ports, std::uint16_t port) {
    return std::find(ports.begin(), ports.end(), port) != ports.end();
}

} // namespace

ServerCore::ServerCore(ServerOptions options)
    : options_(std::move(options)),
      io_context_(static_cast<int>(choose_worker_count(options_.worker_threads))),
      work_guard_(boost::asio::make_work_guard(io_context_)),
      runtime_store_(std::make_shared<config::RuntimeConfigStore>(
          initial_runtime_config(options_))),
      connection_admission_(std::make_shared<network::ConnectionAdmission>(
          options_.maximum_connections)) {
    options_.worker_threads = choose_worker_count(options_.worker_threads);
}

ServerCore::~ServerCore() {
    stop();
    wait();
}

void ServerCore::start() {
    if (started_.exchange(true)) {
        throw std::logic_error{"HTTP server has already been started"};
    }

    try {
        const auto address = boost::asio::ip::make_address(options_.bind_address);
        const auto runtime = runtime_store_->load();

        std::unordered_map<std::uint16_t, std::shared_ptr<network::HttpListener>> http_listeners;
        std::unordered_map<std::uint16_t, std::shared_ptr<network::TlsListener>> tls_listeners;
        for (const auto port : runtime->http_ports()) {
            http_listeners.emplace(
                port,
                std::make_shared<network::HttpListener>(
                    io_context_,
                    boost::asio::ip::tcp::endpoint{address, port},
                    runtime_store_,
                    connection_admission_,
                    options_.logger));
        }
        for (const auto port : runtime->https_ports()) {
            tls_listeners.emplace(
                port,
                std::make_shared<network::TlsListener>(
                    io_context_,
                    boost::asio::ip::tcp::endpoint{address, port},
                    runtime_store_,
                    connection_admission_,
                    options_.logger));
        }

        {
            std::scoped_lock lock{control_mutex_};
            http_listeners_ = std::move(http_listeners);
            tls_listeners_ = std::move(tls_listeners);
            for (const auto& entry : http_listeners_) {
                entry.second->start(runtime->revision());
            }
            for (const auto& entry : tls_listeners_) {
                entry.second->start(runtime->revision());
            }
        }

        workers_.reserve(options_.worker_threads);
        for (std::size_t index = 0; index < options_.worker_threads; ++index) {
            workers_.emplace_back([this] { run_worker(); });
        }
    } catch (...) {
        stopping_.store(true);
        work_guard_.reset();
        io_context_.stop();
        wait();
        throw;
    }
}

std::function<void()> ServerCore::prepare_reload(config::RuntimeConfigSpec spec) {
    struct PreparedReload final {
        struct HttpRetirement final {
            std::shared_ptr<network::HttpListener> listener;
            network::HttpListener::DrainedHandler on_drained;
        };

        struct TlsRetirement final {
            std::shared_ptr<network::TlsListener> listener;
            network::TlsListener::DrainedHandler on_drained;
        };

        explicit PreparedReload(std::mutex& control_mutex)
            : control_lock(control_mutex) {}

        ~PreparedReload() {
            if (committed) return;
            for (const auto& listener : added_http) listener->stop();
            for (const auto& listener : added_tls) listener->stop();
        }

        std::unique_lock<std::mutex> control_lock;
        std::shared_ptr<const config::RuntimeConfig> next;
        std::vector<routing::BackendOverloadConfig> overload_limits;
        std::vector<std::int64_t> active_site_ids;
        std::unordered_map<std::uint16_t, std::shared_ptr<network::HttpListener>> final_http;
        std::unordered_map<std::uint16_t, std::shared_ptr<network::TlsListener>> final_tls;
        std::vector<std::shared_ptr<network::HttpListener>> final_retired_http;
        std::vector<std::shared_ptr<network::TlsListener>> final_retired_tls;
        std::vector<std::shared_ptr<network::HttpListener>> added_http;
        std::vector<std::shared_ptr<network::TlsListener>> added_tls;
        std::vector<HttpRetirement> retire_http;
        std::vector<TlsRetirement> retire_tls;
        bool server_started{};
        bool committed{};
    };

    std::vector<routing::BackendOverloadConfig> overload_limits;
    std::vector<std::int64_t> active_site_ids;
    overload_limits.reserve(spec.sites.size());
    active_site_ids.reserve(spec.sites.size());
    for (const auto& site : spec.sites) {
        overload_limits.push_back(site.virtual_host.overload);
        active_site_ids.push_back(site.virtual_host.overload.site_id);
    }
    auto next = config::build_runtime_config(std::move(spec));
    auto prepared = std::make_shared<PreparedReload>(control_mutex_);
    prepared->next = std::move(next);
    prepared->overload_limits = std::move(overload_limits);
    prepared->active_site_ids = std::move(active_site_ids);

    if (stopping_.load()) {
        throw std::logic_error{"cannot reload a stopping server"};
    }
    prepared->server_started = started_.load();

    if (prepared->server_started) {
        const auto address = boost::asio::ip::make_address(options_.bind_address);
        prepared->final_http = http_listeners_;
        prepared->final_tls = tls_listeners_;
        prepared->final_retired_http = retired_http_listeners_;
        prepared->final_retired_tls = retired_tls_listeners_;
        prepared->final_http.reserve(
            prepared->final_http.size() + prepared->next->http_ports().size());
        prepared->final_tls.reserve(
            prepared->final_tls.size() + prepared->next->https_ports().size());
        prepared->added_http.reserve(prepared->next->http_ports().size());
        prepared->added_tls.reserve(prepared->next->https_ports().size());
        prepared->retire_http.reserve(prepared->final_http.size());
        prepared->retire_tls.reserve(prepared->final_tls.size());
        prepared->final_retired_http.reserve(
            prepared->final_retired_http.size() + prepared->final_http.size());
        prepared->final_retired_tls.reserve(
            prepared->final_retired_tls.size() + prepared->final_tls.size());

        for (const auto port : prepared->next->http_ports()) {
            if (prepared->final_http.contains(port)) continue;
            auto listener = std::make_shared<network::HttpListener>(
                io_context_,
                boost::asio::ip::tcp::endpoint{address, port},
                runtime_store_,
                connection_admission_,
                options_.logger);
            prepared->added_http.push_back(listener);
            listener->start(prepared->next->revision());
            prepared->final_http.emplace(port, std::move(listener));
        }
        for (const auto port : prepared->next->https_ports()) {
            if (prepared->final_tls.contains(port)) continue;
            auto listener = std::make_shared<network::TlsListener>(
                io_context_,
                boost::asio::ip::tcp::endpoint{address, port},
                runtime_store_,
                connection_admission_,
                options_.logger);
            prepared->added_tls.push_back(listener);
            listener->start(prepared->next->revision());
            prepared->final_tls.emplace(port, std::move(listener));
        }

        for (auto listener = prepared->final_http.begin();
             listener != prepared->final_http.end();) {
            if (contains_port(prepared->next->http_ports(), listener->first)) {
                ++listener;
                continue;
            }
            auto retired = listener->second;
            network::HttpListener::DrainedHandler on_drained =
                [this](network::HttpListener* drained) {
                    boost::asio::post(io_context_, [this, drained] {
                        std::scoped_lock lock{control_mutex_};
                        std::erase_if(
                            retired_http_listeners_,
                            [drained](const auto& item) { return item.get() == drained; });
                    });
                };
            prepared->final_retired_http.push_back(retired);
            prepared->retire_http.push_back(
                PreparedReload::HttpRetirement{retired, std::move(on_drained)});
            listener = prepared->final_http.erase(listener);
        }
        for (auto listener = prepared->final_tls.begin();
             listener != prepared->final_tls.end();) {
            if (contains_port(prepared->next->https_ports(), listener->first)) {
                ++listener;
                continue;
            }
            auto retired = listener->second;
            network::TlsListener::DrainedHandler on_drained =
                [this](network::TlsListener* drained) {
                    boost::asio::post(io_context_, [this, drained] {
                        std::scoped_lock lock{control_mutex_};
                        std::erase_if(
                            retired_tls_listeners_,
                            [drained](const auto& item) { return item.get() == drained; });
                    });
                };
            prepared->final_retired_tls.push_back(retired);
            prepared->retire_tls.push_back(
                PreparedReload::TlsRetirement{retired, std::move(on_drained)});
            listener = prepared->final_tls.erase(listener);
        }
    }

    return [this, prepared]() noexcept {
        if (prepared->committed) return;
        prepared->committed = true;

        for (const auto& overload : prepared->overload_limits) {
            try {
                proxy::BackendConcurrencyLimiter::instance().update_limits(
                    overload.site_id,
                    overload.maximum_active_connections,
                    overload.maximum_queue);
            } catch (...) {
            }
        }
        proxy::BackendConcurrencyLimiter::instance().retain_sites(
            prepared->active_site_ids);

        if (prepared->server_started) {
            http_listeners_.swap(prepared->final_http);
            tls_listeners_.swap(prepared->final_tls);
            retired_http_listeners_.swap(prepared->final_retired_http);
            retired_tls_listeners_.swap(prepared->final_retired_tls);
            for (auto& retirement : prepared->retire_http) {
                retirement.listener->retire(std::move(retirement.on_drained));
            }
            for (auto& retirement : prepared->retire_tls) {
                retirement.listener->retire(std::move(retirement.on_drained));
            }
        }

        // Publication opens the revision gate on every pre-started listener
        // and is deliberately the final commit operation.
        runtime_store_->publish(prepared->next);
        auto* const control_mutex = prepared->control_lock.release();
        control_mutex->unlock();
    };
}

void ServerCore::reload(config::RuntimeConfigSpec spec) {
    auto commit = prepare_reload(std::move(spec));
    commit();
}

void ServerCore::stop() {
    std::scoped_lock lock{control_mutex_};
    if (!started_.load() || stopping_.exchange(true)) return;
    for (const auto& entry : http_listeners_) {
        entry.second->stop();
    }
    for (const auto& entry : tls_listeners_) {
        entry.second->stop();
    }
    for (const auto& listener : retired_http_listeners_) {
        listener->stop();
    }
    for (const auto& listener : retired_tls_listeners_) {
        listener->stop();
    }
    proxy::BackendConnectionPool::instance().clear();
    proxy::BackendConcurrencyLimiter::instance().clear();
    work_guard_.reset();
}

void ServerCore::wait() {
    for (auto& worker : workers_) {
        if (worker.joinable()) {
            worker.join();
        }
    }
    workers_.clear();
    {
        std::scoped_lock lock{control_mutex_};
        http_listeners_.clear();
        tls_listeners_.clear();
        retired_http_listeners_.clear();
        retired_tls_listeners_.clear();
    }
    proxy::BackendConnectionPool::instance().clear();
    proxy::BackendConcurrencyLimiter::instance().clear();
    ConnectionRegistry::instance().clear();
    HttpRequestRegistry::instance().clear();
}

boost::asio::io_context& ServerCore::io_context() noexcept {
    return io_context_;
}

boost::asio::ip::tcp::endpoint ServerCore::local_endpoint() const {
    std::scoped_lock lock{control_mutex_};
    const auto preferred = http_listeners_.find(options_.port);
    if (preferred != http_listeners_.end()) {
        return preferred->second->local_endpoint();
    }
    if (http_listeners_.empty()) {
        throw std::logic_error{"HTTP server has not been started"};
    }
    return http_listeners_.begin()->second->local_endpoint();
}

boost::asio::ip::tcp::endpoint ServerCore::http_local_endpoint(
    std::uint16_t configured_port) const {
    std::scoped_lock lock{control_mutex_};
    const auto listener = http_listeners_.find(configured_port);
    if (listener == http_listeners_.end()) {
        throw std::invalid_argument{"HTTP listener port is not active"};
    }
    return listener->second->local_endpoint();
}

std::optional<boost::asio::ip::tcp::endpoint> ServerCore::tls_local_endpoint() const {
    std::scoped_lock lock{control_mutex_};
    if (options_.https_port) {
        const auto preferred = tls_listeners_.find(*options_.https_port);
        if (preferred != tls_listeners_.end()) {
            return preferred->second->local_endpoint();
        }
    }
    if (tls_listeners_.empty()) {
        return std::nullopt;
    }
    return tls_listeners_.begin()->second->local_endpoint();
}

std::optional<boost::asio::ip::tcp::endpoint> ServerCore::tls_local_endpoint(
    std::uint16_t configured_port) const {
    std::scoped_lock lock{control_mutex_};
    const auto listener = tls_listeners_.find(configured_port);
    if (listener == tls_listeners_.end()) {
        return std::nullopt;
    }
    return listener->second->local_endpoint();
}

std::size_t ServerCore::worker_count() const noexcept {
    return options_.worker_threads;
}

std::size_t ServerCore::active_connection_count() const noexcept {
    return connection_admission_->active();
}

std::size_t ServerCore::maximum_connection_count() const noexcept {
    return connection_admission_->maximum();
}

std::uint64_t ServerCore::rejected_connection_count() const noexcept {
    return connection_admission_->rejected();
}

std::size_t ServerCore::retired_listener_count() const {
    std::scoped_lock lock{control_mutex_};
    return retired_http_listeners_.size() + retired_tls_listeners_.size();
}

std::uint64_t ServerCore::runtime_revision() const noexcept {
    return runtime_store_->load()->revision();
}

std::vector<ListenerStatus> ServerCore::listener_statuses() const {
    std::scoped_lock lock{control_mutex_};
    const auto runtime = runtime_store_->load();
    std::vector<ListenerStatus> result;
    result.reserve(http_listeners_.size() + tls_listeners_.size());
    for (const auto& [port, listener] : http_listeners_) {
        const auto endpoint = listener->local_endpoint();
        result.push_back(ListenerStatus{
            "HTTP", endpoint.address().to_string(), port, endpoint.port(),
            runtime->site_count(config::ListenerProtocol::http, port), "Listening"});
    }
    for (const auto& [port, listener] : tls_listeners_) {
        const auto endpoint = listener->local_endpoint();
        result.push_back(ListenerStatus{
            "HTTPS", endpoint.address().to_string(), port, endpoint.port(),
            runtime->site_count(config::ListenerProtocol::https, port), "Listening"});
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        if (left.bound_port != right.bound_port) return left.bound_port < right.bound_port;
        return left.protocol < right.protocol;
    });
    return result;
}

void ServerCore::run_worker() noexcept {
    for (;;) {
        try {
            io_context_.run();
            return;
        } catch (const std::bad_alloc&) {
            if (options_.logger) {
                try {
                    options_.logger->log_error(
                        logging::ErrorSeverity::critical,
                        "server_worker",
                        "worker handler ran out of memory; event loop will continue");
                } catch (...) {
                }
            }
        } catch (const std::exception& exception) {
            if (options_.logger) {
                try {
                    options_.logger->log_error(
                        logging::ErrorSeverity::critical,
                        "server_worker",
                        "uncaught worker handler exception: " +
                            std::string{exception.what()});
                } catch (...) {
                }
            }
        } catch (...) {
            if (options_.logger) {
                try {
                    options_.logger->log_error(
                        logging::ErrorSeverity::critical,
                        "server_worker",
                        "unknown worker handler exception; event loop will continue");
                } catch (...) {
                }
            }
        }
    }
}

} // namespace webserver::core
