#pragma once

#include <boost/asio/any_io_executor.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace webserver::proxy {

enum class BackendAcquireResult {
    granted,
    queue_full,
    queue_timeout,
};

struct BackendConcurrencyMetrics final {
    std::int64_t site_id{};
    std::string site_name;
    std::string backend;
    std::uint32_t maximum_active{};
    std::uint32_t maximum_queue{};
    std::uint32_t queue_timeout_seconds{};
    std::uint64_t active_connections{};
    std::uint64_t queue_length{};
    std::uint64_t rejected_requests{};
    std::uint64_t queue_timeouts{};
};

class BackendConcurrencyLimiter final {
public:
    class Permit;
    class Pending;
    using AcquireHandler = std::function<void(
        BackendAcquireResult,
        std::shared_ptr<Permit>)>;

    static BackendConcurrencyLimiter& instance();

    [[nodiscard]] std::shared_ptr<Pending> async_acquire(
        std::int64_t site_id,
        std::string site_name,
        std::string backend,
        std::uint32_t maximum_active,
        std::uint32_t maximum_queue,
        std::chrono::seconds queue_timeout,
        boost::asio::any_io_executor executor,
        AcquireHandler handler);

    [[nodiscard]] std::vector<BackendConcurrencyMetrics> metrics() const;
    void update_limits(
        std::int64_t site_id,
        std::uint32_t maximum_active,
        std::uint32_t maximum_queue);
    void retain_sites(const std::vector<std::int64_t>& active_site_ids) noexcept;
    void clear();

private:
    struct Impl;
    BackendConcurrencyLimiter();
    ~BackendConcurrencyLimiter();
    BackendConcurrencyLimiter(const BackendConcurrencyLimiter&) = delete;
    BackendConcurrencyLimiter& operator=(const BackendConcurrencyLimiter&) = delete;

    void release(std::int64_t site_id) noexcept;
    void cancel_pending(std::int64_t site_id, std::uint64_t waiter_id);
    void timeout_pending(std::int64_t site_id, std::uint64_t waiter_id);

    std::unique_ptr<Impl> impl_;
};

class BackendConcurrencyLimiter::Permit final {
public:
    ~Permit();
    Permit(const Permit&) = delete;
    Permit& operator=(const Permit&) = delete;

private:
    friend class BackendConcurrencyLimiter;
    Permit(BackendConcurrencyLimiter& owner, std::int64_t site_id);

    BackendConcurrencyLimiter* owner_{};
    std::int64_t site_id_{};
};

class BackendConcurrencyLimiter::Pending final {
public:
    struct State;
    ~Pending();
    Pending(const Pending&) = delete;
    Pending& operator=(const Pending&) = delete;
    void cancel();

private:
    friend class BackendConcurrencyLimiter;
    explicit Pending(std::shared_ptr<State> state);
    std::shared_ptr<State> state_;
};

} // namespace webserver::proxy
