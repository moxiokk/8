#include "proxy/BackendConcurrencyLimiter.hpp"

#include <boost/asio/io_context.hpp>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>

namespace {

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error{message};
}

} // namespace

int main() {
    using namespace std::chrono_literals;
    try {
        auto& limiter = webserver::proxy::BackendConcurrencyLimiter::instance();
        limiter.clear();
        boost::asio::io_context io;
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit> first_permit;
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit> second_permit;
        webserver::proxy::BackendAcquireResult third_result =
            webserver::proxy::BackendAcquireResult::granted;
        bool first_called = false;
        bool second_called = false;
        bool third_called = false;

        auto first = limiter.async_acquire(
            42, "limited site", "127.0.0.1:8090", 1, 1, 5s, io.get_executor(),
            [&](auto result, auto permit) {
                first_called = true;
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "first request was not granted");
                first_permit = std::move(permit);
            });
        auto second = limiter.async_acquire(
            42, "limited site", "127.0.0.1:8090", 1, 1, 5s, io.get_executor(),
            [&](auto result, auto permit) {
                second_called = true;
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "queued request was not granted");
                second_permit = std::move(permit);
            });
        auto third = limiter.async_acquire(
            42, "limited site", "127.0.0.1:8090", 1, 1, 5s, io.get_executor(),
            [&](auto result, auto) {
                third_called = true;
                third_result = result;
            });
        io.poll();
        require(first_called, "immediate acquire callback did not run");
        require(!second_called, "queued request ran before a permit was released");
        require(third_called &&
                    third_result == webserver::proxy::BackendAcquireResult::queue_full,
                "queue overflow was not rejected");

        const auto before_release = limiter.metrics();
        require(before_release.size() == 1 &&
                    before_release.front().active_connections == 1 &&
                    before_release.front().queue_length == 1 &&
                    before_release.front().rejected_requests == 1,
                "limiter metrics did not reflect active, queued, and rejected requests");

        first_permit.reset();
        io.restart();
        io.poll();
        require(second_called && second_permit, "released capacity did not wake the queue head");
        second_permit.reset();
        const auto after_release = limiter.metrics();
        require(after_release.front().active_connections == 0 &&
                    after_release.front().queue_length == 0,
                "permit release did not drain limiter counters");

        first.reset();
        second.reset();
        third.reset();
        limiter.clear();
        io.restart();

        std::vector<std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>>
            hot_reload_permits;
        std::vector<std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Pending>>
            hot_reload_pending;
        int granted = 0;
        for (int index = 0; index < 4; ++index) {
            hot_reload_pending.push_back(limiter.async_acquire(
                43, "hot reload site", "127.0.0.1:8091", 2, 8, 5s,
                io.get_executor(),
                [&](auto result, auto permit) {
                    require(result == webserver::proxy::BackendAcquireResult::granted,
                            "hot reload waiter was not granted");
                    ++granted;
                    hot_reload_permits.push_back(std::move(permit));
                }));
        }
        io.poll();
        require(granted == 2, "old active limit was not enforced");
        require(limiter.metrics().front().queue_length == 2,
                "old active limit did not queue two waiters");

        limiter.update_limits(43, 4, 8);
        io.restart();
        io.poll();
        const auto after_hot_increase = limiter.metrics();
        require(granted == 4 && after_hot_increase.front().active_connections == 4 &&
                    after_hot_increase.front().queue_length == 0,
                "increasing the active limit did not immediately drain queued waiters");

        // The async acquire path also applies new limits defensively, so callers
        // that race with a runtime publish cannot leave old waiters stranded.
        auto fifth = limiter.async_acquire(
            43, "hot reload site", "127.0.0.1:8091", 5, 8, 5s,
            io.get_executor(),
            [&](auto result, auto permit) {
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "new request after a limit increase was not granted");
                ++granted;
                hot_reload_permits.push_back(std::move(permit));
            });
        io.restart();
        io.poll();
        require(granted == 5 && limiter.metrics().front().active_connections == 5,
                "async acquire did not observe the increased active limit");

        fifth.reset();
        hot_reload_pending.clear();
        hot_reload_permits.clear();
        limiter.clear();

        io.restart();
        std::vector<std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>>
            raced_permits;
        std::vector<std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Pending>>
            raced_pending;
        int raced_granted = 0;
        for (int index = 0; index < 4; ++index) {
            raced_pending.push_back(limiter.async_acquire(
                44, "raced reload site", "127.0.0.1:8092", 2, 8, 5s,
                io.get_executor(),
                [&](auto result, auto permit) {
                    require(result == webserver::proxy::BackendAcquireResult::granted,
                            "raced hot reload waiter was not granted");
                    ++raced_granted;
                    raced_permits.push_back(std::move(permit));
                }));
        }
        io.poll();
        bool newest_called = false;
        auto newest = limiter.async_acquire(
            44, "raced reload site", "127.0.0.1:8092", 4, 8, 5s,
            io.get_executor(),
            [&](auto, auto) { newest_called = true; });
        io.restart();
        io.poll();
        const auto raced_metrics = limiter.metrics();
        require(raced_granted == 4 && !newest_called &&
                    raced_metrics.front().active_connections == 4 &&
                    raced_metrics.front().queue_length == 1,
                "async acquire did not promote old FIFO waiters after a raced limit increase");

        newest.reset();
        raced_pending.clear();
        raced_permits.clear();

        limiter.clear();
        io.restart();
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>
            retired_permit;
        auto retired_pending = limiter.async_acquire(
            45, "removed site", "127.0.0.1:8093", 1, 1, 5s,
            io.get_executor(),
            [&](auto result, auto permit) {
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "removed-site permit was not granted");
                retired_permit = std::move(permit);
            });
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>
            retained_permit;
        auto retained_pending = limiter.async_acquire(
            46, "retained site", "127.0.0.1:8094", 1, 1, 5s,
            io.get_executor(),
            [&](auto result, auto permit) {
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "retained-site permit was not granted");
                retained_permit = std::move(permit);
            });
        io.poll();
        require(retired_permit && retained_permit,
                "site-retirement setup did not acquire both permits");

        limiter.retain_sites({46});
        auto retirement_metrics = limiter.metrics();
        require(retirement_metrics.size() == 2,
                "an active removed site was discarded before its permit drained");
        retired_permit.reset();
        retirement_metrics = limiter.metrics();
        require(retirement_metrics.size() == 1 &&
                    retirement_metrics.front().site_id == 46,
                "a drained removed site was not reclaimed");

        retained_permit.reset();
        limiter.retain_sites({});
        require(limiter.metrics().empty(),
                "an inactive historical site was retained indefinitely");
        retired_pending.reset();
        retained_pending.reset();

        io.restart();
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>
            draining_first_permit;
        std::shared_ptr<webserver::proxy::BackendConcurrencyLimiter::Permit>
            draining_second_permit;
        auto draining_first = limiter.async_acquire(
            47, "draining removed site", "127.0.0.1:8095", 1, 1, 5s,
            io.get_executor(),
            [&](auto result, auto permit) {
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "first draining permit was not granted");
                draining_first_permit = std::move(permit);
            });
        auto draining_second = limiter.async_acquire(
            47, "draining removed site", "127.0.0.1:8095", 1, 1, 5s,
            io.get_executor(),
            [&](auto result, auto permit) {
                require(result == webserver::proxy::BackendAcquireResult::granted,
                        "queued request for a removed site was not drained");
                draining_second_permit = std::move(permit);
            });
        io.poll();
        require(draining_first_permit && !draining_second_permit,
                "draining-site setup did not leave one queued request");
        limiter.retain_sites({});
        draining_first_permit.reset();
        io.restart();
        io.poll();
        require(static_cast<bool>(draining_second_permit),
                "retiring a site silently discarded its queued in-flight request");
        draining_second_permit.reset();
        require(limiter.metrics().empty(),
                "a removed site was not reclaimed after its queue drained");
        draining_first.reset();
        draining_second.reset();

        limiter.clear();
        std::cout << "backend concurrency limiter tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "backend concurrency limiter tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
