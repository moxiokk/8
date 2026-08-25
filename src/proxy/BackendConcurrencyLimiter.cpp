#include "proxy/BackendConcurrencyLimiter.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include <algorithm>
#include <atomic>
#include <deque>
#include <mutex>
#include <unordered_map>
#include <utility>

namespace webserver::proxy {
namespace asio = boost::asio;

struct BackendConcurrencyLimiter::Pending::State final {
    BackendConcurrencyLimiter* owner{};
    std::int64_t site_id{};
    std::uint64_t waiter_id{};
    asio::any_io_executor executor;
    std::shared_ptr<asio::steady_timer> timer;
    AcquireHandler handler;
    std::atomic_bool completed{false};
};

struct BackendConcurrencyLimiter::Impl final {
    struct SiteState final {
        std::string site_name;
        std::string backend;
        std::uint32_t maximum_active{};
        std::uint32_t maximum_queue{};
        std::uint32_t queue_timeout_seconds{};
        std::uint64_t active{};
        std::uint64_t rejected{};
        std::uint64_t timeouts{};
        std::deque<std::shared_ptr<Pending::State>> queue;
        bool retired{};
    };

    mutable std::mutex mutex;
    std::unordered_map<std::int64_t, SiteState> sites;
    std::uint64_t next_waiter_id{1};
};

BackendConcurrencyLimiter::BackendConcurrencyLimiter() : impl_(std::make_unique<Impl>()) {}
BackendConcurrencyLimiter::~BackendConcurrencyLimiter() = default;

BackendConcurrencyLimiter& BackendConcurrencyLimiter::instance() {
    static BackendConcurrencyLimiter limiter;
    return limiter;
}

BackendConcurrencyLimiter::Permit::Permit(
    BackendConcurrencyLimiter& owner,
    std::int64_t site_id)
    : owner_(&owner), site_id_(site_id) {}

BackendConcurrencyLimiter::Permit::~Permit() {
    if (owner_) owner_->release(site_id_);
}

BackendConcurrencyLimiter::Pending::Pending(std::shared_ptr<State> state)
    : state_(std::move(state)) {}

BackendConcurrencyLimiter::Pending::~Pending() {
    cancel();
}

void BackendConcurrencyLimiter::Pending::cancel() {
    if (state_ && state_->owner) {
        state_->owner->cancel_pending(state_->site_id, state_->waiter_id);
    }
}

std::shared_ptr<BackendConcurrencyLimiter::Pending>
BackendConcurrencyLimiter::async_acquire(
    std::int64_t site_id,
    std::string site_name,
    std::string backend,
    std::uint32_t maximum_active,
    std::uint32_t maximum_queue,
    std::chrono::seconds queue_timeout,
    asio::any_io_executor executor,
    AcquireHandler handler) {
    auto state = std::make_shared<Pending::State>();
    state->owner = this;
    state->site_id = site_id;
    state->executor = std::move(executor);
    state->handler = std::move(handler);

    BackendAcquireResult immediate = BackendAcquireResult::granted;
    bool queued = false;
    std::vector<std::shared_ptr<Pending::State>> promoted;
    {
        std::scoped_lock lock{impl_->mutex};
        auto& site = impl_->sites[site_id];
        site.retired = false;
        site.site_name = std::move(site_name);
        site.backend = std::move(backend);
        site.maximum_active = maximum_active;
        site.maximum_queue = maximum_queue;
        site.queue_timeout_seconds = static_cast<std::uint32_t>(queue_timeout.count());
        state->waiter_id = impl_->next_waiter_id++;

        // A hot increase must benefit waiters that were already queued before
        // this request. Promote them first to preserve FIFO ordering.
        while (site.active < maximum_active && !site.queue.empty()) {
            auto candidate = std::move(site.queue.front());
            site.queue.pop_front();
            bool expected = false;
            if (!candidate->completed.compare_exchange_strong(expected, true)) {
                continue;
            }
            ++site.active;
            promoted.push_back(std::move(candidate));
        }

        if (site.queue.empty() && site.active < maximum_active) {
            ++site.active;
            state->completed.store(true);
        } else if (site.queue.size() >= maximum_queue) {
            ++site.rejected;
            immediate = BackendAcquireResult::queue_full;
            state->completed.store(true);
        } else {
            state->timer = std::make_shared<asio::steady_timer>(
                state->executor, queue_timeout);
            site.queue.push_back(state);
            queued = true;
            state->timer->async_wait([state](const boost::system::error_code& error) {
                if (!error && state->owner) {
                    state->owner->timeout_pending(state->site_id, state->waiter_id);
                }
            });
        }
    }

    for (auto& ready : promoted) {
        if (ready->timer) ready->timer->cancel();
        auto permit = std::shared_ptr<Permit>{new Permit{*this, site_id}};
        asio::post(ready->executor, [ready, permit = std::move(permit)]() mutable {
            if (ready->handler) {
                ready->handler(BackendAcquireResult::granted, std::move(permit));
            }
            ready->handler = {};
        });
    }

    auto pending = std::shared_ptr<Pending>{new Pending{state}};
    if (!queued) {
        auto permit = immediate == BackendAcquireResult::granted
                          ? std::shared_ptr<Permit>{new Permit{*this, site_id}}
                          : std::shared_ptr<Permit>{};
        asio::post(state->executor, [state, immediate, permit = std::move(permit)]() mutable {
            if (state->handler) state->handler(immediate, std::move(permit));
            state->handler = {};
        });
        return pending;
    }

    return pending;
}

void BackendConcurrencyLimiter::release(std::int64_t site_id) noexcept {
    std::shared_ptr<Pending::State> next;
    try {
        {
            std::scoped_lock lock{impl_->mutex};
            auto found = impl_->sites.find(site_id);
            if (found == impl_->sites.end()) return;
            auto& site = found->second;
            if (site.active > site.maximum_active) {
                --site.active;
                if (site.retired && site.active == 0 && site.queue.empty()) {
                    impl_->sites.erase(found);
                }
                return;
            }
            while (!site.queue.empty()) {
                auto candidate = std::move(site.queue.front());
                site.queue.pop_front();
                bool expected = false;
                if (candidate->completed.compare_exchange_strong(expected, true)) {
                    next = std::move(candidate);
                    break;
                }
            }
            if (!next && site.active != 0) --site.active;
            if (!next && site.retired && site.active == 0 && site.queue.empty()) {
                impl_->sites.erase(found);
            }
        }

        if (!next) return;
        if (next->timer) {
            // BOOST_ASIO_NO_DEPRECATED removes cancel(error_code&) from
            // waitable timers. Keep this noexcept hand-off path safe when the
            // throwing overload reports an unexpected failure.
            try {
                next->timer->cancel();
            } catch (...) {
            }
        }

        std::shared_ptr<Permit> permit;
        try {
            permit = std::shared_ptr<Permit>{new Permit{*this, site_id}};
        } catch (...) {
            try {
                if (next->handler) {
                    next->handler(BackendAcquireResult::queue_full, {});
                }
            } catch (...) {
            }
            next->handler = {};
            // The active slot was reserved for this waiter. Release it again
            // so an allocation failure cannot permanently consume capacity.
            release(site_id);
            return;
        }

        try {
            asio::post(next->executor, [next, permit]() mutable noexcept {
                try {
                    if (next->handler) {
                        next->handler(
                            BackendAcquireResult::granted, std::move(permit));
                    }
                } catch (...) {
                }
                next->handler = {};
            });
        } catch (...) {
            try {
                if (next->handler) {
                    next->handler(
                        BackendAcquireResult::granted, std::move(permit));
                }
            } catch (...) {
            }
            next->handler = {};
        }
    } catch (...) {
        // Permit destruction must never terminate the process. There are no
        // expected throwing operations before the slot is accounted for.
    }
}

void BackendConcurrencyLimiter::cancel_pending(
    std::int64_t site_id,
    std::uint64_t waiter_id) {
    std::shared_ptr<Pending::State> cancelled;
    {
        std::scoped_lock lock{impl_->mutex};
        auto found = impl_->sites.find(site_id);
        if (found == impl_->sites.end()) return;
        auto& queue = found->second.queue;
        const auto waiter = std::find_if(queue.begin(), queue.end(), [waiter_id](const auto& item) {
            return item->waiter_id == waiter_id;
        });
        if (waiter == queue.end()) return;
        cancelled = *waiter;
        bool expected = false;
        if (!cancelled->completed.compare_exchange_strong(expected, true)) return;
        queue.erase(waiter);
        if (found->second.retired && found->second.active == 0 && queue.empty()) {
            impl_->sites.erase(found);
        }
    }
    if (cancelled->timer) cancelled->timer->cancel();
    cancelled->handler = {};
}

void BackendConcurrencyLimiter::timeout_pending(
    std::int64_t site_id,
    std::uint64_t waiter_id) {
    std::shared_ptr<Pending::State> timed_out;
    {
        std::scoped_lock lock{impl_->mutex};
        auto found = impl_->sites.find(site_id);
        if (found == impl_->sites.end()) return;
        auto& site = found->second;
        const auto waiter = std::find_if(site.queue.begin(), site.queue.end(), [waiter_id](const auto& item) {
            return item->waiter_id == waiter_id;
        });
        if (waiter == site.queue.end()) return;
        timed_out = *waiter;
        bool expected = false;
        if (!timed_out->completed.compare_exchange_strong(expected, true)) return;
        site.queue.erase(waiter);
        ++site.rejected;
        ++site.timeouts;
        if (site.retired && site.active == 0 && site.queue.empty()) {
            impl_->sites.erase(found);
        }
    }
    asio::post(timed_out->executor, [timed_out] {
        if (timed_out->handler) {
            timed_out->handler(BackendAcquireResult::queue_timeout, {});
        }
        timed_out->handler = {};
    });
}

std::vector<BackendConcurrencyMetrics> BackendConcurrencyLimiter::metrics() const {
    std::scoped_lock lock{impl_->mutex};
    std::vector<BackendConcurrencyMetrics> result;
    result.reserve(impl_->sites.size());
    for (const auto& [site_id, site] : impl_->sites) {
        result.push_back(BackendConcurrencyMetrics{
            site_id,
            site.site_name,
            site.backend,
            site.maximum_active,
            site.maximum_queue,
            site.queue_timeout_seconds,
            site.active,
            site.queue.size(),
            site.rejected,
            site.timeouts});
    }
    std::sort(result.begin(), result.end(), [](const auto& left, const auto& right) {
        return left.site_id < right.site_id;
    });
    return result;
}

void BackendConcurrencyLimiter::update_limits(
    std::int64_t site_id,
    std::uint32_t maximum_active,
    std::uint32_t maximum_queue) {
    std::vector<std::shared_ptr<Pending::State>> promoted;
    {
        std::scoped_lock lock{impl_->mutex};
        const auto found = impl_->sites.find(site_id);
        if (found == impl_->sites.end()) return;

        auto& site = found->second;
        site.retired = false;
        site.maximum_active = maximum_active;
        site.maximum_queue = maximum_queue;
        while (site.active < maximum_active && !site.queue.empty()) {
            auto candidate = std::move(site.queue.front());
            site.queue.pop_front();
            bool expected = false;
            if (!candidate->completed.compare_exchange_strong(expected, true)) {
                continue;
            }
            ++site.active;
            promoted.push_back(std::move(candidate));
        }
    }

    for (auto& ready : promoted) {
        if (ready->timer) ready->timer->cancel();
        auto permit = std::shared_ptr<Permit>{new Permit{*this, site_id}};
        asio::post(ready->executor, [ready, permit = std::move(permit)]() mutable {
            if (ready->handler) {
                ready->handler(BackendAcquireResult::granted, std::move(permit));
            }
            ready->handler = {};
        });
    }
}

void BackendConcurrencyLimiter::retain_sites(
    const std::vector<std::int64_t>& active_site_ids) noexcept {
    std::scoped_lock lock{impl_->mutex};
    for (auto site = impl_->sites.begin(); site != impl_->sites.end();) {
        if (std::find(active_site_ids.begin(), active_site_ids.end(), site->first) !=
            active_site_ids.end()) {
            ++site;
            continue;
        }
        site->second.retired = true;
        if (site->second.active == 0 && site->second.queue.empty()) {
            site = impl_->sites.erase(site);
        } else {
            ++site;
        }
    }
}

void BackendConcurrencyLimiter::clear() {
    std::vector<std::shared_ptr<Pending::State>> pending;
    {
        std::scoped_lock lock{impl_->mutex};
        for (auto& [ignored, site] : impl_->sites) {
            static_cast<void>(ignored);
            for (auto& waiter : site.queue) {
                bool expected = false;
                if (waiter->completed.compare_exchange_strong(expected, true)) {
                    pending.push_back(std::move(waiter));
                }
            }
        }
        impl_->sites.clear();
    }
    for (auto& waiter : pending) {
        if (waiter->timer) {
waiter->timer->cancel();
        }
        waiter->handler = {};
    }
}

} // namespace webserver::proxy
