#include "network/ConnectionAdmission.hpp"

#include <stdexcept>
#include <utility>

namespace webserver::network {

ConnectionAdmission::Permit::Permit(std::shared_ptr<State> state)
    : state_(std::move(state)) {}

ConnectionAdmission::Permit::~Permit() {
    if (state_) {
        state_->active.fetch_sub(1, std::memory_order_acq_rel);
    }
}

ConnectionAdmission::ConnectionAdmission(std::size_t maximum_connections) {
    if (maximum_connections == 0 || maximum_connections > 1'000'000) {
        throw std::invalid_argument{
            "maximum client connections must be between 1 and 1000000"};
    }
    state_ = std::make_shared<State>(maximum_connections);
}

std::shared_ptr<ConnectionAdmission::Permit> ConnectionAdmission::try_acquire() {
    auto current = state_->active.load(std::memory_order_relaxed);
    while (current < state_->maximum) {
        if (state_->active.compare_exchange_weak(
                current,
                current + 1,
                std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            try {
                return std::shared_ptr<Permit>{new Permit{state_}};
            } catch (...) {
                state_->active.fetch_sub(1, std::memory_order_acq_rel);
                throw;
            }
        }
    }
    state_->rejected.fetch_add(1, std::memory_order_relaxed);
    return {};
}

std::size_t ConnectionAdmission::active() const noexcept {
    return state_->active.load(std::memory_order_acquire);
}

std::size_t ConnectionAdmission::maximum() const noexcept {
    return state_->maximum;
}

std::uint64_t ConnectionAdmission::rejected() const noexcept {
    return state_->rejected.load(std::memory_order_relaxed);
}

} // namespace webserver::network
