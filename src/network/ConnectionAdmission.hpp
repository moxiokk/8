#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

namespace webserver::network {

class ConnectionAdmission final {
    struct State;

public:
    class Permit final {
    public:
        ~Permit();
        Permit(const Permit&) = delete;
        Permit& operator=(const Permit&) = delete;

    private:
        friend class ConnectionAdmission;
        explicit Permit(std::shared_ptr<State> state);
        std::shared_ptr<State> state_;
    };

    explicit ConnectionAdmission(std::size_t maximum_connections);

    [[nodiscard]] std::shared_ptr<Permit> try_acquire();
    [[nodiscard]] std::size_t active() const noexcept;
    [[nodiscard]] std::size_t maximum() const noexcept;
    [[nodiscard]] std::uint64_t rejected() const noexcept;

private:
    struct State final {
        explicit State(std::size_t maximum_connections)
            : maximum(maximum_connections) {}

        const std::size_t maximum;
        std::atomic_size_t active{};
        std::atomic_uint64_t rejected{};
    };

    std::shared_ptr<State> state_;
};

} // namespace webserver::network
