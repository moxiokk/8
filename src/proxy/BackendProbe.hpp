#pragma once

#include "routing/VirtualHostRouter.hpp"

#include <boost/asio/any_io_executor.hpp>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace webserver::proxy {

struct BackendProbeResult final {
    bool success{};
    std::string protocol;
    std::string remote_address;
    std::uint16_t remote_port{};
    double latency_ms{};
    bool tls_verified{};
    std::string error;
};

class BackendProbeOperation {
public:
    virtual ~BackendProbeOperation() = default;
    virtual void cancel() = 0;
};

[[nodiscard]] BackendProbeResult probe_backend(const routing::BackendConfig& backend);
[[nodiscard]] std::shared_ptr<BackendProbeOperation> async_probe_backend(
    routing::BackendConfig backend,
    boost::asio::any_io_executor executor,
    std::function<void(BackendProbeResult)> completion);

} // namespace webserver::proxy
