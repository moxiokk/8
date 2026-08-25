#pragma once

#include "core/ServerCore.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/beast/http/string_body.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace webserver::admin {

class AuthService;

}

namespace webserver::config {

class ConfigService;

}

namespace webserver::logging {
class LogManager;
}

namespace webserver::proxy {
class BackendProbeOperation;
}

namespace webserver::admin {

class AdminApi final {
public:
    using Request = boost::beast::http::request<boost::beast::http::string_body>;
    using Response = boost::beast::http::response<boost::beast::http::string_body>;
    using ResponseHandler = std::function<void(Response)>;
    using FailureHandler = std::function<void()>;

    AdminApi(
        config::ConfigService& config_service,
        AuthService& auth_service,
        std::shared_ptr<logging::LogManager> logger = {},
        std::function<std::vector<core::ListenerStatus>()> listener_status_provider = {});

    [[nodiscard]] Response handle(const Request& request, std::string_view remote_ip);
    [[nodiscard]] std::shared_ptr<proxy::BackendProbeOperation> handle_async(
        Request request,
        std::string remote_ip,
        boost::asio::any_io_executor executor,
        ResponseHandler completion,
        FailureHandler failure = {});

private:
    [[nodiscard]] Response handle_authenticated(
        const Request& request,
        std::string_view path,
        std::string_view token);

    config::ConfigService& config_service_;
    AuthService& auth_service_;
    std::shared_ptr<logging::LogManager> logger_;
    std::function<std::vector<core::ListenerStatus>()> listener_status_provider_;
    std::chrono::steady_clock::time_point started_at_;
};

} // namespace webserver::admin
