#pragma once

#include "config/RuntimeConfig.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/http/string_body.hpp>
#include <boost/beast/http/empty_body.hpp>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace webserver::logging {
class LogManager;
}

namespace webserver::http {

struct RequestSecurityContext final {
    std::string forwarded_scheme{"http"};
    std::optional<std::string> sni_host;
    std::function<bool(std::string_view)> certificate_matches_host;
};

class RequestDispatcher final : public std::enable_shared_from_this<RequestDispatcher> {
public:
    using Request = boost::beast::http::request<boost::beast::http::empty_body>;
    using Response = boost::beast::http::response<boost::beast::http::string_body>;
    using CompletionHandler = std::function<void(Response)>;
    using SiteResolvedHandler = std::function<void(
        std::int64_t,
        std::string_view,
        std::string_view)>;
    using ProxyHandler = std::function<void(
        routing::BackendConfig,
        Request,
        std::string,
        std::string,
        std::string,
        config::RuntimeSettings,
        routing::BackendOverloadConfig)>;

    RequestDispatcher(
        boost::asio::any_io_executor executor,
        std::shared_ptr<const config::RuntimeConfig> runtime_config,
        std::uint16_t listener_port,
        Request request,
        std::string client_ip,
        RequestSecurityContext security,
        SiteResolvedHandler on_site_resolved,
        ProxyHandler on_proxy,
        std::shared_ptr<logging::LogManager> logger,
        CompletionHandler on_complete);

    void start();
    void cancel();
    void complete_stream(unsigned status, std::uint64_t response_bytes);

private:
    void complete(Response response);
    void log_access(unsigned status, std::uint64_t response_bytes);

    boost::asio::any_io_executor executor_;
    std::shared_ptr<const config::RuntimeConfig> runtime_config_;
    std::uint16_t listener_port_{};
    Request request_;
    std::string client_ip_;
    RequestSecurityContext security_;
    SiteResolvedHandler on_site_resolved_;
    ProxyHandler on_proxy_;
    std::shared_ptr<logging::LogManager> logger_;
    CompletionHandler on_complete_;
    std::chrono::steady_clock::time_point started_at_;
    std::string request_id_;
    std::string request_method_;
    std::string request_path_;
    std::string request_host_;
    bool completed_{false};
};

} // namespace webserver::http
