#include "http/RequestDispatcher.hpp"

#include "config/RuntimeConfig.hpp"
#include "logging/LogManager.hpp"
#include "routing/HostNormalizer.hpp"
#include "routing/VirtualHostRouter.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/beast/version.hpp>
#include <boost/beast/websocket/rfc6455.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <string_view>
#include <utility>

namespace webserver::http {
namespace beast = boost::beast;
namespace http = beast::http;

namespace {

RequestDispatcher::Response make_text_response(
    const RequestDispatcher::Request& request,
    http::status status,
    std::string_view body,
    bool keep_alive) {
    RequestDispatcher::Response response{status, request.version()};
    response.set(http::field::server, BOOST_BEAST_VERSION_STRING);
    response.set(http::field::content_type, "text/plain; charset=utf-8");
    response.keep_alive(keep_alive);

    if (request.method() == http::verb::head) {
        response.content_length(body.size());
    } else {
        response.body() = std::string{body};
        response.prepare_payload();
    }
    return response;
}

bool valid_reverse_proxy_target(const RequestDispatcher::Request& request) {
    const auto target = request.target();
    if (target.empty()) {
        return false;
    }
    if (target == "*") {
        return request.method() == http::verb::options;
    }
    return target.front() == '/';
}

} // namespace

RequestDispatcher::RequestDispatcher(
    boost::asio::any_io_executor executor,
    std::shared_ptr<const config::RuntimeConfig> runtime_config,
    std::uint16_t listener_port,
    Request request,
    std::string client_ip,
    RequestSecurityContext security,
    SiteResolvedHandler on_site_resolved,
    ProxyHandler on_proxy,
    std::shared_ptr<logging::LogManager> logger,
    CompletionHandler on_complete)
    : executor_(std::move(executor)),
      runtime_config_(std::move(runtime_config)),
      listener_port_(listener_port),
      request_(std::move(request)),
      client_ip_(std::move(client_ip)),
      security_(std::move(security)),
      on_site_resolved_(std::move(on_site_resolved)),
      on_proxy_(std::move(on_proxy)),
      logger_(std::move(logger)),
      on_complete_(std::move(on_complete)),
      started_at_(std::chrono::steady_clock::now()) {
    const auto method = request_.method_string();
    request_method_.assign(method.data(), method.size());
    const auto target = request_.target();
    request_path_ = logging::LogManager::sanitize_request_target(
        std::string_view{target.data(), target.size()});
    const auto host = request_[http::field::host];
    request_host_.assign(host.data(), std::min<std::size_t>(host.size(), 512));
    request_id_ = logging::LogManager::next_request_id();
}

void RequestDispatcher::start() {
    if (request_.base().count(http::field::host) != 1) {
        complete(make_text_response(
            request_, http::status::bad_request, "Invalid Host header", false));
        return;
    }

    const auto host_header = request_[http::field::host];
    const auto normalized_host = routing::HostNormalizer::normalize_authority(
        std::string_view{host_header.data(), host_header.size()});
    if (!normalized_host) {
        complete(make_text_response(
            request_, http::status::bad_request, "Invalid Host header", false));
        return;
    }
    request_host_ = *normalized_host;

    const auto protocol = security_.forwarded_scheme == "https"
                              ? config::ListenerProtocol::https
                              : config::ListenerProtocol::http;
    const auto router = runtime_config_->router(protocol, listener_port_);
    const auto virtual_host = router ? router->find(*normalized_host) : nullptr;
    if (!virtual_host) {
        complete(make_text_response(
            request_,
            http::status::not_found,
            "Virtual host not found",
            request_.keep_alive()));
        return;
    }

    if (on_site_resolved_) {
        on_site_resolved_(
            virtual_host->overload().site_id,
            virtual_host->name(),
            *normalized_host);
    }

    if (security_.forwarded_scheme == "https") {
        const bool certificate_matches =
            security_.certificate_matches_host &&
            security_.certificate_matches_host(*normalized_host);
        const auto sni_virtual_host = security_.sni_host
                                          ? router->find(*security_.sni_host)
                                          : virtual_host;
        if (!certificate_matches || !sni_virtual_host ||
            sni_virtual_host.get() != virtual_host.get()) {
            complete(make_text_response(
                request_,
                http::status::misdirected_request,
                "SNI and Host do not identify the same site",
                false));
            return;
        }
    }

    if (!valid_reverse_proxy_target(request_)) {
        complete(make_text_response(
            request_, http::status::bad_request, "Invalid request target", false));
        return;
    }

    if (request_.method() == http::verb::connect) {
        complete(make_text_response(
            request_,
            http::status::not_implemented,
            "CONNECT tunneling is not supported",
            false));
        return;
    }

    const auto method_text = request_.method_string();
    const auto target_text = request_.target();
    const auto user_agent_text = request_[http::field::user_agent];
    const auto referer_text = request_[http::field::referer];
    policy::RequestView policy_request{
        std::string_view{method_text.data(), method_text.size()},
        std::string_view{target_text.data(), target_text.size()},
        std::string_view{user_agent_text.data(), user_agent_text.size()},
        std::string_view{referer_text.data(), referer_text.size()},
        [this](std::string_view name) -> std::string_view {
            const auto found = request_.find(beast::string_view{name.data(), name.size()});
            if (found == request_.end()) {
                return {};
            }
            const auto value = found->value();
            return {value.data(), value.size()};
        }};
    if (const auto decision = virtual_host->request_policy()->evaluate(
            policy_request, client_ip_, *normalized_host, security_.forwarded_scheme)) {
        auto response = make_text_response(
            request_,
            static_cast<http::status>(decision->status),
            decision->body,
            request_.keep_alive());
        if (!decision->location.empty()) {
            response.set(http::field::location, decision->location);
        }
        if (decision->retry_after_seconds != 0) {
            response.set(
                http::field::retry_after,
                std::to_string(decision->retry_after_seconds));
        }
        complete(std::move(response));
        return;
    }

    const auto authentication = virtual_host->url_authenticator()->authenticate(
        std::string_view{request_.target().data(), request_.target().size()});
    if (!authentication.allowed) {
        complete(make_text_response(
            request_,
            http::status::forbidden,
            "URL authentication failed",
            request_.keep_alive()));
        return;
    }
    if (!authentication.rewritten_target.empty()) {
        request_.target(beast::string_view{
            authentication.rewritten_target.data(),
            authentication.rewritten_target.size()});
    }

    if (!on_proxy_) {
        complete(make_text_response(
            request_, http::status::internal_server_error, "Proxy handoff is unavailable", false));
        return;
    }
    on_proxy_(
        virtual_host->backend(),
        std::move(request_),
        client_ip_,
        security_.forwarded_scheme,
        request_id_,
        runtime_config_->settings(),
        virtual_host->overload());
}

void RequestDispatcher::cancel() {
    boost::asio::dispatch(executor_, [self = shared_from_this()] {
        self->on_proxy_ = {};
        self->on_site_resolved_ = {};
        self->on_complete_ = {};
    });
}

void RequestDispatcher::complete_stream(unsigned status, std::uint64_t response_bytes) {
    if (completed_) return;
    completed_ = true;
    log_access(status, response_bytes);
    on_proxy_ = {};
    on_site_resolved_ = {};
    on_complete_ = {};
}

void RequestDispatcher::complete(Response response) {
    if (completed_) {
        return;
    }
    completed_ = true;

    if (!request_id_.empty()) {
        response.set("X-Request-ID", request_id_);
    }
    log_access(response.result_int(), response.body().size());
    on_site_resolved_ = {};

    if (on_complete_) {
        auto on_complete = std::move(on_complete_);
        on_complete(std::move(response));
    }
}

void RequestDispatcher::log_access(unsigned status, std::uint64_t response_bytes) {
    if (logger_) {
        logging::AccessLogEntry entry;
        entry.request_id = request_id_;
        entry.client_ip = client_ip_;
        entry.scheme = security_.forwarded_scheme;
        entry.listener_port = listener_port_;
        entry.host = request_host_;
        entry.method = request_method_;
        entry.path = request_path_;
        entry.status = status;
        entry.response_bytes = response_bytes;
        entry.duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - started_at_);
        entry.config_revision = runtime_config_->revision();
        logger_->log_access(std::move(entry));
    }
}

} // namespace webserver::http
