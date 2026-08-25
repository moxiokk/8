#pragma once

#include <boost/asio/ssl/context.hpp>

#include <openssl/ssl.h>

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace webserver::tls {

struct TlsCertificateConfig final {
    std::string name;
    std::vector<std::string> domains;
    std::string certificate_chain_file;
    std::string private_key_file;
    bool is_default{false};
    std::string certificate_chain_pem;
    std::string private_key_pem;
};

class SslContextHolder final {
public:
    explicit SslContextHolder(TlsCertificateConfig config);

    [[nodiscard]] boost::asio::ssl::context& context() noexcept;
    [[nodiscard]] SSL_CTX* native_handle() noexcept;
    [[nodiscard]] const std::string& name() const noexcept;
    [[nodiscard]] bool matches_domain(std::string_view normalized_host) const noexcept;
    [[nodiscard]] const std::vector<std::string>& exact_domains() const noexcept;
    [[nodiscard]] const std::vector<std::string>& wildcard_domains() const noexcept;

private:
    std::string name_;
    std::vector<std::string> exact_domains_;
    std::vector<std::string> wildcard_domains_;
    boost::asio::ssl::context context_;
};

struct TlsConnectionState final {
    std::shared_ptr<SslContextHolder> selected_context;
    std::optional<std::string> sni_host;
};

class TlsContextManager final {
public:
    explicit TlsContextManager(
        std::vector<TlsCertificateConfig> certificates,
        bool reject_unknown_sni = true);

    TlsContextManager(const TlsContextManager&) = delete;
    TlsContextManager& operator=(const TlsContextManager&) = delete;

    [[nodiscard]] std::shared_ptr<SslContextHolder> default_context() const noexcept;
    [[nodiscard]] bool can_serve_domain(std::string_view domain_pattern) const;
    void initialize_connection(SSL* ssl, TlsConnectionState& state) const;

private:
    using ContextPtr = std::shared_ptr<SslContextHolder>;

    [[nodiscard]] ContextPtr find(std::string_view normalized_host) const;
    static int server_name_callback(SSL* ssl, int* alert, void* argument) noexcept;
    static int connection_state_index();

    std::vector<ContextPtr> contexts_;
    ContextPtr default_context_;
    std::unordered_map<std::string, ContextPtr> exact_contexts_;
    std::vector<std::pair<std::string, ContextPtr>> wildcard_contexts_;
    bool reject_unknown_sni_;
};

} // namespace webserver::tls
