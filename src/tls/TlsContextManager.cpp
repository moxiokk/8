#include "tls/TlsContextManager.hpp"

#include "routing/HostNormalizer.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ssl/context_base.hpp>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <memory>
#include <stdexcept>
#include <unordered_set>
#include <utility>

namespace webserver::tls {
namespace ssl = boost::asio::ssl;

namespace {

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

std::string openssl_error_text() {
    const auto error = ERR_get_error();
    if (error == 0) {
        return "unknown OpenSSL error";
    }

    std::array<char, 256> buffer{};
    ERR_error_string_n(error, buffer.data(), buffer.size());
    return buffer.data();
}

X509Ptr load_leaf_certificate(const std::string& path) {
    BioPtr file{BIO_new_file(path.c_str(), "rb"), &BIO_free};
    if (!file) {
        throw std::invalid_argument{
            "cannot open certificate file '" + path + "': " + openssl_error_text()};
    }

    X509Ptr certificate{PEM_read_bio_X509(file.get(), nullptr, nullptr, nullptr), &X509_free};
    if (!certificate) {
        throw std::invalid_argument{
            "cannot parse PEM certificate file '" + path + "': " + openssl_error_text()};
    }
    return certificate;
}

X509Ptr load_leaf_certificate_pem(const std::string& pem, const std::string& name) {
    BioPtr input{BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), &BIO_free};
    if (!input) {
        throw std::runtime_error{"cannot allocate certificate parser for '" + name + "'"};
    }
    X509Ptr certificate{
        PEM_read_bio_X509(input.get(), nullptr, nullptr, nullptr), &X509_free};
    if (!certificate) {
        throw std::invalid_argument{
            "cannot parse PEM certificate '" + name + "': " + openssl_error_text()};
    }
    return certificate;
}

std::string certificate_probe_name(std::string_view configured_domain) {
    if (configured_domain.starts_with("*.")) {
        return "certificate-check." + std::string{configured_domain.substr(2)};
    }
    return std::string{configured_domain};
}

void validate_certificate(
    X509* certificate,
    const std::string& certificate_name,
    const std::vector<std::string>& normalized_patterns) {
    if (X509_cmp_current_time(X509_get0_notBefore(certificate)) >= 0) {
        throw std::invalid_argument{
            "certificate '" + certificate_name + "' is not valid yet"};
    }
    if (X509_cmp_current_time(X509_get0_notAfter(certificate)) <= 0) {
        throw std::invalid_argument{
            "certificate '" + certificate_name + "' has expired"};
    }

    for (const auto& domain : normalized_patterns) {
        const auto probe = certificate_probe_name(domain);
        if (X509_check_host(
                certificate,
                probe.c_str(),
                probe.size(),
                X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS,
                nullptr) != 1) {
            throw std::invalid_argument{
                "certificate '" + certificate_name + "' does not cover domain " + domain};
        }
    }
}

std::vector<std::string> normalize_domains(
    const TlsCertificateConfig& config,
    const std::string& certificate_name,
    std::vector<std::string>& exact_domains,
    std::vector<std::string>& wildcard_domains) {
    if (config.domains.empty()) {
        throw std::invalid_argument{
            "TLS certificate '" + certificate_name + "' must bind at least one domain"};
    }

    std::vector<std::string> patterns;
    std::unordered_set<std::string> unique_patterns;
    for (const auto& pattern : config.domains) {
        const bool wildcard = pattern.starts_with("*.");
        const auto normalized = routing::HostNormalizer::normalize_domain(
            wildcard ? std::string_view{pattern}.substr(2) : pattern);
        if (!normalized) {
            throw std::invalid_argument{
                "invalid TLS certificate domain: " + pattern};
        }
        if (wildcard && normalized->find('.') == std::string::npos) {
            throw std::invalid_argument{
                "TLS wildcard domain is too broad: " + pattern};
        }

        const auto normalized_pattern = wildcard ? "*." + *normalized : *normalized;
        if (!unique_patterns.emplace(normalized_pattern).second) {
            throw std::invalid_argument{
                "duplicate domain on TLS certificate '" + certificate_name + "': " + pattern};
        }

        patterns.push_back(normalized_pattern);
        if (wildcard) {
            wildcard_domains.push_back(*normalized);
        } else {
            exact_domains.push_back(*normalized);
        }
    }
    return patterns;
}

int alpn_select_callback(
    SSL*,
    const unsigned char** selected,
    unsigned char* selected_length,
    const unsigned char* client_protocols,
    unsigned int client_protocols_length,
    void*) noexcept {
    static constexpr std::array<unsigned char, 9> http_1_1{
        8, 'h', 't', 't', 'p', '/', '1', '.', '1'};

    unsigned char* negotiated = nullptr;
    unsigned char negotiated_length = 0;
    const auto result = SSL_select_next_proto(
        &negotiated,
        &negotiated_length,
        http_1_1.data(),
        static_cast<unsigned int>(http_1_1.size()),
        client_protocols,
        client_protocols_length);
    if (result != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    *selected = negotiated;
    *selected_length = negotiated_length;
    return SSL_TLSEXT_ERR_OK;
}

} // namespace

SslContextHolder::SslContextHolder(TlsCertificateConfig config)
    : name_(std::move(config.name)),
      context_(ssl::context::tls_server) {
    if (name_.empty()) {
        throw std::invalid_argument{"TLS certificate name cannot be empty"};
    }
    const bool inline_pem = !config.certificate_chain_pem.empty() ||
                            !config.private_key_pem.empty();
    if (inline_pem && (config.certificate_chain_pem.empty() || config.private_key_pem.empty())) {
        throw std::invalid_argument{
            "TLS certificate '" + name_ +
            "' must provide both certificate PEM and private key PEM"};
    }
    if (!inline_pem &&
        (config.certificate_chain_file.empty() || config.private_key_file.empty())) {
        throw std::invalid_argument{
            "TLS certificate and private-key paths cannot be empty for '" + name_ + "'"};
    }

    const auto normalized_patterns = normalize_domains(
        config, name_, exact_domains_, wildcard_domains_);
    const auto leaf_certificate = inline_pem
                                      ? load_leaf_certificate_pem(
                                            config.certificate_chain_pem, name_)
                                      : load_leaf_certificate(config.certificate_chain_file);
    validate_certificate(leaf_certificate.get(), name_, normalized_patterns);

    try {
        context_.set_options(
            ssl::context::default_workarounds |
            ssl::context::no_sslv2 |
            ssl::context::no_sslv3);
        if (SSL_CTX_set_min_proto_version(context_.native_handle(), TLS1_2_VERSION) != 1) {
            throw std::runtime_error{openssl_error_text()};
        }
        SSL_CTX_set_session_cache_mode(
            context_.native_handle(), SSL_SESS_CACHE_OFF);
        SSL_CTX_set_options(context_.native_handle(), SSL_OP_NO_TICKET);
#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_CTX_set_options(context_.native_handle(), SSL_OP_NO_RENEGOTIATION);
#endif
        if (inline_pem) {
            context_.use_certificate_chain(boost::asio::buffer(config.certificate_chain_pem));
            context_.use_private_key(
                boost::asio::buffer(config.private_key_pem), ssl::context::pem);
        } else {
            context_.use_certificate_chain_file(config.certificate_chain_file);
            context_.use_private_key_file(config.private_key_file, ssl::context::pem);
        }
        if (SSL_CTX_check_private_key(context_.native_handle()) != 1) {
            throw std::runtime_error{openssl_error_text()};
        }
        SSL_CTX_set_alpn_select_cb(
            context_.native_handle(), &alpn_select_callback, nullptr);
    } catch (const std::exception& error) {
        throw std::invalid_argument{
            "failed to create TLS context '" + name_ + "': " + error.what()};
    }
}

boost::asio::ssl::context& SslContextHolder::context() noexcept {
    return context_;
}

SSL_CTX* SslContextHolder::native_handle() noexcept {
    return context_.native_handle();
}

const std::string& SslContextHolder::name() const noexcept {
    return name_;
}

bool SslContextHolder::matches_domain(std::string_view normalized_host) const noexcept {
    if (std::find(exact_domains_.begin(), exact_domains_.end(), normalized_host) !=
        exact_domains_.end()) {
        return true;
    }

    return std::any_of(
        wildcard_domains_.begin(), wildcard_domains_.end(),
        [normalized_host](const std::string& suffix) {
            if (normalized_host.size() <= suffix.size() ||
                !normalized_host.ends_with(suffix) ||
                normalized_host[normalized_host.size() - suffix.size() - 1] != '.') {
                return false;
            }
            const auto label_size = normalized_host.size() - suffix.size() - 1;
            return normalized_host.substr(0, label_size).find('.') == std::string_view::npos;
        });
}

const std::vector<std::string>& SslContextHolder::exact_domains() const noexcept {
    return exact_domains_;
}

const std::vector<std::string>& SslContextHolder::wildcard_domains() const noexcept {
    return wildcard_domains_;
}

TlsContextManager::TlsContextManager(
    std::vector<TlsCertificateConfig> certificates,
    bool reject_unknown_sni)
    : reject_unknown_sni_(reject_unknown_sni) {
    if (certificates.empty()) {
        throw std::invalid_argument{"HTTPS listener requires at least one TLS certificate"};
    }

    std::unordered_set<std::string> certificate_names;
    std::size_t default_count = 0;
    for (const auto& config : certificates) {
        if (!certificate_names.emplace(config.name).second) {
            throw std::invalid_argument{"duplicate TLS certificate name: " + config.name};
        }
        default_count += config.is_default ? 1U : 0U;
    }
    if (default_count > 1) {
        throw std::invalid_argument{"only one TLS certificate can be the default"};
    }

    contexts_.reserve(certificates.size());
    for (auto& config : certificates) {
        const bool is_default = config.is_default;
        auto holder = std::make_shared<SslContextHolder>(std::move(config));
        if (is_default || (!default_context_ && default_count == 0)) {
            default_context_ = holder;
        }

        for (const auto& domain : holder->exact_domains()) {
            if (!exact_contexts_.emplace(domain, holder).second) {
                throw std::invalid_argument{"duplicate TLS certificate domain: " + domain};
            }
        }
        for (const auto& suffix : holder->wildcard_domains()) {
            const auto duplicate = std::find_if(
                wildcard_contexts_.begin(), wildcard_contexts_.end(),
                [&suffix](const auto& entry) { return entry.first == suffix; });
            if (duplicate != wildcard_contexts_.end()) {
                throw std::invalid_argument{
                    "duplicate TLS certificate domain: *." + suffix};
            }
            wildcard_contexts_.emplace_back(suffix, holder);
        }
        contexts_.push_back(std::move(holder));
    }

    std::sort(
        wildcard_contexts_.begin(), wildcard_contexts_.end(),
        [](const auto& left, const auto& right) {
            return left.first.size() > right.first.size();
        });

    static_cast<void>(connection_state_index());
    for (const auto& context : contexts_) {
        SSL_CTX_set_tlsext_servername_callback(
            context->native_handle(), &TlsContextManager::server_name_callback);
        SSL_CTX_set_tlsext_servername_arg(context->native_handle(), this);
    }
}

std::shared_ptr<SslContextHolder> TlsContextManager::default_context() const noexcept {
    return default_context_;
}

bool TlsContextManager::can_serve_domain(std::string_view domain_pattern) const {
    const bool wildcard = domain_pattern.starts_with("*.");
    const auto normalized = routing::HostNormalizer::normalize_domain(
        wildcard ? domain_pattern.substr(2) : domain_pattern);
    if (!normalized) {
        return false;
    }

    if (wildcard) {
        return std::any_of(
            contexts_.begin(), contexts_.end(),
            [&normalized](const ContextPtr& context) {
                const auto& wildcards = context->wildcard_domains();
                return std::find(wildcards.begin(), wildcards.end(), *normalized) !=
                       wildcards.end();
            });
    }

    const auto probe = *normalized;
    const auto selected = find(probe);
    return selected && selected->matches_domain(probe);
}

void TlsContextManager::initialize_connection(SSL* ssl, TlsConnectionState& state) const {
    state.selected_context = default_context_;
    state.sni_host.reset();
    if (SSL_set_ex_data(ssl, connection_state_index(), &state) != 1) {
        throw std::runtime_error{"failed to initialize TLS connection state"};
    }
}

TlsContextManager::ContextPtr TlsContextManager::find(
    std::string_view normalized_host) const {
    const auto exact = exact_contexts_.find(std::string{normalized_host});
    if (exact != exact_contexts_.end()) {
        return exact->second;
    }

    for (const auto& [suffix, context] : wildcard_contexts_) {
        if (normalized_host.size() > suffix.size() &&
            normalized_host.ends_with(suffix) &&
            normalized_host[normalized_host.size() - suffix.size() - 1] == '.' &&
            normalized_host.substr(0, normalized_host.size() - suffix.size() - 1).find('.') ==
                std::string_view::npos) {
            return context;
        }
    }
    return {};
}

int TlsContextManager::server_name_callback(
    SSL* ssl,
    int* alert,
    void* argument) noexcept {
    try {
        auto* manager = static_cast<TlsContextManager*>(argument);
        auto* state = static_cast<TlsConnectionState*>(
            SSL_get_ex_data(ssl, connection_state_index()));
        if (!manager || !state) {
            if (alert) {
                *alert = SSL_AD_INTERNAL_ERROR;
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        const char* server_name = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (!server_name) {
            state->selected_context = manager->default_context_;
            state->sni_host.reset();
            return SSL_TLSEXT_ERR_OK;
        }

        auto normalized = routing::HostNormalizer::normalize_domain(server_name);
        const auto selected = normalized ? manager->find(*normalized) : ContextPtr{};
        if (!selected) {
            if (manager->reject_unknown_sni_) {
                if (alert) {
                    *alert = SSL_AD_UNRECOGNIZED_NAME;
                }
                return SSL_TLSEXT_ERR_ALERT_FATAL;
            }
            state->selected_context = manager->default_context_;
            state->sni_host = std::move(normalized);
            return SSL_TLSEXT_ERR_OK;
        }

        if (!SSL_set_SSL_CTX(ssl, selected->native_handle())) {
            if (alert) {
                *alert = SSL_AD_INTERNAL_ERROR;
            }
            return SSL_TLSEXT_ERR_ALERT_FATAL;
        }

        state->selected_context = selected;
        state->sni_host = std::move(normalized);
        return SSL_TLSEXT_ERR_OK;
    } catch (...) {
        if (alert) {
            *alert = SSL_AD_INTERNAL_ERROR;
        }
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
}

int TlsContextManager::connection_state_index() {
    static const int index = SSL_get_ex_new_index(0, nullptr, nullptr, nullptr, nullptr);
    if (index < 0) {
        throw std::runtime_error{"failed to allocate OpenSSL connection-state index"};
    }
    return index;
}

} // namespace webserver::tls
