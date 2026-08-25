#include "config/RuntimeConfig.hpp"
#include "tls/TlsContextManager.hpp"

#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

template <typename Callable>
void require_rejected(Callable&& callable, const std::string& message) {
    bool rejected = false;
    try {
        callable();
    } catch (const std::invalid_argument&) {
        rejected = true;
    }
    require(rejected, message);
}

void run_tests(char* argv[]) {
    using webserver::tls::TlsCertificateConfig;
    using webserver::tls::TlsContextManager;

    const std::string a_certificate{argv[1]};
    const std::string a_key{argv[2]};
    const std::string b_certificate{argv[3]};
    const std::string b_key{argv[4]};
    const auto read_file = [](const std::string& path) {
        std::ifstream input{path, std::ios::binary};
        if (!input) throw std::runtime_error{"cannot read TLS fixture"};
        return std::string{
            std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
    };

    TlsContextManager valid_manager{{
        TlsCertificateConfig{
            "a", {"a.test", "*.a.test"}, a_certificate, a_key, true},
        TlsCertificateConfig{
            "b", {"b.test"}, b_certificate, b_key, false},
    }};
    require(
        valid_manager.default_context()->name() == "a",
        "explicit default TLS certificate was not selected");
    require(
        valid_manager.default_context()->matches_domain("www.a.test"),
        "certificate domain matcher rejected a configured domain");
    require(
        !valid_manager.default_context()->matches_domain("b.test"),
        "certificate domain matcher accepted another certificate's domain");
    require(
        !valid_manager.default_context()->matches_domain("deep.www.a.test"),
        "TLS wildcard matched more than one DNS label");
    require(
        valid_manager.can_serve_domain("*.a.test") &&
            !valid_manager.can_serve_domain("*.b.test"),
        "TLS certificate coverage validation is incorrect");

    const TlsContextManager inline_manager{{
        TlsCertificateConfig{
            "inline-a", {"a.test", "*.a.test"}, {}, {}, true,
            read_file(a_certificate), read_file(a_key)},
    }};
    require(
        inline_manager.can_serve_domain("a.test"),
        "inline PEM certificate was not loaded for database-backed TLS management");

    auto runtime_spec = [&] {
        webserver::config::RuntimeConfigSpec spec;
        webserver::config::RuntimeSiteConfig site;
        site.virtual_host = webserver::routing::VirtualHostConfig{
            "secure-site",
            {"a.test"},
            webserver::routing::BackendConfig{"127.0.0.1", 9000}};
        site.http_enabled = false;
        site.https_enabled = true;
        site.https_port = 8443;
        spec.sites.push_back(std::move(site));
        spec.tls_certificates = {
            TlsCertificateConfig{
                "a", {"a.test", "*.a.test"}, a_certificate, a_key, true},
        };
        return spec;
    };

    auto first_runtime = webserver::config::build_runtime_config(runtime_spec());
    webserver::config::RuntimeConfigStore runtime_store{first_runtime};
    const auto old_tls_contexts = first_runtime->tls_contexts();
    runtime_store.publish(webserver::config::build_runtime_config(runtime_spec()));
    require(
        runtime_store.load()->tls_contexts().get() != old_tls_contexts.get(),
        "certificate reload reused the old TLS context manager");
    require(
        old_tls_contexts->default_context()->matches_domain("a.test"),
        "old TLS context was invalidated while an existing connection could still hold it");

    require_rejected(
        [&] {
            const TlsContextManager manager{{
                TlsCertificateConfig{
                    "mismatched-key", {"a.test"}, a_certificate, b_key, true},
            }};
            static_cast<void>(manager);
        },
        "certificate/private-key mismatch was accepted");

    require_rejected(
        [&] {
            const TlsContextManager manager{{
                TlsCertificateConfig{
                    "wrong-domain", {"b.test"}, a_certificate, a_key, true},
            }};
            static_cast<void>(manager);
        },
        "certificate that does not cover its configured domain was accepted");

    require_rejected(
        [&] {
            const TlsContextManager manager{{
                TlsCertificateConfig{
                    "first", {"a.test"}, a_certificate, a_key, true},
                TlsCertificateConfig{
                    "second", {"A.TEST."}, a_certificate, a_key, false},
            }};
            static_cast<void>(manager);
        },
        "duplicate normalized SNI domain was accepted");

    require_rejected(
        [&] {
            const TlsContextManager manager{{
                TlsCertificateConfig{
                    "first", {"a.test"}, a_certificate, a_key, true},
                TlsCertificateConfig{
                    "second", {"b.test"}, b_certificate, b_key, true},
            }};
            static_cast<void>(manager);
        },
        "multiple default TLS certificates were accepted");
}

} // namespace

int main(int argc, char* argv[]) {
    try {
        if (argc != 5) {
            throw std::runtime_error{"expected four certificate fixture paths"};
        }
        run_tests(argv);
        std::cout << "TLS context tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "TLS context tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
