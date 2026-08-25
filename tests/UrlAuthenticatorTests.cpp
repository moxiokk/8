#include "policy/UrlAuthenticator.hpp"

#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

webserver::policy::UrlAuthSpec full_site_spec() {
    webserver::policy::UrlAuthSpec spec;
    spec.enabled = true;
    spec.primary_key = "aliyuncdnexp1234";
    spec.validity_seconds = 1800;
    return spec;
}

void test_official_type_a_vector_and_parameter_removal() {
    using webserver::policy::UrlAuthenticator;
    UrlAuthenticator authenticator{full_site_spec()};
    constexpr std::string_view auth_key =
        "1444435200-0-0-23bf85053008f5c0e791667a313e28ce";

    const auto accepted = authenticator.authenticate(
        "/video/standard/test.mp4?quality=hd&auth_key=" + std::string{auth_key} +
            "&sign=legacy&time=1444435200&download=1",
        1444435200);
    require(accepted.allowed && accepted.authentication_applied,
            "Alibaba Cloud type A reference signature was rejected");
    require(
        accepted.rewritten_target == "/video/standard/test.mp4?quality=hd&download=1",
        "signing parameters were not removed while retaining application query parameters");

    const auto expires_at_boundary = authenticator.authenticate(
        "/video/standard/test.mp4?auth_key=" + std::string{auth_key},
        1444437000);
    require(expires_at_boundary.allowed,
            "signature was rejected at the documented expiration boundary");
}

void test_rejections() {
    using webserver::policy::UrlAuthenticator;
    UrlAuthenticator authenticator{full_site_spec()};
    constexpr std::string_view valid =
        "/video/standard/test.mp4?auth_key="
        "1444435200-0-0-23bf85053008f5c0e791667a313e28ce";

    require(!authenticator.authenticate("/video/standard/test.mp4", 1444435200).allowed,
            "missing auth_key was accepted");
    require(!authenticator.authenticate(valid, 1444437001).allowed,
            "expired auth_key was accepted");
    require(authenticator.authenticate(
                "/video/standard/test.mp4?auth_key="
                "1444435500-0-0-94efd29583a2a5ebcc025b4a143b311a",
                1444435200)
                 .allowed,
            "auth_key within the five-minute clock-skew allowance was rejected");
    require(!authenticator.authenticate(
                "/video/standard/test.mp4?auth_key="
                "1444435501-0-0-a9901884b16afad37d3a94223f48243b",
                1444435200)
                 .allowed,
            "auth_key more than five minutes in the future was accepted");
    require(!authenticator.authenticate(
                "/video/standard/test.mp4?auth_key="
                "1444435200-0-0-13bf85053008f5c0e791667a313e28ce",
                1444435200)
                 .allowed,
            "incorrect digest was accepted");
    require(!authenticator.authenticate(
                std::string{valid} +
                    "&auth_key=1444435200-0-0-23bf85053008f5c0e791667a313e28ce",
                1444435200)
                 .allowed,
            "duplicate auth_key parameters were accepted");
    require(!authenticator.authenticate(
                "/video/standard/test.mp4?auth_key=1444435200-0-0-NOT-A-DIGEST",
                1444435200)
                 .allowed,
            "malformed auth_key was accepted");
}

void test_primary_backup_keys_and_selected_uris() {
    using namespace webserver::policy;
    UrlAuthSpec spec;
    spec.enabled = true;
    spec.scope = UrlAuthScope::specified;
    spec.primary_key = "PrimaryKey123";
    spec.backup_key = "BackupKey123";
    spec.validity_seconds = 1800;
    spec.protected_uris = {
        UrlAuthUriSpec{"/private/file.zip", UrlAuthMatch::exact},
        UrlAuthUriSpec{"/video/", UrlAuthMatch::prefix}};
    UrlAuthenticator authenticator{std::move(spec)};

    const auto bypassed = authenticator.authenticate("/public/file.zip", 1700000000);
    require(bypassed.allowed && !bypassed.authentication_applied &&
                bypassed.rewritten_target.empty(),
            "an unprotected URI did not bypass URL authentication");
    require(!authenticator.authenticate("/private/file.zip/extra", 1700000000)
                 .authentication_applied,
            "an exact URI rule matched a longer path");

    const auto backup = authenticator.authenticate(
        "/private/file.zip?auth_key="
        "1700000000-abc-0-b122e842750e17c9f541ac4d148fd63f",
        1700000001);
    require(backup.allowed && backup.rewritten_target == "/private/file.zip",
            "backup KEY signature was rejected");

    const auto primary = authenticator.authenticate(
        "/video/a.mp4?auth_key="
        "1700000000-0-0-9b4daca1a7f9cbff00f703f0c22e4b8f",
        1700000001);
    require(primary.allowed && primary.rewritten_target == "/video/a.mp4",
            "prefix URI rule or primary KEY signature failed");
}

void test_configuration_validation() {
    using namespace webserver::policy;
    const auto rejected = [](UrlAuthSpec spec) {
        try {
            const UrlAuthenticator ignored{std::move(spec)};
            static_cast<void>(ignored);
            return false;
        } catch (const std::invalid_argument&) {
            return true;
        }
    };

    UrlAuthSpec no_key;
    no_key.enabled = true;
    require(rejected(std::move(no_key)), "enabled URL authentication accepted no KEY");

    UrlAuthSpec short_key;
    short_key.enabled = true;
    short_key.primary_key = "short";
    require(rejected(std::move(short_key)), "a KEY shorter than six characters was accepted");

    UrlAuthSpec no_selected_uri;
    no_selected_uri.enabled = true;
    no_selected_uri.primary_key = "PrimaryKey123";
    no_selected_uri.scope = UrlAuthScope::specified;
    require(rejected(std::move(no_selected_uri)),
            "specified scope accepted an empty URI rule set");

    UrlAuthSpec invalid_uri;
    invalid_uri.enabled = true;
    invalid_uri.primary_key = "PrimaryKey123";
    invalid_uri.scope = UrlAuthScope::specified;
    invalid_uri.protected_uris = {UrlAuthUriSpec{"video/", UrlAuthMatch::prefix}};
    require(rejected(std::move(invalid_uri)), "a relative protected URI was accepted");
}

} // namespace

int main() {
    try {
        test_official_type_a_vector_and_parameter_removal();
        test_rejections();
        test_primary_backup_keys_and_selected_uris();
        test_configuration_validation();
        std::cout << "URL authenticator tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "URL authenticator tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
