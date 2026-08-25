#pragma once

#include "config/RuntimeConfig.hpp"
#include "database/ConfigRepository.hpp"
#include "routing/VirtualHostRouter.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

namespace webserver::config {

class ConfigService final {
public:
    class Activation final {
    public:
        Activation() = default;

        template <typename Handler>
            requires(
                !std::is_same_v<std::remove_cvref_t<Handler>, Activation> &&
                std::is_nothrow_invocable_v<std::decay_t<Handler>&>)
        Activation(Handler&& handler)
            : handler_(std::forward<Handler>(handler)) {}

        void operator()() noexcept {
            if (handler_) handler_();
        }

        [[nodiscard]] explicit operator bool() const noexcept {
            return static_cast<bool>(handler_);
        }

    private:
        std::function<void()> handler_;
    };

    using ReloadHandler = std::function<Activation(RuntimeConfigSpec)>;

    explicit ConfigService(database::ConfigRepository& repository);

    void initialize();
    void set_reload_handler(ReloadHandler handler);
    void mark_runtime_unavailable();
    void reload_runtime();
    [[nodiscard]] std::vector<routing::VirtualHostConfig> load_runtime_sites();
    [[nodiscard]] std::vector<RuntimeSiteConfig> load_runtime_site_configs();
    [[nodiscard]] RuntimeConfigSpec load_runtime_config();
    [[nodiscard]] std::vector<database::SiteRecord> list_sites();
    [[nodiscard]] database::SiteRecord create_site(database::SiteRecord site);
    [[nodiscard]] database::SiteRecord update_site(database::SiteRecord site);
    void delete_site(std::int64_t id);
    void seed_default_certificate(
        std::string name,
        std::vector<std::string> domains,
        std::string certificate_pem,
        std::string private_key_pem);
    [[nodiscard]] std::vector<database::CertificateRecord> list_certificates();
    [[nodiscard]] database::CertificateRecord find_certificate(std::int64_t id);
    [[nodiscard]] database::CertificateRecord create_certificate(
        database::CertificateRecord certificate);
    [[nodiscard]] database::CertificateRecord update_certificate(
        database::CertificateRecord certificate);
    void delete_certificate(std::int64_t id);
    [[nodiscard]] database::RuntimeSettingsRecord runtime_settings();
    [[nodiscard]] database::RuntimeSettingsRecord update_runtime_settings(
        database::RuntimeSettingsRecord settings);
    [[nodiscard]] std::string export_configuration();
    void import_configuration(std::string_view encoded);

    [[nodiscard]] std::uint64_t active_revision() const;
    [[nodiscard]] std::uint64_t stored_revision();
    [[nodiscard]] bool restart_required();
    [[nodiscard]] bool hot_reload_enabled() const;

private:
    static void validate_and_normalize(database::SiteRecord& site);
    [[nodiscard]] static policy::SitePolicySpec runtime_policy(
        const database::SiteRecord& site);
    [[nodiscard]] static policy::UrlAuthSpec runtime_url_auth(
        const database::SiteRecord& site);
    [[nodiscard]] std::vector<RuntimeSiteConfig> load_runtime_site_configs_locked();
    [[nodiscard]] RuntimeConfigSpec build_runtime_spec_locked(std::uint64_t revision);
    [[nodiscard]] RuntimeConfigSpec build_runtime_spec(
        const std::vector<database::SiteRecord>& sites,
        const std::vector<database::CertificateRecord>& certificates,
        const database::RuntimeSettingsRecord& settings,
        std::uint64_t revision);
    [[nodiscard]] Activation prepare_candidate_locked(RuntimeConfigSpec candidate);
    void commit_candidate_locked(Activation activation, std::uint64_t revision) noexcept;
    static void validate_and_normalize_certificate(database::CertificateRecord& certificate);
    static void validate_runtime_settings(database::RuntimeSettingsRecord& settings);
    void activate_latest_locked();

    database::ConfigRepository& repository_;
    mutable std::mutex mutex_;
    std::uint64_t active_revision_{0};
    ReloadHandler reload_handler_;
};

} // namespace webserver::config
