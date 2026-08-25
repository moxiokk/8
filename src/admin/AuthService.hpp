#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace webserver::database {
class ConfigRepository;
}

namespace webserver::admin {

struct AuthSessionOptions final {
    std::chrono::steady_clock::duration lifetime{std::chrono::hours{8}};
    std::size_t maximum_active_sessions{4096};
};

class AuthService final {
public:
    explicit AuthService(
        database::ConfigRepository& repository,
        AuthSessionOptions session_options = {});

    [[nodiscard]] bool setup_required();
    [[nodiscard]] std::string create_first_admin(
        std::string username,
        std::string_view password,
        std::string_view remote_ip);
    [[nodiscard]] std::string login(
        const std::string& username,
        std::string_view password,
        std::string_view remote_ip);
    [[nodiscard]] bool authorize(std::string_view token);
    void logout(std::string_view token);

    [[nodiscard]] static std::string session_cookie(std::string_view token);
    [[nodiscard]] static std::string expired_session_cookie();

private:
    struct Session final {
        std::chrono::steady_clock::time_point expires_at;
    };

    struct FailureBucket final {
        unsigned int failures{};
        std::chrono::steady_clock::time_point window_started{};
    };

    static constexpr int password_iterations = 310000;
    static constexpr std::size_t salt_bytes = 16;
    static constexpr std::size_t hash_bytes = 32;
    static constexpr std::size_t token_bytes = 32;

    void check_rate_limit(std::string_view remote_ip);
    void record_failure(std::string_view remote_ip);
    void clear_failures(std::string_view remote_ip);
    void purge_expired_sessions(std::chrono::steady_clock::time_point now);
    [[nodiscard]] std::string issue_session();

    database::ConfigRepository& repository_;
    AuthSessionOptions session_options_;
    std::mutex mutex_;
    std::unordered_map<std::string, Session> sessions_;
    std::unordered_map<std::string, FailureBucket> failures_;
};

} // namespace webserver::admin
