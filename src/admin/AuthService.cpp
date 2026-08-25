#include "admin/AuthService.hpp"

#include "database/ConfigRepository.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <vector>

namespace webserver::admin {
namespace {

using namespace std::chrono_literals;

std::vector<unsigned char> random_bytes(std::size_t size) {
    std::vector<unsigned char> output(size);
    if (RAND_bytes(output.data(), static_cast<int>(output.size())) != 1) {
        throw std::runtime_error{"cryptographic random generator failed"};
    }
    return output;
}

std::vector<unsigned char> derive_password(
    std::string_view password,
    const std::vector<unsigned char>& salt,
    int iterations,
    std::size_t output_size) {
    std::vector<unsigned char> output(output_size);
    if (PKCS5_PBKDF2_HMAC(
            password.data(),
            static_cast<int>(password.size()),
            salt.data(),
            static_cast<int>(salt.size()),
            iterations,
            EVP_sha256(),
            static_cast<int>(output.size()),
            output.data()) != 1) {
        throw std::runtime_error{"password derivation failed"};
    }
    return output;
}

std::string to_hex(const std::vector<unsigned char>& bytes) {
    constexpr char alphabet[] = "0123456789abcdef";
    std::string output(bytes.size() * 2, '0');
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        output[index * 2] = alphabet[bytes[index] >> 4];
        output[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
    }
    return output;
}

void validate_credentials(std::string_view username, std::string_view password) {
    if (username.size() < 3 || username.size() > 64 ||
        !std::all_of(username.begin(), username.end(), [](unsigned char character) {
            return std::isalnum(character) != 0 || character == '_' || character == '-';
        })) {
        throw std::invalid_argument{
            "username must contain 3 to 64 letters, numbers, hyphens or underscores"};
    }
    if (password.size() < 12 || password.size() > 256) {
        throw std::invalid_argument{"password must contain 12 to 256 characters"};
    }
}

} // namespace

AuthService::AuthService(
    database::ConfigRepository& repository,
    AuthSessionOptions session_options)
    : repository_(repository), session_options_(session_options) {
    if (session_options_.lifetime <= std::chrono::steady_clock::duration::zero()) {
        throw std::invalid_argument{"admin session lifetime must be positive"};
    }
    if (session_options_.maximum_active_sessions == 0) {
        throw std::invalid_argument{"maximum active admin sessions must be positive"};
    }
}

bool AuthService::setup_required() {
    std::scoped_lock lock{mutex_};
    return repository_.admin_user_count() == 0;
}

std::string AuthService::create_first_admin(
    std::string username,
    std::string_view password,
    std::string_view remote_ip) {
    validate_credentials(username, password);
    std::scoped_lock lock{mutex_};
    check_rate_limit(remote_ip);
    if (repository_.admin_user_count() != 0) {
        throw std::logic_error{"administrator setup has already been completed"};
    }

    database::AdminUserRecord user;
    user.username = std::move(username);
    user.password_salt = random_bytes(salt_bytes);
    user.password_iterations = password_iterations;
    user.password_hash = derive_password(
        password, user.password_salt, user.password_iterations, hash_bytes);
    repository_.create_admin_user(user);
    clear_failures(remote_ip);
    return issue_session();
}

std::string AuthService::login(
    const std::string& username,
    std::string_view password,
    std::string_view remote_ip) {
    std::scoped_lock lock{mutex_};
    check_rate_limit(remote_ip);

    try {
        const auto user = repository_.find_admin_user(username);
        const auto candidate = derive_password(
            password,
            user.password_salt,
            user.password_iterations,
            user.password_hash.size());
        if (candidate.size() != user.password_hash.size() ||
            CRYPTO_memcmp(candidate.data(), user.password_hash.data(), candidate.size()) != 0) {
            throw std::invalid_argument{"invalid username or password"};
        }
    } catch (const std::invalid_argument&) {
        record_failure(remote_ip);
        throw std::invalid_argument{"invalid username or password"};
    }

    clear_failures(remote_ip);
    return issue_session();
}

bool AuthService::authorize(std::string_view token) {
    if (token.empty()) {
        return false;
    }

    std::scoped_lock lock{mutex_};
    const auto now = std::chrono::steady_clock::now();
    purge_expired_sessions(now);
    const auto session = sessions_.find(std::string{token});
    if (session == sessions_.end()) {
        return false;
    }
    session->second.expires_at = now + session_options_.lifetime;
    return true;
}

void AuthService::logout(std::string_view token) {
    std::scoped_lock lock{mutex_};
    sessions_.erase(std::string{token});
}

std::string AuthService::session_cookie(std::string_view token) {
    return "ws_admin_session=" + std::string{token} +
           "; Path=/; HttpOnly; SameSite=Strict; Max-Age=28800";
}

std::string AuthService::expired_session_cookie() {
    return "ws_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";
}

void AuthService::check_rate_limit(std::string_view remote_ip) {
    const auto now = std::chrono::steady_clock::now();
    const auto entry = failures_.find(std::string{remote_ip});
    if (entry == failures_.end()) {
        return;
    }
    if (now - entry->second.window_started > 5min) {
        failures_.erase(entry);
        return;
    }
    if (entry->second.failures >= 5) {
        throw std::runtime_error{"too many login attempts; retry later"};
    }
}

void AuthService::record_failure(std::string_view remote_ip) {
    const auto now = std::chrono::steady_clock::now();
    auto& bucket = failures_[std::string{remote_ip}];
    if (bucket.failures == 0 || now - bucket.window_started > 5min) {
        bucket.window_started = now;
        bucket.failures = 1;
    } else {
        ++bucket.failures;
    }
}

void AuthService::clear_failures(std::string_view remote_ip) {
    failures_.erase(std::string{remote_ip});
}

void AuthService::purge_expired_sessions(std::chrono::steady_clock::time_point now) {
    for (auto session = sessions_.begin(); session != sessions_.end();) {
        if (session->second.expires_at <= now) {
            session = sessions_.erase(session);
        } else {
            ++session;
        }
    }
}

std::string AuthService::issue_session() {
    const auto now = std::chrono::steady_clock::now();
    purge_expired_sessions(now);
    if (sessions_.size() >= session_options_.maximum_active_sessions) {
        const auto oldest = std::min_element(
            sessions_.begin(), sessions_.end(), [](const auto& left, const auto& right) {
                return left.second.expires_at < right.second.expires_at;
            });
        if (oldest != sessions_.end()) sessions_.erase(oldest);
    }
    const auto token = to_hex(random_bytes(token_bytes));
    sessions_.insert_or_assign(token, Session{now + session_options_.lifetime});
    return token;
}

} // namespace webserver::admin
