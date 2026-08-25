#include "policy/UrlAuthenticator.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <charconv>
#include <chrono>
#include <limits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace webserver::policy {
namespace {

constexpr std::size_t max_uri_length = 8192;
constexpr std::size_t max_protected_uris = 200;
constexpr std::uint32_t maximum_validity_seconds = 31536000;
constexpr std::int64_t maximum_future_clock_skew_seconds = 300;

bool ascii_digit(unsigned char character) {
    return character >= static_cast<unsigned char>('0') &&
           character <= static_cast<unsigned char>('9');
}

bool ascii_alphanumeric(unsigned char character) {
    return ascii_digit(character) ||
           (character >= static_cast<unsigned char>('A') &&
            character <= static_cast<unsigned char>('Z')) ||
           (character >= static_cast<unsigned char>('a') &&
            character <= static_cast<unsigned char>('z'));
}

bool valid_key(std::string_view key) {
    return key.empty() ||
           (key.size() >= 6 && key.size() <= 128 &&
            std::all_of(key.begin(), key.end(), [](const unsigned char character) {
                return ascii_alphanumeric(character);
            }));
}

bool valid_path(std::string_view path) {
    return !path.empty() && path.size() <= max_uri_length && path.front() == '/' &&
           path.find_first_of("?#") == std::string_view::npos &&
           std::none_of(path.begin(), path.end(), [](const unsigned char character) {
               return character <= 0x20U || character == 0x7FU;
           });
}

bool lower_hex_digest(std::string_view value) {
    return value.size() == 32 &&
           std::all_of(value.begin(), value.end(), [](const unsigned char character) {
               return ascii_digit(character) ||
                      (character >= static_cast<unsigned char>('a') &&
                       character <= static_cast<unsigned char>('f'));
           });
}

std::optional<std::string> md5_hex(std::string_view value) {
    using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
    Context context{EVP_MD_CTX_new(), EVP_MD_CTX_free};
    if (!context || EVP_DigestInit_ex(context.get(), EVP_md5(), nullptr) != 1 ||
        EVP_DigestUpdate(context.get(), value.data(), value.size()) != 1) {
        return std::nullopt;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
    unsigned digest_size{};
    if (EVP_DigestFinal_ex(context.get(), digest.data(), &digest_size) != 1 ||
        digest_size != 16) {
        return std::nullopt;
    }

    constexpr std::array<char, 16> hex{
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    std::string result;
    result.resize(digest_size * 2);
    for (std::size_t index = 0; index < digest_size; ++index) {
        result[index * 2] = hex[digest[index] >> 4U];
        result[index * 2 + 1] = hex[digest[index] & 0x0FU];
    }
    return result;
}

bool digest_matches(std::string_view candidate, std::string_view expected) {
    return candidate.size() == expected.size() &&
           CRYPTO_memcmp(candidate.data(), expected.data(), candidate.size()) == 0;
}

struct ParsedQuery final {
    std::string auth_key;
    std::vector<std::string_view> retained_parameters;
    std::size_t auth_key_count{};
};

ParsedQuery parse_query(std::string_view query) {
    ParsedQuery result;
    while (!query.empty()) {
        const auto separator = query.find('&');
        const auto parameter = query.substr(0, separator);
        const auto equals = parameter.find('=');
        const auto name = parameter.substr(0, equals);
        if (name == "auth_key") {
            ++result.auth_key_count;
            if (equals != std::string_view::npos) {
                result.auth_key.assign(parameter.substr(equals + 1));
            }
        } else if (name != "sign" && name != "time" && !parameter.empty()) {
            result.retained_parameters.push_back(parameter);
        }
        if (separator == std::string_view::npos) {
            break;
        }
        query.remove_prefix(separator + 1);
    }
    return result;
}

std::string cleaned_target(
    std::string_view path,
    const std::vector<std::string_view>& parameters) {
    std::string result{path};
    if (parameters.empty()) {
        return result;
    }
    result.push_back('?');
    for (std::size_t index = 0; index < parameters.size(); ++index) {
        if (index != 0) {
            result.push_back('&');
        }
        result.append(parameters[index]);
    }
    return result;
}

} // namespace

UrlAuthenticator::UrlAuthenticator(UrlAuthSpec spec) : spec_(std::move(spec)) {
    if (spec_.validity_seconds == 0 ||
        spec_.validity_seconds > maximum_validity_seconds) {
        throw std::invalid_argument{
            "URL authentication validity must be between 1 and 31536000 seconds"};
    }
    if (!valid_key(spec_.primary_key) || !valid_key(spec_.backup_key)) {
        throw std::invalid_argument{
            "URL authentication keys must contain 6 to 128 letters or digits"};
    }
    if (spec_.enabled && spec_.primary_key.empty() && spec_.backup_key.empty()) {
        throw std::invalid_argument{"URL authentication requires a primary or backup key"};
    }
    if (spec_.protected_uris.size() > max_protected_uris) {
        throw std::invalid_argument{
            "URL authentication cannot contain more than 200 protected URI rules"};
    }

    std::unordered_set<std::string> unique_rules;
    for (const auto& rule : spec_.protected_uris) {
        if (!valid_path(rule.path)) {
            throw std::invalid_argument{
                "URL authentication protected URI must be a valid encoded absolute path"};
        }
        const auto prefix = rule.match == UrlAuthMatch::prefix ? "prefix:" : "exact:";
        if (!unique_rules.emplace(prefix + rule.path).second) {
            throw std::invalid_argument{"URL authentication contains a duplicate URI rule"};
        }
    }
    if (spec_.enabled && spec_.scope == UrlAuthScope::specified &&
        spec_.protected_uris.empty()) {
        throw std::invalid_argument{
            "specified URL authentication requires at least one protected URI"};
    }
}

UrlAuthResult UrlAuthenticator::authenticate(std::string_view target) const {
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return authenticate(target, now);
}

UrlAuthResult UrlAuthenticator::authenticate(
    std::string_view target,
    std::int64_t now_unix_seconds) const {
    const auto query_position = target.find('?');
    const auto path = target.substr(0, query_position);
    if (!spec_.enabled || !protects(path)) {
        return {};
    }

    UrlAuthResult denied{false, true, {}};
    if (query_position == std::string_view::npos) {
        return denied;
    }
    const auto parsed = parse_query(target.substr(query_position + 1));
    if (parsed.auth_key_count != 1 || parsed.auth_key.empty()) {
        return denied;
    }

    const std::string_view auth_key{parsed.auth_key};
    const auto first = auth_key.find('-');
    const auto second = first == std::string_view::npos
                            ? std::string_view::npos
                            : auth_key.find('-', first + 1);
    const auto third = second == std::string_view::npos
                           ? std::string_view::npos
                           : auth_key.find('-', second + 1);
    if (first == std::string_view::npos || second == std::string_view::npos ||
        third == std::string_view::npos || auth_key.find('-', third + 1) != std::string_view::npos) {
        return denied;
    }

    const auto timestamp_text = auth_key.substr(0, first);
    const auto random = auth_key.substr(first + 1, second - first - 1);
    const auto uid = auth_key.substr(second + 1, third - second - 1);
    const auto supplied_digest = auth_key.substr(third + 1);
    if (timestamp_text.size() != 10 || random.empty() || uid.empty() ||
        !std::all_of(timestamp_text.begin(), timestamp_text.end(), [](unsigned char character) {
            return ascii_digit(character);
        }) ||
        !lower_hex_digest(supplied_digest)) {
        return denied;
    }

    std::int64_t timestamp{};
    const auto [end, error] = std::from_chars(
        timestamp_text.data(), timestamp_text.data() + timestamp_text.size(), timestamp);
    if (error != std::errc{} || end != timestamp_text.data() + timestamp_text.size() ||
        timestamp < 0 || now_unix_seconds < 0 ||
        (timestamp > now_unix_seconds &&
         timestamp - now_unix_seconds > maximum_future_clock_skew_seconds) ||
        timestamp > std::numeric_limits<std::int64_t>::max() - spec_.validity_seconds ||
        timestamp + spec_.validity_seconds < now_unix_seconds) {
        return denied;
    }

    const auto matches_key = [&](std::string_view key) {
        if (key.empty()) {
            return false;
        }
        std::string signing_text;
        signing_text.reserve(
            path.size() + timestamp_text.size() + random.size() + uid.size() + key.size() + 4);
        signing_text.append(path);
        signing_text.push_back('-');
        signing_text.append(timestamp_text);
        signing_text.push_back('-');
        signing_text.append(random);
        signing_text.push_back('-');
        signing_text.append(uid);
        signing_text.push_back('-');
        signing_text.append(key);
        const auto expected = md5_hex(signing_text);
        return expected && digest_matches(supplied_digest, *expected);
    };

    const bool primary_matches = matches_key(spec_.primary_key);
    const bool backup_matches = matches_key(spec_.backup_key);
    if (!primary_matches && !backup_matches) {
        return denied;
    }
    return UrlAuthResult{
        true,
        true,
        cleaned_target(path, parsed.retained_parameters)};
}

bool UrlAuthenticator::protects(std::string_view path) const noexcept {
    if (spec_.scope == UrlAuthScope::all) {
        return true;
    }
    return std::any_of(
        spec_.protected_uris.begin(), spec_.protected_uris.end(), [&](const auto& rule) {
            return rule.match == UrlAuthMatch::exact ? path == rule.path
                                                     : path.starts_with(rule.path);
        });
}

} // namespace webserver::policy
