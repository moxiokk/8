#include "routing/HostNormalizer.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <limits>

namespace webserver::routing {
namespace {

bool valid_port(std::string_view port) {
    if (port.empty()) {
        return false;
    }

    std::uint32_t value = 0;
    for (const unsigned char character : port) {
        if (!std::isdigit(character)) {
            return false;
        }
        value = (value * 10U) + static_cast<std::uint32_t>(character - '0');
        if (value > std::numeric_limits<std::uint16_t>::max()) {
            return false;
        }
    }
    return true;
}

bool valid_ipv4_address(std::string_view address) {
    std::size_t component_start = 0;
    std::size_t component_count = 0;

    while (component_start < address.size()) {
        const auto component_end = address.find('.', component_start);
        const auto end = component_end == std::string_view::npos
                             ? address.size()
                             : component_end;
        const auto component = address.substr(component_start, end - component_start);
        if (component.empty() || component.size() > 3) {
            return false;
        }

        std::uint32_t value = 0;
        for (const unsigned char character : component) {
            if (!std::isdigit(character)) {
                return false;
            }
            value = (value * 10U) + static_cast<std::uint32_t>(character - '0');
        }
        if (value > 255U) {
            return false;
        }

        ++component_count;
        if (component_end == std::string_view::npos) {
            break;
        }
        component_start = component_end + 1;
    }

    return component_count == 4;
}

bool count_ipv6_groups(
    std::string_view sequence,
    int& group_count,
    bool allow_ipv4_tail) {
    if (sequence.empty()) {
        return true;
    }
    if (sequence.back() == ':') {
        return false;
    }

    std::size_t group_start = 0;
    while (group_start < sequence.size()) {
        const auto group_end = sequence.find(':', group_start);
        const auto end = group_end == std::string_view::npos
                             ? sequence.size()
                             : group_end;
        const auto group = sequence.substr(group_start, end - group_start);
        if (group.empty()) {
            return false;
        }

        if (group.find('.') != std::string_view::npos) {
            if (!allow_ipv4_tail ||
                group_end != std::string_view::npos ||
                !valid_ipv4_address(group)) {
                return false;
            }
            group_count += 2;
        } else {
            if (group.size() > 4 ||
                !std::all_of(group.begin(), group.end(), [](const unsigned char character) {
                    return std::isxdigit(character);
                })) {
                return false;
            }
            ++group_count;
        }

        if (group_end == std::string_view::npos) {
            break;
        }
        group_start = group_end + 1;
    }
    return true;
}

bool valid_ipv6_literal(std::string_view literal) {
    if (literal.empty()) {
        return false;
    }

    const auto compression = literal.find("::");
    if (compression == std::string_view::npos) {
        int group_count = 0;
        return count_ipv6_groups(literal, group_count, true) && group_count == 8;
    }

    if (literal.find("::", compression + 2) != std::string_view::npos) {
        return false;
    }

    int group_count = 0;
    const auto left = literal.substr(0, compression);
    const auto right = literal.substr(compression + 2);
    return count_ipv6_groups(left, group_count, false) &&
           count_ipv6_groups(right, group_count, true) &&
           group_count < 8;
}

bool valid_dns_name(std::string_view host) {
    if (host.empty() || host.size() > 253 || host.back() == '.') {
        return false;
    }

    std::size_t label_start = 0;
    while (label_start < host.size()) {
        const auto label_end = host.find('.', label_start);
        const auto end = label_end == std::string_view::npos ? host.size() : label_end;
        const auto label = host.substr(label_start, end - label_start);

        if (label.empty() || label.size() > 63 || label.front() == '-' || label.back() == '-') {
            return false;
        }

        const bool valid_label = std::all_of(
            label.begin(), label.end(), [](const unsigned char character) {
                return std::isalnum(character) || character == '-';
            });
        if (!valid_label) {
            return false;
        }

        if (label_end == std::string_view::npos) {
            break;
        }
        label_start = label_end + 1;
    }
    return true;
}

std::optional<std::string> normalize(std::string_view authority, bool allow_port) {
    if (authority.empty()) {
        return std::nullopt;
    }

    const bool contains_invalid_character = std::any_of(
        authority.begin(), authority.end(), [](const unsigned char character) {
            return character <= 0x20U || character >= 0x7FU;
        });
    if (contains_invalid_character) {
        return std::nullopt;
    }

    std::string_view host;
    if (authority.front() == '[') {
        const auto closing_bracket = authority.find(']');
        if (closing_bracket == std::string_view::npos) {
            return std::nullopt;
        }

        host = authority.substr(1, closing_bracket - 1);
        const auto remainder = authority.substr(closing_bracket + 1);
        if (!remainder.empty()) {
            if (!allow_port || remainder.front() != ':' || !valid_port(remainder.substr(1))) {
                return std::nullopt;
            }
        }
        if (!valid_ipv6_literal(host)) {
            return std::nullopt;
        }
    } else {
        const auto colon = authority.find(':');
        if (colon == std::string_view::npos) {
            host = authority;
        } else {
            if (!allow_port || authority.find(':', colon + 1) != std::string_view::npos) {
                return std::nullopt;
            }
            host = authority.substr(0, colon);
            if (!valid_port(authority.substr(colon + 1))) {
                return std::nullopt;
            }
        }

        if (!host.empty() && host.back() == '.') {
            host.remove_suffix(1);
        }
        if (!valid_dns_name(host)) {
            return std::nullopt;
        }
    }

    std::string normalized{host};
    std::transform(
        normalized.begin(), normalized.end(), normalized.begin(), [](const unsigned char character) {
            return static_cast<char>(std::tolower(character));
        });
    return normalized;
}

} // namespace

std::optional<std::string> HostNormalizer::normalize_authority(std::string_view authority) {
    return normalize(authority, true);
}

std::optional<std::string> HostNormalizer::normalize_domain(std::string_view domain) {
    return normalize(domain, false);
}

} // namespace webserver::routing
