#include "network/ClientIpResolver.hpp"

#include <boost/asio/ip/address.hpp>
#include <boost/beast/core/string.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <optional>
#include <stdexcept>

namespace webserver::network {
namespace {

std::string_view trim(std::string_view value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.remove_suffix(1);
    return value;
}

ClientIpResolver::Range parse_range(const std::string& text) {
    const auto slash = text.find('/');
    const auto address_text = slash == std::string::npos ? text : text.substr(0, slash);
    boost::system::error_code error;
    auto address = boost::asio::ip::make_address(address_text, error);
    if (error) throw std::invalid_argument{"invalid trusted proxy CIDR: " + text};

    const unsigned maximum = address.is_v4() ? 32U : 128U;
    unsigned prefix = maximum;
    if (slash != std::string::npos) {
        const auto prefix_text = std::string_view{text}.substr(slash + 1);
        const auto [end, parse_error] = std::from_chars(
            prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
        if (parse_error != std::errc{} || end != prefix_text.data() + prefix_text.size() ||
            prefix > maximum) {
            throw std::invalid_argument{"invalid trusted proxy CIDR prefix: " + text};
        }
    }
    return {address, static_cast<std::uint8_t>(prefix)};
}

bool contains(const ClientIpResolver::Range& range, const boost::asio::ip::address& candidate) {
    if (range.network.is_v4() != candidate.is_v4()) return false;
    if (candidate.is_v4()) {
        const auto prefix = static_cast<unsigned>(range.prefix);
        const std::uint32_t mask = prefix == 0 ? 0U : 0xffffffffU << (32U - prefix);
        return (range.network.to_v4().to_uint() & mask) ==
               (candidate.to_v4().to_uint() & mask);
    }
    const auto network = range.network.to_v6().to_bytes();
    const auto address = candidate.to_v6().to_bytes();
    const auto full_bytes = static_cast<std::size_t>(range.prefix / 8);
    const auto remaining = static_cast<unsigned>(range.prefix % 8);
    if (!std::equal(network.begin(), network.begin() + full_bytes, address.begin())) return false;
    if (remaining == 0) return true;
    const auto mask = static_cast<unsigned char>(0xffU << (8U - remaining));
    return (network[full_bytes] & mask) == (address[full_bytes] & mask);
}

std::optional<boost::asio::ip::address> parse_ip(std::string_view value) {
    value = trim(value);
    if (value.empty()) return std::nullopt;
    boost::system::error_code error;
    auto address = boost::asio::ip::make_address(value, error);
    if (error) return std::nullopt;
    return address;
}

} // namespace

ClientIpResolver::ClientIpResolver(
    std::vector<std::string> trusted_proxy_cidrs,
    std::vector<std::string> header_priority)
    : header_priority_(std::move(header_priority)) {
    ranges_.reserve(trusted_proxy_cidrs.size());
    for (const auto& cidr : trusted_proxy_cidrs) ranges_.push_back(parse_range(cidr));
}

bool ClientIpResolver::is_trusted(const boost::asio::ip::address& address) const noexcept {
    return std::any_of(ranges_.begin(), ranges_.end(),
        [&address](const Range& range) { return contains(range, address); });
}

std::string ClientIpResolver::resolve(
    const boost::asio::ip::address& peer,
    const std::vector<std::pair<std::string, std::string>>& headers) const {
    if (!is_trusted(peer)) return peer.to_string();

    for (const auto& [name, value] : headers) {
        if (value.empty()) continue;
        if (boost::beast::iequals(
                boost::beast::string_view{name.data(), name.size()}, "X-Forwarded-For")) {
            std::vector<boost::asio::ip::address> chain;
            std::size_t start = 0;
            while (start <= value.size() && chain.size() < 64) {
                const auto comma = value.find(',', start);
                const auto end = comma == std::string::npos ? value.size() : comma;
                const auto parsed = parse_ip(std::string_view{value}.substr(start, end - start));
                if (!parsed) {
                    chain.clear();
                    break;
                }
                chain.push_back(*parsed);
                if (comma == std::string::npos) break;
                start = comma + 1;
            }
            auto current = peer;
            for (auto iterator = chain.rbegin(); iterator != chain.rend(); ++iterator) {
                if (!is_trusted(current)) break;
                current = *iterator;
            }
            if (!chain.empty()) return current.to_string();
            continue;
        }
        if (const auto single = parse_ip(value)) return single->to_string();
    }
    return peer.to_string();
}

const std::vector<std::string>& ClientIpResolver::header_priority() const noexcept {
    return header_priority_;
}

} // namespace webserver::network
