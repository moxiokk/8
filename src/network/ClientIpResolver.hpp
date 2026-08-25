#pragma once

#include <boost/asio/ip/address.hpp>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace webserver::network {

class ClientIpResolver final {
public:
    ClientIpResolver(
        std::vector<std::string> trusted_proxy_cidrs = {},
        std::vector<std::string> header_priority = {
            "EO-Connecting-IP", "CF-Connecting-IP", "True-Client-IP", "X-Forwarded-For"});

    [[nodiscard]] std::string resolve(
        const boost::asio::ip::address& peer,
        const std::vector<std::pair<std::string, std::string>>& headers) const;
    [[nodiscard]] const std::vector<std::string>& header_priority() const noexcept;
    [[nodiscard]] bool is_trusted(const boost::asio::ip::address& address) const noexcept;

    struct Range final {
        boost::asio::ip::address network;
        std::uint8_t prefix{};
    };

private:
    std::vector<Range> ranges_;
    std::vector<std::string> header_priority_;
};

} // namespace webserver::network
