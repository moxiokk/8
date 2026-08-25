#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace webserver::routing {

class HostNormalizer final {
public:
    [[nodiscard]] static std::optional<std::string> normalize_authority(
        std::string_view authority);

    [[nodiscard]] static std::optional<std::string> normalize_domain(
        std::string_view domain);
};

} // namespace webserver::routing
