#pragma once

#include <filesystem>
#include <functional>
#include <stop_token>
#include <string>
#include <string_view>

namespace webserver::service {

class WindowsService final {
public:
    using ReadyHandler = std::function<void()>;
    using Worker = std::function<int(std::stop_token, ReadyHandler)>;

    static constexpr std::wstring_view name{L"WebServer"};
    static constexpr std::wstring_view display_name{L"WebServer Reverse Proxy"};

    [[nodiscard]] int run(Worker worker) const;

    static void install(const std::filesystem::path& executable_path);
    static void uninstall();

    [[nodiscard]] static std::wstring service_command_line(
        const std::filesystem::path& executable_path);
    [[nodiscard]] static bool supported() noexcept;
};

} // namespace webserver::service
