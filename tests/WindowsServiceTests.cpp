#include "service/WindowsService.hpp"

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

void run_test() {
    const auto command = webserver::service::WindowsService::service_command_line(
        std::filesystem::path{"directory with spaces"} / "WebServer.exe");
    require(command.starts_with(L"\""), "service executable is not quoted");
    require(command.ends_with(L"\" --service"), "service mode argument is missing");
    require(
        command.find(L"directory with spaces") != std::wstring::npos,
        "service executable path was changed");

    bool invalid_path_rejected = false;
    try {
        static_cast<void>(webserver::service::WindowsService::service_command_line(
            std::filesystem::path{L"invalid\"path.exe"}));
    } catch (const std::invalid_argument&) {
        invalid_path_rejected = true;
    }
    require(invalid_path_rejected, "quoted executable path was accepted");

#ifdef _WIN32
    require(webserver::service::WindowsService::supported(), "Windows service is disabled");
#else
    require(!webserver::service::WindowsService::supported(), "service is enabled off Windows");
#endif
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Windows service command tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Windows service command tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
