#include "logging/LogManager.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <mutex>
#include <thread>
#include <unordered_set>
#include <vector>

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error{message};
    }
}

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void run_test() {
    static_assert(
        !noexcept(webserver::logging::LogManager::next_request_id()),
        "request ID allocation failures must remain catchable");
    const auto suffix = std::to_string(
        std::chrono::steady_clock::now().time_since_epoch().count());
    std::error_code temp_error;
    auto temporary_root = std::filesystem::temp_directory_path(temp_error);
    if (temp_error) {
        temporary_root = std::filesystem::current_path();
    }
    const auto directory = temporary_root / ("webserver-logging-tests-" + suffix);
    std::filesystem::create_directories(directory);

    try {
        webserver::logging::LogOptions options;
        options.directory = directory;
        options.max_file_bytes = 1024;
        options.rotated_file_count = 2;
        options.queue_capacity = 32;
        webserver::logging::LogManager logger{options};

        require(
            webserver::logging::LogManager::sanitize_request_target(
                "/download/file.zip?token=secret&user=alice#fragment") ==
                "/download/file.zip",
            "query values were not removed from the logged target");
        require(
            webserver::logging::LogManager::sanitize_request_target("?secret=value") == "/",
            "empty target path was not normalized");

        const auto first_id = logger.next_request_id();
        const auto second_id = logger.next_request_id();
        require(first_id.size() == 32, "request ID is not 128-bit hexadecimal text");
        require(first_id != second_id, "request IDs are not unique");

        for (unsigned index = 0; index < 200; ++index) {
            webserver::logging::AccessLogEntry entry;
            entry.request_id = logger.next_request_id();
            entry.client_ip = "127.0.0.1";
            entry.scheme = "http";
            entry.listener_port = 8080;
            entry.host = "example.test";
            entry.method = "GET";
            entry.path = "/asset/" + std::to_string(index);
            entry.status = 200;
            entry.response_bytes = 128;
            entry.duration = std::chrono::microseconds{1500};
            entry.config_revision = 7;
            logger.log_access(std::move(entry));
        }
        std::mutex identifiers_mutex;
        std::unordered_set<std::string> identifiers;
        std::vector<std::thread> producers;
        for (unsigned producer = 0; producer < 4; ++producer) {
            producers.emplace_back([&logger, &identifiers, &identifiers_mutex, producer] {
                for (unsigned index = 0; index < 100; ++index) {
                    auto request_id = logger.next_request_id();
                    {
                        std::scoped_lock lock{identifiers_mutex};
                        identifiers.insert(request_id);
                    }
                    webserver::logging::AccessLogEntry entry;
                    entry.request_id = std::move(request_id);
                    entry.client_ip = "127.0.0.1";
                    entry.scheme = "http";
                    entry.listener_port = 8080;
                    entry.host = "concurrent.test";
                    entry.method = "GET";
                    entry.path = "/producer/" + std::to_string(producer) + '/' +
                                 std::to_string(index);
                    entry.status = 204;
                    entry.config_revision = 7;
                    logger.log_access(std::move(entry));
                }
            });
        }
        for (auto& producer : producers) {
            producer.join();
        }
        require(identifiers.size() == 400, "concurrent request IDs are not unique");
        logger.flush();

        webserver::logging::AccessLogEntry final_entry;
        final_entry.request_id = "final-request-id";
        final_entry.client_ip = "127.0.0.1";
        final_entry.scheme = "https";
        final_entry.listener_port = 8443;
        final_entry.host = "example.test";
        final_entry.method = "POST";
        final_entry.path = "/final";
        final_entry.status = 201;
        final_entry.response_bytes = 42;
        final_entry.duration = std::chrono::microseconds{2500};
        final_entry.config_revision = 8;
        logger.log_access(std::move(final_entry));
        logger.log_error(
            webserver::logging::ErrorSeverity::error,
            "unit_test",
            "quoted \"message\"\nnext line",
            "final-request-id");
        logger.flush();

        require(std::filesystem::exists(directory / "access.log"), "access.log is missing");
        require(std::filesystem::exists(directory / "access.log.1"), "access log did not rotate");
        const auto access = read_file(directory / "access.log");
        const auto errors = read_file(directory / "error.log");
        require(
            access.find("\"request_id\":\"final-request-id\"") != std::string::npos &&
                access.find("\"path\":\"/final\"") != std::string::npos &&
                access.find("\"status\":201") != std::string::npos,
            "final structured access event is incomplete");
        require(
            errors.find("\"level\":\"error\"") != std::string::npos &&
                errors.find("quoted \\\"message\\\"\\nnext line") != std::string::npos,
            "error event was not JSON escaped");
        const auto recent_access = logger.recent_lines(webserver::logging::LogKind::access, 1000);
        const auto recent_error = logger.recent_lines(webserver::logging::LogKind::error, 1000);
        require(
            !recent_access.empty() &&
                recent_access.back().find("\"request_id\":\"final-request-id\"") != std::string::npos,
            "recent access reader did not include the newest rotated log entry");
        require(
            std::any_of(recent_error.begin(), recent_error.end(), [](const std::string& line) {
                return line.find("\"component\":\"unit_test\"") != std::string::npos;
            }),
            "recent error reader returned the wrong entries");

        const auto statistics = logger.statistics();
        require(
            statistics.accepted_access + statistics.dropped_access == 601,
            "access queue accounting is inconsistent");
        require(
            statistics.accepted_error + statistics.dropped_error == 1,
            "error queue accounting is inconsistent");
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove_all(directory, ignored);
        throw;
    }

    std::error_code ignored;
    std::filesystem::remove_all(directory, ignored);
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Logging tests passed\n";
        return EXIT_SUCCESS;
    } catch (const std::exception& error) {
        std::cerr << "Logging tests failed: " << error.what() << '\n';
        return EXIT_FAILURE;
    }
}
