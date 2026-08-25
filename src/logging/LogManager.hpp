#pragma once

#include <chrono>
#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

namespace webserver::logging {

enum class ErrorSeverity {
    info,
    warning,
    error,
    critical,
};

enum class LogKind {
    access,
    error,
};

struct LogOptions final {
    std::filesystem::path directory;
    std::uintmax_t max_file_bytes{20U * 1024U * 1024U};
    std::size_t rotated_file_count{10};
    std::size_t queue_capacity{8192};
};

struct AccessLogEntry final {
    std::string request_id;
    std::string client_ip;
    std::string scheme;
    std::uint16_t listener_port{};
    std::string host;
    std::string method;
    std::string path;
    unsigned status{};
    std::uint64_t response_bytes{};
    std::chrono::microseconds duration{};
    std::uint64_t config_revision{};
};

struct LogStatistics final {
    std::uint64_t accepted_access{};
    std::uint64_t accepted_error{};
    std::uint64_t dropped_access{};
    std::uint64_t dropped_error{};
};

class LogManager final {
public:
    explicit LogManager(LogOptions options);
    ~LogManager();

    LogManager(const LogManager&) = delete;
    LogManager& operator=(const LogManager&) = delete;
    LogManager(LogManager&&) = delete;
    LogManager& operator=(LogManager&&) = delete;

    [[nodiscard]] static std::string next_request_id();
    void log_access(AccessLogEntry entry) noexcept;
    void log_error(
        ErrorSeverity severity,
        std::string component,
        std::string message,
        std::string request_id = {}) noexcept;
    void flush();

    [[nodiscard]] LogStatistics statistics() const noexcept;
    [[nodiscard]] const std::filesystem::path& directory() const noexcept;
    [[nodiscard]] std::vector<std::string> recent_lines(
        LogKind kind,
        std::size_t maximum_lines = 50000);

    [[nodiscard]] static std::string sanitize_request_target(std::string_view target);

private:
    struct ErrorLogEntry final {
        ErrorSeverity severity{ErrorSeverity::error};
        std::string component;
        std::string message;
        std::string request_id;
    };

    struct Event final {
        std::chrono::system_clock::time_point timestamp;
        std::variant<AccessLogEntry, ErrorLogEntry> payload;
    };

    struct RotatingFile final {
        std::filesystem::path path;
        std::ofstream stream;
        std::uintmax_t current_bytes{};
    };

    void enqueue(Event event, bool access_event) noexcept;
    void writer_loop() noexcept;
    void write_event(const Event& event);
    void write_drop_summary();
    void write_line(RotatingFile& file, std::string line);
    void rotate(RotatingFile& file);
    static RotatingFile open_file(const std::filesystem::path& path);

    LogOptions options_;
    RotatingFile access_file_;
    RotatingFile error_file_;
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::condition_variable drained_;
    std::deque<Event> queue_;
    std::thread writer_;
    std::uint64_t accepted_access_{};
    std::uint64_t accepted_error_{};
    std::uint64_t dropped_access_{};
    std::uint64_t dropped_error_{};
    std::uint64_t reported_dropped_access_{};
    std::uint64_t reported_dropped_error_{};
    bool writer_busy_{false};
    bool stopping_{false};
};

using LogManagerPtr = std::shared_ptr<LogManager>;

} // namespace webserver::logging
