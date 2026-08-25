#include "logging/LogManager.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <iterator>
#include <random>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace webserver::logging {
namespace {

std::string json_escape(std::string_view value) {
    std::string result;
    result.reserve(value.size() + 8);
    constexpr char hexadecimal[] = "0123456789abcdef";
    for (const unsigned char character : value) {
        switch (character) {
        case '\"': result += "\\\""; break;
        case '\\': result += "\\\\"; break;
        case '\b': result += "\\b"; break;
        case '\f': result += "\\f"; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (character < 0x20U) {
                result += "\\u00";
                result += hexadecimal[(character >> 4U) & 0x0fU];
                result += hexadecimal[character & 0x0fU];
            } else {
                result += static_cast<char>(character);
            }
        }
    }
    return result;
}

std::string timestamp_text(std::chrono::system_clock::time_point timestamp) {
    const auto time = std::chrono::system_clock::to_time_t(timestamp);
    std::tm utc{};
#ifdef _WIN32
    gmtime_s(&utc, &time);
#else
    gmtime_r(&time, &utc);
#endif
    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()) % 1000;

    std::ostringstream output;
    output << std::put_time(&utc, "%Y-%m-%dT%H:%M:%S") << '.'
           << std::setw(3) << std::setfill('0') << milliseconds.count() << 'Z';
    return output.str();
}

std::string_view severity_text(ErrorSeverity severity) {
    switch (severity) {
    case ErrorSeverity::info: return "info";
    case ErrorSeverity::warning: return "warning";
    case ErrorSeverity::error: return "error";
    case ErrorSeverity::critical: return "critical";
    }
    return "error";
}

std::uint64_t request_id_prefix() noexcept {
    static const std::uint64_t prefix = []() noexcept {
        try {
            std::random_device random;
            return (static_cast<std::uint64_t>(random()) << 32U) ^ random();
        } catch (...) {
            return static_cast<std::uint64_t>(
                std::chrono::steady_clock::now().time_since_epoch().count());
        }
    }();
    return prefix;
}

std::atomic_uint64_t request_id_sequence{};

std::string access_line(
    std::chrono::system_clock::time_point timestamp,
    const AccessLogEntry& entry) {
    std::ostringstream output;
    output << "{\"timestamp\":\"" << timestamp_text(timestamp)
           << "\",\"request_id\":\"" << json_escape(entry.request_id)
           << "\",\"client_ip\":\"" << json_escape(entry.client_ip)
           << "\",\"scheme\":\"" << json_escape(entry.scheme)
           << "\",\"listener_port\":" << entry.listener_port
           << ",\"host\":\"" << json_escape(entry.host)
           << "\",\"method\":\"" << json_escape(entry.method)
           << "\",\"path\":\"" << json_escape(entry.path)
           << "\",\"status\":" << entry.status
           << ",\"response_bytes\":" << entry.response_bytes
           << ",\"duration_ms\":" << std::fixed << std::setprecision(3)
           << static_cast<double>(entry.duration.count()) / 1000.0
           << ",\"config_revision\":" << entry.config_revision << '}';
    return output.str();
}

std::string error_line(
    std::chrono::system_clock::time_point timestamp,
    ErrorSeverity severity,
    std::string_view component,
    std::string_view message,
    std::string_view request_id) {
    std::ostringstream output;
    output << "{\"timestamp\":\"" << timestamp_text(timestamp)
           << "\",\"level\":\"" << severity_text(severity)
           << "\",\"component\":\"" << json_escape(component)
           << "\",\"message\":\"" << json_escape(message) << '\"';
    if (!request_id.empty()) {
        output << ",\"request_id\":\"" << json_escape(request_id) << '\"';
    }
    output << '}';
    return output.str();
}

} // namespace

LogManager::LogManager(LogOptions options)
    : options_(std::move(options)) {
    if (options_.directory.empty()) {
        throw std::invalid_argument{"log directory must not be empty"};
    }
    if (options_.max_file_bytes < 1024U) {
        throw std::invalid_argument{"log max file size must be at least 1024 bytes"};
    }
    if (options_.rotated_file_count == 0 || options_.rotated_file_count > 100) {
        throw std::invalid_argument{"rotated log file count must be between 1 and 100"};
    }
    if (options_.queue_capacity < 2 || options_.queue_capacity > 1'000'000) {
        throw std::invalid_argument{"log queue capacity must be between 2 and 1000000"};
    }

    std::filesystem::create_directories(options_.directory);
    access_file_ = open_file(options_.directory / "access.log");
    error_file_ = open_file(options_.directory / "error.log");

    writer_ = std::thread([this] { writer_loop(); });
}

LogManager::~LogManager() {
    {
        std::scoped_lock lock{mutex_};
        stopping_ = true;
    }
    ready_.notify_one();
    if (writer_.joinable()) {
        writer_.join();
    }
}

std::string LogManager::next_request_id() {
    const auto sequence = request_id_sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    std::array<char, 34> buffer{};
    std::snprintf(
        buffer.data(),
        buffer.size(),
        "%016llx%016llx",
        static_cast<unsigned long long>(request_id_prefix()),
        static_cast<unsigned long long>(sequence));
    return buffer.data();
}

void LogManager::log_access(AccessLogEntry entry) noexcept {
    enqueue(Event{std::chrono::system_clock::now(), std::move(entry)}, true);
}

void LogManager::log_error(
    ErrorSeverity severity,
    std::string component,
    std::string message,
    std::string request_id) noexcept {
    enqueue(
        Event{
            std::chrono::system_clock::now(),
            ErrorLogEntry{
                severity,
                std::move(component),
                std::move(message),
                std::move(request_id)}},
        false);
}

void LogManager::flush() {
    std::unique_lock lock{mutex_};
    drained_.wait(lock, [this] { return queue_.empty() && !writer_busy_; });
}

LogStatistics LogManager::statistics() const noexcept {
    std::scoped_lock lock{mutex_};
    return LogStatistics{
        accepted_access_, accepted_error_, dropped_access_, dropped_error_};
}

const std::filesystem::path& LogManager::directory() const noexcept {
    return options_.directory;
}

std::vector<std::string> LogManager::recent_lines(LogKind kind, std::size_t maximum_lines) {
    if (maximum_lines == 0 || maximum_lines > 100000) {
        throw std::invalid_argument{"log scan limit must be between 1 and 100000"};
    }
    flush();
    const auto base = options_.directory /
        (kind == LogKind::access ? "access.log" : "error.log");
    std::deque<std::string> lines;
    const auto prepend_file = [&lines, maximum_lines](const std::filesystem::path& path) {
        const auto remaining = maximum_lines - lines.size();
        if (remaining == 0) return;
        std::ifstream input{path, std::ios::binary};
        std::deque<std::string> file_lines;
        std::string line;
        while (std::getline(input, line)) {
            if (line.size() > 1024 * 1024) continue;
            file_lines.push_back(std::move(line));
            if (file_lines.size() > remaining) file_lines.pop_front();
        }
        lines.insert(
            lines.begin(),
            std::make_move_iterator(file_lines.begin()),
            std::make_move_iterator(file_lines.end()));
    };
    prepend_file(base);
    for (std::size_t index = 1;
         index <= options_.rotated_file_count && lines.size() < maximum_lines;
         ++index) {
        prepend_file(std::filesystem::path{base.string() + "." + std::to_string(index)});
    }
    return {std::make_move_iterator(lines.begin()), std::make_move_iterator(lines.end())};
}

std::string LogManager::sanitize_request_target(std::string_view target) {
    const auto separator = target.find_first_of("?#");
    target = target.substr(0, separator);
    if (target.empty()) {
        return "/";
    }
    constexpr std::size_t maximum_logged_path = 4096;
    if (target.size() > maximum_logged_path) {
        target = target.substr(0, maximum_logged_path);
    }
    return std::string{target};
}

void LogManager::enqueue(Event event, bool access_event) noexcept {
    try {
        {
            std::scoped_lock lock{mutex_};
            if (stopping_) {
                if (access_event) {
                    ++dropped_access_;
                } else {
                    ++dropped_error_;
                }
                return;
            }

            if (queue_.size() >= options_.queue_capacity) {
                if (access_event) {
                    ++dropped_access_;
                    return;
                }

                const auto access = std::find_if(
                    queue_.begin(), queue_.end(), [](const Event& queued) {
                        return std::holds_alternative<AccessLogEntry>(queued.payload);
                    });
                if (access == queue_.end()) {
                    ++dropped_error_;
                    return;
                }
                queue_.erase(access);
                --accepted_access_;
                ++dropped_access_;
            }

            queue_.push_back(std::move(event));
            if (access_event) {
                ++accepted_access_;
            } else {
                ++accepted_error_;
            }
        }
        ready_.notify_one();
    } catch (...) {
        std::scoped_lock lock{mutex_};
        if (access_event) {
            ++dropped_access_;
        } else {
            ++dropped_error_;
        }
    }
}

void LogManager::writer_loop() noexcept {
    try {
        for (;;) {
            Event event;
            {
                std::unique_lock lock{mutex_};
                ready_.wait(lock, [this] { return stopping_ || !queue_.empty(); });
                if (queue_.empty() && stopping_) {
                    writer_busy_ = true;
                    lock.unlock();
                    write_drop_summary();
                    access_file_.stream.flush();
                    error_file_.stream.flush();
                    lock.lock();
                    writer_busy_ = false;
                    drained_.notify_all();
                    return;
                }
                event = std::move(queue_.front());
                queue_.pop_front();
                writer_busy_ = true;
            }

            write_event(event);

            bool queue_empty{};
            {
                std::scoped_lock lock{mutex_};
                queue_empty = queue_.empty();
            }
            if (queue_empty) {
                write_drop_summary();
                access_file_.stream.flush();
                error_file_.stream.flush();
            }
            {
                std::scoped_lock lock{mutex_};
                writer_busy_ = false;
                if (queue_.empty()) {
                    drained_.notify_all();
                }
            }
        }
    } catch (const std::exception& error) {
        std::fprintf(stderr, "logging writer failed: %s\n", error.what());
    } catch (...) {
        std::fputs("logging writer failed: unknown exception\n", stderr);
    }

    std::scoped_lock lock{mutex_};
    writer_busy_ = false;
    stopping_ = true;
    queue_.clear();
    drained_.notify_all();
}

void LogManager::write_event(const Event& event) {
    if (const auto* access = std::get_if<AccessLogEntry>(&event.payload)) {
        write_line(access_file_, access_line(event.timestamp, *access));
        return;
    }

    const auto& error = std::get<ErrorLogEntry>(event.payload);
    write_line(
        error_file_,
        error_line(
            event.timestamp,
            error.severity,
            error.component,
            error.message,
            error.request_id));
}

void LogManager::write_drop_summary() {
    std::uint64_t dropped_access{};
    std::uint64_t dropped_error{};
    {
        std::scoped_lock lock{mutex_};
        if (dropped_access_ == reported_dropped_access_ &&
            dropped_error_ == reported_dropped_error_) {
            return;
        }
        dropped_access = dropped_access_ - reported_dropped_access_;
        dropped_error = dropped_error_ - reported_dropped_error_;
        reported_dropped_access_ = dropped_access_;
        reported_dropped_error_ = dropped_error_;
    }

    write_line(
        error_file_,
        error_line(
            std::chrono::system_clock::now(),
            ErrorSeverity::warning,
            "logging",
            "asynchronous queue dropped " + std::to_string(dropped_access) +
                " access and " + std::to_string(dropped_error) + " error events",
            {}));
}

void LogManager::write_line(RotatingFile& file, std::string line) {
    line.push_back('\n');
    if (file.current_bytes != 0 &&
        file.current_bytes + line.size() > options_.max_file_bytes) {
        rotate(file);
    }
    file.stream.write(line.data(), static_cast<std::streamsize>(line.size()));
    if (!file.stream) {
        throw std::runtime_error{"cannot write log file: " + file.path.string()};
    }
    file.current_bytes += line.size();
}

void LogManager::rotate(RotatingFile& file) {
    file.stream.close();
    std::error_code error;
    const auto oldest = std::filesystem::path{
        file.path.string() + '.' + std::to_string(options_.rotated_file_count)};
    std::filesystem::remove(oldest, error);

    for (std::size_t index = options_.rotated_file_count; index > 1; --index) {
        const auto source = std::filesystem::path{
            file.path.string() + '.' + std::to_string(index - 1)};
        const auto target = std::filesystem::path{
            file.path.string() + '.' + std::to_string(index)};
        error.clear();
        if (std::filesystem::exists(source, error)) {
            std::filesystem::remove(target, error);
            error.clear();
            std::filesystem::rename(source, target, error);
            if (error) {
                throw std::filesystem::filesystem_error{
                    "cannot rotate log file", source, target, error};
            }
        }
    }

    const auto first = std::filesystem::path{file.path.string() + ".1"};
    std::filesystem::remove(first, error);
    error.clear();
    std::filesystem::rename(file.path, first, error);
    if (error) {
        throw std::filesystem::filesystem_error{
            "cannot rotate log file", file.path, first, error};
    }

    file.stream.open(file.path, std::ios::binary | std::ios::trunc);
    if (!file.stream) {
        throw std::runtime_error{"cannot reopen log file: " + file.path.string()};
    }
    file.current_bytes = 0;
}

LogManager::RotatingFile LogManager::open_file(const std::filesystem::path& path) {
    RotatingFile file;
    file.path = path;
    std::error_code error;
    if (std::filesystem::exists(path, error)) {
        file.current_bytes = std::filesystem::file_size(path, error);
        if (error) {
            throw std::filesystem::filesystem_error{
                "cannot inspect log file", path, error};
        }
    }
    file.stream.open(path, std::ios::binary | std::ios::app);
    if (!file.stream) {
        throw std::runtime_error{"cannot open log file: " + path.string()};
    }
    return file;
}

} // namespace webserver::logging
