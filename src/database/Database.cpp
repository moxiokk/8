#include "database/Database.hpp"

#include <sqlite3.h>

#include <stdexcept>
#include <string>

namespace webserver::database {

namespace {

std::runtime_error sqlite_error(sqlite3* handle, std::string_view operation) {
    return std::runtime_error{
        std::string{operation} + ": " + (handle ? sqlite3_errmsg(handle) : "unknown SQLite error")};
}

} // namespace

Database::Database(const std::filesystem::path& path) {
    if (path.has_parent_path()) {
        std::filesystem::create_directories(path.parent_path());
    }

    const auto path_text = path.u8string();
    const auto open_result = sqlite3_open_v2(
        reinterpret_cast<const char*>(path_text.c_str()),
        &handle_,
        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX,
        nullptr);
    if (open_result != SQLITE_OK) {
        const auto error = sqlite_error(handle_, "cannot open configuration database");
        if (handle_) {
            sqlite3_close(handle_);
            handle_ = nullptr;
        }
        throw error;
    }

    sqlite3_extended_result_codes(handle_, 1);
    execute("PRAGMA journal_mode = WAL;");
    execute("PRAGMA synchronous = FULL;");
    execute("PRAGMA foreign_keys = ON;");
    execute("PRAGMA busy_timeout = 5000;");
}

Database::~Database() {
    if (handle_) {
        sqlite3_close(handle_);
    }
}

void Database::execute(std::string_view sql) {
    char* error_message = nullptr;
    const auto result = sqlite3_exec(
        handle_, std::string{sql}.c_str(), nullptr, nullptr, &error_message);
    if (result == SQLITE_OK) {
        return;
    }

    std::string message = error_message ? error_message : sqlite3_errmsg(handle_);
    sqlite3_free(error_message);
    throw std::runtime_error{"SQLite statement failed: " + message};
}

sqlite3* Database::handle() const noexcept {
    return handle_;
}

} // namespace webserver::database
