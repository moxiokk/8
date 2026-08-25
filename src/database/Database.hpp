#pragma once

#include <filesystem>
#include <string_view>

struct sqlite3;

namespace webserver::database {

class Database final {
public:
    explicit Database(const std::filesystem::path& path);
    ~Database();

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;
    Database(Database&&) = delete;
    Database& operator=(Database&&) = delete;

    void execute(std::string_view sql);
    [[nodiscard]] sqlite3* handle() const noexcept;

private:
    sqlite3* handle_{nullptr};
};

} // namespace webserver::database
