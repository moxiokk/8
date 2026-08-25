#include "admin/AuthService.hpp"
#include "config/ConfigService.hpp"
#include "database/ConfigRepository.hpp"
#include "database/Database.hpp"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

using namespace std::chrono_literals;

namespace {

void require(bool condition, const std::string& message) {
    if (!condition) throw std::runtime_error{message};
}

std::filesystem::path database_path() {
    return std::filesystem::temp_directory_path() /
           ("webserver-auth-test-" + std::to_string(
               std::chrono::steady_clock::now().time_since_epoch().count()) + ".db");
}

void remove_database_files(const std::filesystem::path& path) {
    std::error_code ignored;
    std::filesystem::remove(path, ignored);
    std::filesystem::remove(path.string() + "-wal", ignored);
    std::filesystem::remove(path.string() + "-shm", ignored);
}

void run_test() {
    const auto path = database_path();
    try {
        webserver::database::Database database{path};
        webserver::database::ConfigRepository repository{database};
        webserver::config::ConfigService config{repository};
        config.initialize();

        webserver::admin::AuthService bounded{
            repository,
            webserver::admin::AuthSessionOptions{1h, 2}};
        const auto first = bounded.create_first_admin(
            "admin", "correct horse battery staple", "127.0.0.1");
        const auto second = bounded.login(
            "admin", "correct horse battery staple", "127.0.0.1");
        const auto third = bounded.login(
            "admin", "correct horse battery staple", "127.0.0.1");
        require(!bounded.authorize(first), "oldest session was not evicted at the active-session cap");
        require(bounded.authorize(second) && bounded.authorize(third),
                "session cap evicted a newer active session");

        webserver::admin::AuthService expiring{
            repository,
            webserver::admin::AuthSessionOptions{20ms, 4}};
        const auto expired = expiring.login(
            "admin", "correct horse battery staple", "127.0.0.1");
        std::this_thread::sleep_for(40ms);
        const auto current = expiring.login(
            "admin", "correct horse battery staple", "127.0.0.1");
        require(!expiring.authorize(expired), "expired session remained authorized");
        require(expiring.authorize(current), "new session was not authorized after cleanup");
    } catch (...) {
        remove_database_files(path);
        throw;
    }
    remove_database_files(path);
}

} // namespace

int main() {
    try {
        run_test();
        std::cout << "Auth service tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Auth service tests failed: " << error.what() << '\n';
        return 1;
    }
}
