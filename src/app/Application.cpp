#include "app/Application.hpp"

#include "BuildInfo.hpp"
#include "admin/AdminServer.hpp"
#include "admin/AuthService.hpp"
#include "config/ConfigService.hpp"
#include "core/ServerCore.hpp"
#include "database/ConfigRepository.hpp"
#include "database/Database.hpp"
#include "logging/LogManager.hpp"
#include "service/WindowsService.hpp"

#include <boost/asio/signal_set.hpp>

#include <csignal>
#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <fstream>
#include <iostream>
#include <iterator>
#include <memory>
#include <stop_token>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

namespace webserver::app {
namespace {

std::string read_text_file(const std::filesystem::path& path) {
    std::ifstream input{path, std::ios::binary};
    if (!input) throw std::runtime_error{"cannot read required file: " + path.string()};
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}

void print_version() {
    std::cout << "WebServer " << build::version << '\n';
}

void print_help() {
    print_version();
    std::cout
        << "Usage:\n"
        << "  WebServer [--help] [--version]\n"
        << "  WebServer --service\n"
        << "  WebServer --install-service\n"
        << "  WebServer --uninstall-service\n\n"
        << "Without an option, starts public HTTP/HTTPS listeners on 0.0.0.0:80/443\n"
        << "and the authenticated admin panel on http://127.0.0.1:3312.\n"
        << "The initial site is example.com -> 127.0.0.1:8090.\n"
        << "Admin saves and access policies are hot reloaded without restarting.\n"
        << "JSON Lines access/error logs are written under the logs directory.\n"
        << "Press Ctrl+C to stop accepting connections and shut down cleanly.\n";
}

int run_server(
    const std::filesystem::path& executable_directory,
    std::stop_token stop_token,
    service::WindowsService::ReadyHandler ready,
    bool console_mode,
    std::function<void()> request_stop = {}) {
    const auto certificate_directory = executable_directory / "certs";
    const auto database_path = executable_directory / "data" / "webserver.db";
    const auto admin_assets = executable_directory / "admin-ui";
    const auto log_directory = executable_directory / "logs";

    auto logger = std::make_shared<logging::LogManager>(
        logging::LogOptions{log_directory});
    logger->log_error(
        logging::ErrorSeverity::info,
        "application",
        "WebServer " + std::string{build::version} + " is starting");

    try {
        database::Database database{database_path};
        database::ConfigRepository repository{database};
        config::ConfigService config_service{repository};
        config_service.initialize();
        admin::AuthService auth_service{repository};
        std::unique_ptr<core::ServerCore> server;
        std::atomic<core::ServerCore*> active_server{nullptr};
        admin::AdminServer admin_server{
            config_service,
            auth_service,
            admin_assets,
            3312,
            logger,
            [&active_server] {
                const auto current = active_server.load(std::memory_order_acquire);
                return current ? current->listener_statuses()
                               : std::vector<core::ListenerStatus>{};
            }};

        std::stop_callback stop_callback{stop_token, [&active_server, &admin_server, logger] {
            logger->log_error(
                logging::ErrorSeverity::info,
                "application",
                "graceful shutdown requested");
            admin_server.stop();
            if (const auto current = active_server.load(std::memory_order_acquire)) {
                current->stop();
            }
        }};

        std::string data_plane_error;
        try {
            if (config_service.list_certificates().empty()) {
                config_service.seed_default_certificate(
                    "example.com development certificate",
                    {"example.com", "www.example.com"},
                    read_text_file(certificate_directory / "example.com.crt"),
                    read_text_file(certificate_directory / "example.com.key"));
            }
            core::ServerOptions options;
            options.bind_address = "0.0.0.0";
            options.runtime_config = config_service.load_runtime_config();
            options.logger = logger;
            server = std::make_unique<core::ServerCore>(std::move(options));
            auto* const server_ptr = server.get();
            config_service.set_reload_handler(
                [server_ptr, logger](config::RuntimeConfigSpec next) {
                    const auto revision = next.revision;
                    try {
                        auto activation = server_ptr->prepare_reload(std::move(next));
                        return [activation = std::move(activation), logger, revision]() mutable noexcept {
                            activation();
                            try {
                                logger->log_error(
                                    logging::ErrorSeverity::info,
                                    "runtime_config",
                                    "published configuration revision " + std::to_string(revision));
                            } catch (...) {
                            }
                        };
                    } catch (const std::exception& error) {
                        logger->log_error(
                            logging::ErrorSeverity::error,
                            "runtime_config",
                            "reload rejected before database commit: " +
                                std::string{error.what()});
                        throw;
                    }
                });
            server->start();
            active_server.store(server.get(), std::memory_order_release);
        } catch (const std::exception& error) {
            data_plane_error = error.what();
            config_service.mark_runtime_unavailable();
            server.reset();
            logger->log_error(
                logging::ErrorSeverity::critical,
                "runtime_config",
                "data plane disabled; Admin recovery mode is available: " + data_plane_error);
        }

        admin_server.start();
        std::unique_ptr<boost::asio::signal_set> signals;
        if (console_mode) {
            signals = std::make_unique<boost::asio::signal_set>(
                admin_server.io_context(), SIGINT, SIGTERM);
            signals->async_wait(
                [request_stop = std::move(request_stop)](
                    const boost::system::error_code& error,
                    int) {
                    if (!error && request_stop) {
                        request_stop();
                    }
                });
        }

        const auto admin_endpoint = admin_server.local_endpoint();
        const auto statuses = server ? server->listener_statuses()
                                     : std::vector<core::ListenerStatus>{};
        logger->log_error(
            logging::ErrorSeverity::info,
            "application",
            server ? "Admin and data listeners are ready"
                   : "Admin recovery listener is ready; data listeners are disabled");
        ready();

        if (console_mode) {
            print_version();
            for (const auto& status : statuses) {
                std::cout << status.protocol << " reverse proxy listening on "
                          << status.address << ':' << status.bound_port << '\n';
            }
            if (!server) {
                std::cout << "Data plane disabled: " << data_plane_error << '\n';
            }
            std::cout
                << "Admin panel: http://127.0.0.1:" << admin_endpoint.port() << '\n'
                << "SQLite configuration: " << database_path.string() << '\n'
                << "Logs: " << log_directory.string() << '\n'
                << "Worker threads: " << (server ? server->worker_count() : 0) << '\n'
                << std::flush;
        }

        if (stop_token.stop_requested()) {
            admin_server.stop();
            if (server) server->stop();
        }
        if (server) {
            server->wait();
            active_server.store(nullptr, std::memory_order_release);
            admin_server.stop();
        }
        admin_server.wait();
        logger->log_error(
            logging::ErrorSeverity::info,
            "application",
            "WebServer stopped cleanly");
        logger->flush();
        return 0;
    } catch (const std::exception& error) {
        logger->log_error(
            logging::ErrorSeverity::critical,
            "application",
            "startup or runtime failure: " + std::string{error.what()});
        logger->flush();
        throw;
    } catch (...) {
        logger->log_error(
            logging::ErrorSeverity::critical,
            "application",
            "unknown startup or runtime failure");
        logger->flush();
        throw;
    }
}

} // namespace

int Application::run(int argc, char* argv[]) const {
    if (argc > 2) {
        std::cerr << "error: expected at most one option\n";
        return 2;
    }

    const auto executable_path = std::filesystem::absolute(std::filesystem::path{argv[0]});
    const auto executable_directory = executable_path.parent_path();

    if (argc == 2) {
        const std::string_view option{argv[1]};
        if (option == "--version") {
            print_version();
            return 0;
        }
        if (option == "--help" || option == "-h") {
            print_help();
            return 0;
        }
        if (option == "--install-service") {
            service::WindowsService::install(executable_path);
            std::cout << "WebServer service installed\n";
            return 0;
        }
        if (option == "--uninstall-service") {
            service::WindowsService::uninstall();
            std::cout << "WebServer service removed\n";
            return 0;
        }
        if (option == "--service") {
            return service::WindowsService{}.run(
                [executable_directory](
                    std::stop_token stop_token,
                    service::WindowsService::ReadyHandler ready) {
                    return run_server(
                        executable_directory,
                        stop_token,
                        std::move(ready),
                        false);
                });
        }

        std::cerr << "error: unknown option: " << option << '\n';
        return 2;
    }

    std::stop_source stop_source;
    return run_server(
        executable_directory,
        stop_source.get_token(),
        [] {},
        true,
        [&stop_source] { stop_source.request_stop(); });
}

} // namespace webserver::app
