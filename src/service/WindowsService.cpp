#include "service/WindowsService.hpp"

#include <chrono>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <utility>

#ifdef _WIN32

#include <windows.h>

#include <array>
#include <memory>
#include <string_view>

namespace webserver::service {
namespace {

class ServiceHandle final {
public:
    explicit ServiceHandle(SC_HANDLE value = nullptr) noexcept : value_(value) {}
    ~ServiceHandle() {
        if (value_ != nullptr) {
            CloseServiceHandle(value_);
        }
    }

    ServiceHandle(const ServiceHandle&) = delete;
    ServiceHandle& operator=(const ServiceHandle&) = delete;

    [[nodiscard]] SC_HANDLE get() const noexcept { return value_; }
    [[nodiscard]] explicit operator bool() const noexcept { return value_ != nullptr; }

private:
    SC_HANDLE value_{};
};

[[noreturn]] void throw_last_error(std::string_view operation) {
    throw std::system_error{
        static_cast<int>(GetLastError()), std::system_category(), std::string{operation}};
}

std::wstring utf8_to_wide(std::string_view value) {
    if (value.empty()) {
        return {};
    }
    const auto size = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        nullptr,
        0);
    if (size <= 0) {
        return L"service worker failed";
    }
    std::wstring result(static_cast<std::size_t>(size), L'\0');
    MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        value.data(),
        static_cast<int>(value.size()),
        result.data(),
        size);
    return result;
}

void report_event(std::string_view message) noexcept {
    try {
        const auto wide_message = utf8_to_wide(message);
        const HANDLE source = RegisterEventSourceW(nullptr, WindowsService::name.data());
        if (source == nullptr) {
            return;
        }
        const wchar_t* strings[]{wide_message.c_str()};
        ReportEventW(
            source,
            EVENTLOG_ERROR_TYPE,
            0,
            1,
            nullptr,
            1,
            0,
            strings,
            nullptr);
        DeregisterEventSource(source);
    } catch (...) {
    }
}

class ServiceRuntime final {
public:
    explicit ServiceRuntime(WindowsService::Worker worker)
        : worker_(std::move(worker)) {}

    void execute() noexcept {
        status_handle_ = RegisterServiceCtrlHandlerExW(
            WindowsService::name.data(), &ServiceRuntime::control_thunk, this);
        if (status_handle_ == nullptr) {
            exit_code_ = static_cast<int>(GetLastError());
            return;
        }

        report(SERVICE_START_PENDING, NO_ERROR, 30'000);
        try {
            const int result = worker_(stop_source_.get_token(), [this] {
                if (!ready_) {
                    ready_ = true;
                    report(SERVICE_RUNNING, NO_ERROR, 0);
                }
            });
            exit_code_ = result;
            if (!ready_ && result == 0) {
                exit_code_ = 1;
                report_event("service worker exited before reporting readiness");
            }
        } catch (const std::exception& error) {
            exit_code_ = 1;
            report_event(error.what());
        } catch (...) {
            exit_code_ = 1;
            report_event("unknown exception in service worker");
        }

        report(
            SERVICE_STOPPED,
            exit_code_ == 0 ? NO_ERROR : ERROR_SERVICE_SPECIFIC_ERROR,
            0,
            exit_code_ == 0 ? 0U : static_cast<DWORD>(exit_code_));
    }

    [[nodiscard]] int exit_code() const noexcept { return exit_code_; }

private:
    static DWORD WINAPI control_thunk(
        DWORD control,
        DWORD,
        void*,
        void* context) noexcept {
        return static_cast<ServiceRuntime*>(context)->control(control);
    }

    DWORD control(DWORD control) noexcept {
        switch (control) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            if (current_state_ == SERVICE_RUNNING) {
                report(SERVICE_STOP_PENDING, NO_ERROR, 30'000);
                stop_source_.request_stop();
            }
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            report(current_state_, NO_ERROR, current_state_ == SERVICE_RUNNING ? 0 : 30'000);
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
        }
    }

    void report(
        DWORD state,
        DWORD win32_exit,
        DWORD wait_hint,
        DWORD service_exit = 0) noexcept {
        current_state_ = state;
        SERVICE_STATUS status{};
        status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        status.dwCurrentState = state;
        status.dwControlsAccepted = state == SERVICE_RUNNING
                                        ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                                        : 0;
        status.dwWin32ExitCode = win32_exit;
        status.dwServiceSpecificExitCode = service_exit;
        status.dwCheckPoint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING
                                   ? ++checkpoint_
                                   : 0;
        status.dwWaitHint = wait_hint;
        SetServiceStatus(status_handle_, &status);
    }

    WindowsService::Worker worker_;
    std::stop_source stop_source_;
    SERVICE_STATUS_HANDLE status_handle_{};
    DWORD current_state_{SERVICE_STOPPED};
    DWORD checkpoint_{};
    int exit_code_{};
    bool ready_{false};
};

ServiceRuntime* active_runtime{};

void WINAPI service_main(DWORD, wchar_t**) noexcept {
    if (active_runtime != nullptr) {
        active_runtime->execute();
    }
}

} // namespace

int WindowsService::run(Worker worker) const {
    if (!worker) {
        throw std::invalid_argument{"service worker is required"};
    }
    ServiceRuntime runtime{std::move(worker)};
    if (active_runtime != nullptr) {
        throw std::logic_error{"a Windows service dispatcher is already active"};
    }
    active_runtime = &runtime;
    SERVICE_TABLE_ENTRYW dispatch_table[]{
        {const_cast<wchar_t*>(name.data()), &service_main},
        {nullptr, nullptr},
    };
    if (!StartServiceCtrlDispatcherW(dispatch_table)) {
        active_runtime = nullptr;
        throw_last_error("StartServiceCtrlDispatcherW");
    }
    active_runtime = nullptr;
    return runtime.exit_code();
}

void WindowsService::install(const std::filesystem::path& executable_path) {
    const auto command = service_command_line(executable_path);
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE)};
    if (!manager) {
        throw_last_error("OpenSCManagerW");
    }

    ServiceHandle service{CreateServiceW(
        manager.get(),
        name.data(),
        display_name.data(),
        SERVICE_CHANGE_CONFIG | SERVICE_START | DELETE,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START,
        SERVICE_ERROR_NORMAL,
        command.c_str(),
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr)};
    if (!service) {
        throw_last_error("CreateServiceW");
    }

    SERVICE_DESCRIPTIONW description{
        const_cast<wchar_t*>(
            L"Asynchronous HTTP/HTTPS reverse proxy and local administration service")};
    SERVICE_DELAYED_AUTO_START_INFO delayed{TRUE};
    std::array<SC_ACTION, 3> actions{
        SC_ACTION{SC_ACTION_RESTART, 5'000},
        SC_ACTION{SC_ACTION_RESTART, 15'000},
        SC_ACTION{SC_ACTION_RESTART, 60'000},
    };
    SERVICE_FAILURE_ACTIONSW failure_actions{};
    failure_actions.dwResetPeriod = 24U * 60U * 60U;
    failure_actions.cActions = static_cast<DWORD>(actions.size());
    failure_actions.lpsaActions = actions.data();
    SERVICE_FAILURE_ACTIONS_FLAG failure_flag{TRUE};

    if (!ChangeServiceConfig2W(service.get(), SERVICE_CONFIG_DESCRIPTION, &description) ||
        !ChangeServiceConfig2W(
            service.get(), SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed) ||
        !ChangeServiceConfig2W(
            service.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &failure_actions) ||
        !ChangeServiceConfig2W(
            service.get(), SERVICE_CONFIG_FAILURE_ACTIONS_FLAG, &failure_flag)) {
        const auto error = GetLastError();
        DeleteService(service.get());
        throw std::system_error{
            static_cast<int>(error), std::system_category(), "ChangeServiceConfig2W"};
    }
}

void WindowsService::uninstall() {
    ServiceHandle manager{OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT)};
    if (!manager) {
        throw_last_error("OpenSCManagerW");
    }
    ServiceHandle service{OpenServiceW(
        manager.get(), name.data(), SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE)};
    if (!service) {
        throw_last_error("OpenServiceW");
    }

    SERVICE_STATUS status{};
    ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{30};
    SERVICE_STATUS_PROCESS process_status{};
    DWORD bytes_needed{};
    while (std::chrono::steady_clock::now() < deadline &&
           QueryServiceStatusEx(
               service.get(),
               SC_STATUS_PROCESS_INFO,
               reinterpret_cast<BYTE*>(&process_status),
               sizeof(process_status),
               &bytes_needed) &&
           process_status.dwCurrentState != SERVICE_STOPPED) {
        std::this_thread::sleep_for(std::chrono::milliseconds{250});
    }

    if (!DeleteService(service.get())) {
        throw_last_error("DeleteService");
    }
}

std::wstring WindowsService::service_command_line(
    const std::filesystem::path& executable_path) {
    const auto executable =
        std::filesystem::absolute(executable_path).lexically_normal().wstring();
    if (executable.empty() || executable.find(L'\"') != std::wstring::npos) {
        throw std::invalid_argument{"invalid service executable path"};
    }
    return L"\"" + executable + L"\" --service";
}

bool WindowsService::supported() noexcept {
    return true;
}

} // namespace webserver::service

#else

namespace webserver::service {

int WindowsService::run(Worker) const {
    throw std::runtime_error{"Windows Service mode is only available on Windows"};
}

void WindowsService::install(const std::filesystem::path&) {
    throw std::runtime_error{"Windows Service installation is only available on Windows"};
}

void WindowsService::uninstall() {
    throw std::runtime_error{"Windows Service removal is only available on Windows"};
}

std::wstring WindowsService::service_command_line(
    const std::filesystem::path& executable_path) {
    const auto executable =
        std::filesystem::absolute(executable_path).lexically_normal().wstring();
    if (executable.empty() || executable.find(L'\"') != std::wstring::npos) {
        throw std::invalid_argument{"invalid service executable path"};
    }
    return L"\"" + executable + L"\" --service";
}

bool WindowsService::supported() noexcept {
    return false;
}

} // namespace webserver::service

#endif
