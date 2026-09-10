#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "scaping/network.hpp"
#include <functional>
#include <string_view>

namespace scaping::net {
struct Handle {
    HANDLE value = nullptr;
    Handle() = default;
    explicit Handle(HANDLE h) : value(h) {}
    ~Handle() { reset(); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    Handle(Handle&& other) noexcept : value(other.release()) {}
    Handle& operator=(Handle&& other) noexcept { if (this != &other) reset(other.release()); return *this; }
    explicit operator bool() const { return value && value != INVALID_HANDLE_VALUE; }
    HANDLE release() { HANDLE h = value; value = nullptr; return h; }
    void reset(HANDLE h = nullptr) { if (*this) CloseHandle(value); value = h; }
};
using RawOutput = std::function<bool(std::string_view)>;
struct ProcessResult { DWORD exitCode = ERROR_GEN_FAILURE; DWORD error = 0; bool cancelled = false; };
ProcessResult run_process(const std::filesystem::path& executable, const std::vector<std::wstring>& args,
    const std::filesystem::path& cwd, HANDLE cancel, const RawOutput& output,
    DWORD deadlineMs = INFINITE, HANDLE parent = nullptr, bool cleanEnvironment = false, HANDLE controlPipe = nullptr);
std::wstring win_error(DWORD error);
bool process_elevated();
std::wstring process_user_sid(HANDLE process);
std::wstring random_token();
std::wstring executable_path();
std::uint64_t process_creation(HANDLE process);
bool trusted_elevation_nmap(const std::filesystem::path& path, std::wstring& diagnostic);
ProcessResult run_elevated_nmap(Protocol protocol, std::wstring_view ip, const std::filesystem::path& expectedNmap,
    const std::filesystem::path& xml, HANDLE cancel, const RawOutput& output);

// Internal integration seam: production always invokes the same engine for [0,65535].
struct TcpRunResult { std::uint32_t attempted = 0, completed = 0, open = 0, closed = 0, uncertain = 0; bool cancelled = false; };
TcpRunResult run_tcp_range(const Config& config, std::uint32_t first, std::uint32_t last, HANDLE cancel,
    const std::function<void(const PortResult&)>& result, const OutputCallback& progress = {});
PortResult run_tcp_probe_for_test(std::wstring_view ip, std::uint32_t port, DWORD timeoutMs, HANDLE cancel);
PortResult classify_tcp_error_for_test(std::uint32_t port, int error);
}
