#include "../src/network_internal.hpp"
#include <atomic>
#include <chrono>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace {
int checks = 0;
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
struct Winsock {
    Winsock() { WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data)) throw std::runtime_error("test Winsock initialization"); }
    ~Winsock() { WSACleanup(); }
};
struct Socket {
    SOCKET value = INVALID_SOCKET;
    explicit Socket(SOCKET socket = INVALID_SOCKET) : value(socket) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
};
std::uint16_t bind_loopback(SOCKET socket) {
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK);
    require(bind(socket, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0, "bind controlled loopback socket");
    int length = sizeof(address);
    require(getsockname(socket, reinterpret_cast<sockaddr*>(&address), &length) == 0, "get controlled loopback port");
    return ntohs(address.sin_port);
}
struct Listener {
    Socket socket{WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT)};
    scaping::net::Handle stop{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::uint16_t port = 0;
    std::thread thread;
    explicit Listener(bool banner, bool binary = false) {
        require(socket.value != INVALID_SOCKET && static_cast<bool>(stop), "listener resources");
        port = bind_loopback(socket.value);
        require(listen(socket.value, 4) == 0, "listen controlled loopback socket");
        u_long mode = 1; require(ioctlsocket(socket.value, FIONBIO, &mode) == 0, "nonblocking test listener");
        thread = std::thread([this, banner, binary] {
            while (WaitForSingleObject(stop.value, 20) == WAIT_TIMEOUT) {
                Socket connection(accept(socket.value, nullptr, nullptr));
                if (connection.value == INVALID_SOCKET) continue;
                if (banner) {
                    std::string text = "220 synthetic fixture ready\r\n";
                    if (binary) {
                        text = "220 synthetic ";
                        text += static_cast<char>(0xff); text += '\0'; text += " ready\r\n";
                    }
                    send(connection.value, text.data(), static_cast<int>(text.size()), 0);
                    shutdown(connection.value, SD_SEND);
                } else WaitForSingleObject(stop.value, 1000);
            }
        });
    }
    ~Listener() { SetEvent(stop.value); if (thread.joinable()) thread.join(); }
};
void test_ping() {
    scaping::Config config; config.language = scaping::current_language(); config.ip = L"127.0.0.1"; config.intervalMs = 250; config.timeoutMs = 200; config.slowMs = 150;
    scaping::net::Handle received(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    std::mutex mutex;
    scaping::PingResult latest;
    std::atomic<unsigned> callbacks{0};
    auto callback = [&](scaping::PingResult result) {
        { std::lock_guard lock(mutex); latest = result; ++callbacks; }
        SetEvent(received.value);
    };
    // Join the monitor before any callback-owned state is destroyed, also on assertion failure.
    scaping::PingMonitor ping;
    ping.start(config, 40, callback);
    require(WaitForSingleObject(received.value, 3000) == WAIT_OBJECT_0, "real loopback ICMP callback timeout");
    { std::lock_guard lock(mutex); require(latest.success && latest.generation == 40, "real loopback ICMP failed"); }
    ping.stop();
    Sleep(30);
    const unsigned stoppedCount = callbacks.load();
    Sleep(350);
    require(callbacks.load() == stoppedCount, "ping callback after stop");
    ResetEvent(received.value);
    ping.start(config, 41, callback);
    require(WaitForSingleObject(received.value, 3000) == WAIT_OBJECT_0, "ping did not restart after resume");
    { std::lock_guard lock(mutex); require(latest.success && latest.generation == 41, "new generation not delivered"); }
    ping.stop();
    std::cout << "Real ICMP loopback, stop and resume passed.\n";
}
void test_tcp() {
    Winsock winsock;
    scaping::net::Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    const auto timeout = scaping::net::classify_tcp_error_for_test(12345, WSAETIMEDOUT);
    require(timeout.state != L"closed" && timeout.reason.find(scaping::current_language() == scaping::Language::English ? L"uncertain" : L"incerto") != std::wstring::npos, "simulated TCP timeout declared closed");
    const auto localError = scaping::net::classify_tcp_error_for_test(12345, WSAEMFILE);
    require(localError.state != L"closed" && localError.state != L"open", "simulated local socket exhaustion misclassified");
    {
        Listener listener(true);
        auto result = scaping::net::run_tcp_probe_for_test(L"127.0.0.1", listener.port, 300, cancel.value);
        require(result.state == L"open" && result.banner.find(L"synthetic fixture ready") != std::wstring::npos, "controlled passive TCP banner failed");
        require(result.product.empty() && result.version.empty() && !result.serviceFromResponse, "native fallback invented service identity");
    }
    {
        Listener listener(true, true);
        auto result = scaping::net::run_tcp_probe_for_test(L"127.0.0.1", listener.port, 300, cancel.value);
        require(result.state == L"open" && result.banner.find(L"synthetic") != std::wstring::npos && result.banner.find(L"\\xFF") != std::wstring::npos && result.banner.find(L"\\x00") != std::wstring::npos, "binary passive banner lost or controls unescaped");
    }
    {
        Listener listener(false);
        const auto started = GetTickCount64();
        auto result = scaping::net::run_tcp_probe_for_test(L"127.0.0.1", listener.port, 300, cancel.value);
        const auto elapsed = GetTickCount64() - started;
        require(result.state == L"open" && result.banner.empty(), "silent open TCP misclassified");
        require(elapsed >= 250 && elapsed < 1500, "passive banner timeout not bounded");
    }
    {
        // Bound but not listening reserves a known local port without relying on an external host.
        Socket reserved(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
        const auto port = bind_loopback(reserved.value);
        // Windows can retry a loopback connect before reporting refusal (about 2 seconds here).
        auto result = scaping::net::run_tcp_probe_for_test(L"127.0.0.1", port, 4000, cancel.value);
        if (result.state != L"closed") std::cerr << "Controlled refusal diagnostic: state=" << scaping::to_utf8(result.state) << ", reason=" << scaping::to_utf8(result.reason) << "\n";
        require(result.state == L"closed", "controlled local TCP refusal not closed");
    }
    scaping::Config config; config.ip = L"127.0.0.1"; config.timeoutMs = 300; config.slowMs = 150;
    config.connectionsPerSecond = 1;
    std::thread canceller([&] { Sleep(120); SetEvent(cancel.value); });
    const auto began = GetTickCount64();
    auto cancelled = scaping::net::run_tcp_range(config, 0, 65535, cancel.value, {});
    canceller.join();
    require(cancelled.cancelled && cancelled.attempted <= 1 && GetTickCount64() - began < 1000, "TCP cancellation or start-rate bound failed");
    ResetEvent(cancel.value);
    config.connectionsPerSecond = 1024;
    Socket reservedBoundary(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
    sockaddr_in boundaryAddress{}; boundaryAddress.sin_family = AF_INET;
    boundaryAddress.sin_addr.S_un.S_addr = htonl(INADDR_LOOPBACK); boundaryAddress.sin_port = htons(65535);
    if (bind(reservedBoundary.value, reinterpret_cast<sockaddr*>(&boundaryAddress), sizeof(boundaryAddress)) == 0) {
        unsigned count = 0;
        auto boundary = scaping::net::run_tcp_range(config, 65535, 65535, cancel.value, [&](const scaping::PortResult& result) { require(result.port == 65535, "last port changed"); ++count; });
        require(boundary.attempted == 1 && boundary.completed == 1 && count == 1, "65535 completion overflow");
    } else std::cout << "SKIP real TCP65535 boundary: already occupied; synthetic full-range core coverage remains tested.\n";
    auto invalid = scaping::net::run_tcp_range(config, 0, 65536, cancel.value, {});
    require(!invalid.attempted, "invalid TCP range accepted");
    SetEvent(cancel.value);
    auto preCancelled = scaping::net::run_tcp_range(config, 0, 65535, cancel.value, {});
    require(preCancelled.cancelled && !preCancelled.attempted, "pre-cancelled scan sent a connection");
    std::cout << "Controlled TCP open/banner/refusal, silent banner deadline, cancellation and boundary passed.\n";
}
void raw_write(HANDLE stream, std::string_view bytes) {
    DWORD count = 0;
    WriteFile(stream, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr);
}
int child_mode(std::wstring_view mode) {
    if (mode == L"output") {
        raw_write(GetStdHandle(STD_OUTPUT_HANDLE), "synthetic stdout\n");
        raw_write(GetStdHandle(STD_ERROR_HANDLE), "synthetic stderr\n");
        return 7;
    }
    if (mode == L"wait") { Sleep(15000); return 0; }
    if (mode == L"spawn") {
        const auto self = scaping::net::executable_path();
        auto command = scaping::quote_argument(self) + L" --child wait";
        STARTUPINFOW startup{sizeof(startup)}; PROCESS_INFORMATION process{};
        if (!CreateProcessW(self.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process)) return 8;
        raw_write(GetStdHandle(STD_OUTPUT_HANDLE), "parent=" + std::to_string(GetCurrentProcessId()) + "\nchild=" + std::to_string(process.dwProcessId) + "\n");
        CloseHandle(process.hThread); CloseHandle(process.hProcess);
        Sleep(15000); return 0;
    }
    return 9;
}
void require_dead(DWORD pid) {
    scaping::net::Handle process(OpenProcess(SYNCHRONIZE, FALSE, pid));
    require(!process || WaitForSingleObject(process.value, 2000) == WAIT_OBJECT_0, "owned child process orphaned");
}
void test_processes() {
    const std::filesystem::path self(scaping::net::executable_path());
    std::string output;
    auto capture = [&](std::string_view bytes) { output.append(bytes); return output.size() < 65536; };
    auto result = scaping::net::run_process(self, {L"--child", L"output"}, self.parent_path(), nullptr, capture, 3000);
    require(!result.error && !result.cancelled && result.exitCode == 7, "child process exit code capture");
    require(output.find("synthetic stdout") != std::string::npos && output.find("synthetic stderr") != std::string::npos, "stdout/stderr capture missing");
    output.clear();
    const auto began = GetTickCount64();
    result = scaping::net::run_process(self, {L"--child", L"spawn"}, self.parent_path(), nullptr, capture, 500);
    require(result.cancelled && GetTickCount64() - began < 3000, "child timeout did not terminate promptly");
    const auto parent = output.find("parent="), child = output.find("child=");
    require(parent != std::string::npos && child != std::string::npos, "nested child fixture failed");
    require_dead(static_cast<DWORD>(std::stoul(output.substr(parent + 7))));
    require_dead(static_cast<DWORD>(std::stoul(output.substr(child + 6))));
    scaping::net::Handle cancel(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    std::thread canceller([&] { Sleep(150); SetEvent(cancel.value); });
    result = scaping::net::run_process(self, {L"--child", L"wait"}, self.parent_path(), cancel.value, capture, 5000);
    canceller.join();
    require(result.cancelled, "explicit child process cancellation failed");
    output.clear();
    result = scaping::net::run_process(self, {L"--child", L"output"}, self.parent_path(), cancel.value, capture, 3000);
    require(result.cancelled && output.empty(), "pre-cancelled child started execution");
    std::cout << "Process stdout/stderr, exit code, timeout, cancellation and nested Job cleanup passed.\n";
}
void test_worker_boundary() {
    wchar_t executable[] = L"synthetic.exe";
    wchar_t worker[] = L"--scaping-worker";
    wchar_t pid[] = L"1";
    wchar_t created[] = L"1";
    wchar_t maliciousNonce[] = L"../../command";
    wchar_t badPid[] = L"not-a-pid";
    wchar_t nonce[] = L"00000000000000000000000000000000";
    wchar_t* normal[]{executable};
    wchar_t* malformed[]{executable, worker, pid, created, maliciousNonce};
    wchar_t* invalidPid[]{executable, worker, badPid, created, nonce};
    require(scaping::worker_entry(1, normal) == -1, "ordinary GUI command classified worker");
    require(scaping::worker_entry(2, malformed) == ERROR_INVALID_PARAMETER, "worker wrong arg count accepted");
    require(scaping::worker_entry(5, malformed) == ERROR_INVALID_PARAMETER, "worker nonce injection accepted");
    require(scaping::worker_entry(5, invalidPid) == ERROR_INVALID_PARAMETER, "worker nonnumeric PID accepted");
    std::wstring diagnostic;
    require(!scaping::net::trusted_elevation_nmap(std::filesystem::path(scaping::kRoot) / L"nmap.exe", diagnostic), "user-writable Nmap elevation accepted");
    const auto denied = scaping::net::run_elevated_nmap(scaping::Protocol::Tcp, L"127.0.0.1", std::filesystem::path(scaping::kRoot) / L"nmap.exe", std::filesystem::path(scaping::kRoot) / L"data" / L"never-created.xml", nullptr, {});
    require(denied.error == ERROR_ACCESS_DENIED, "elevated worker accepted nonfixed TCP profile");
    std::cout << "Worker malformed requests, nonce injection and untrusted path/nonfixed profile rejection passed (no UAC launched).\n";
}
void test_scan_session() {
    scaping::Config config; config.ip = L"127.0.0.1";
    config.language = scaping::current_language();
    config.nmapPath = L"D:\\scaping\\tests\\nonexistent-synthetic-fixture\\nmap.exe";
    config.connectionsPerSecond = 1;
    scaping::net::Handle finished(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    std::wstring output; std::mutex mutex;
    scaping::ScanCompletion completion;
    // Destruction cancels/joins before completion, output, mutex or event leave scope.
    scaping::ScanSession session;
    const auto began = GetTickCount64();
    require(session.start(config, [&](std::wstring text) { std::lock_guard lock(mutex); output += text; }, [&](scaping::ScanCompletion result) { completion = std::move(result); SetEvent(finished.value); }), "scan start rejected");
    require(!session.start(config, {}, {}), "overlapping scan accepted");
    {
        // Simulate the caller changing UI language while the scan keeps its initial language.
        const scaping::ScopedLanguage changed(config.language == scaping::Language::English ? scaping::Language::Italian : scaping::Language::English);
        Sleep(200);
        session.cancel();
        require(WaitForSingleObject(finished.value, 5000) == WAIT_OBJECT_0, "scan session did not cancel");
    }
    require(completion.cancelled && !completion.complete && !completion.udpComplete && !session.running(), "cancelled fallback not partial");
    require(GetTickCount64() - began < 3000, "scan cancellation too slow");
    const bool english = config.language == scaping::Language::English;
    require(output.find(english ? L"TCP only" : L"Solo TCP") != std::wstring::npos, "absent Nmap fallback not disclosed in snapshot language");
    require(completion.summary.find(english ? L"PARTIAL" : L"PARZIALE") != std::wstring::npos, "completion changed language with the caller");
    require(output.find(english ? L"Solo TCP" : L"TCP only") == std::wstring::npos, "scan report mixes application languages");
    require(!completion.reportPath.empty() && std::filesystem::exists(completion.reportPath), "complete report not saved");
    const auto reportDirectory = completion.reportPath.parent_path();
    const auto expectedBase = std::filesystem::path(scaping::kRoot) / L"data" / L"reports";
    if (reportDirectory.parent_path() == expectedBase && completion.reportPath.filename() == L"report.txt") std::filesystem::remove_all(reportDirectory);
    std::cout << "Missing Nmap, single scan, local-only fallback, real cancellation and partial report passed.\n";
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 3 && std::wstring_view(argv[1]) == L"--child") return child_mode(argv[2]);
    if (argc == 2 && std::wstring_view(argv[1]) == L"--language=en") scaping::set_language(scaping::Language::English);
    else if (argc != 1) return 2;
    try {
        test_ping(); test_tcp(); test_processes(); test_worker_boundary(); test_scan_session();
        std::cout << "Network integration checks passed: " << checks << "\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "NETWORK TEST FAILURE after " << checks << " checks: " << error.what() << "\n";
        return 1;
    }
}
