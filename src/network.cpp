#include "network_internal.hpp"
#include <iphlpapi.h>
#include <icmpapi.h>
#include <iptypes.h>
#include <bcrypt.h>
#include <sddl.h>
#include <shlobj.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <unordered_set>

namespace scaping::net {
std::wstring win_error(DWORD error) {
    wchar_t* message = nullptr;
    DWORD count = FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, error, 0, reinterpret_cast<wchar_t*>(&message), 0, nullptr);
    std::wstring text = count ? sanitize_text(std::wstring_view(message, count), 512) : L"Errore " + std::to_wstring(error);
    if (message) LocalFree(message);
    while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) text.pop_back();
    return text;
}
bool process_elevated() {
    Handle token;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value)) return false;
    TOKEN_ELEVATION elevation{}; DWORD size = 0;
    return GetTokenInformation(token.value, TokenElevation, &elevation, sizeof(elevation), &size) && elevation.TokenIsElevated;
}
std::wstring process_user_sid(HANDLE process) {
    Handle token;
    if (!OpenProcessToken(process, TOKEN_QUERY, &token.value)) return {};
    DWORD size = 0; GetTokenInformation(token.value, TokenUser, nullptr, 0, &size);
    std::vector<unsigned char> bytes(size);
    if (!size || !GetTokenInformation(token.value, TokenUser, bytes.data(), size, &size)) return {};
    wchar_t* sid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &sid)) return {};
    std::wstring result(sid); LocalFree(sid); return result;
}
std::wstring random_token() {
    std::array<unsigned char, 16> random{};
    if (BCryptGenRandom(nullptr, random.data(), static_cast<ULONG>(random.size()), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) return {};
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring result; result.reserve(32);
    for (auto value : random) { result.push_back(hex[value >> 4]); result.push_back(hex[value & 15]); }
    return result;
}
std::wstring executable_path() {
    std::wstring path(32768, L'\0');
    DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) return {};
    path.resize(length); return path;
}
std::uint64_t process_creation(HANDLE process) {
    FILETIME created{}, exit{}, kernel{}, user{};
    if (!GetProcessTimes(process, &created, &exit, &kernel, &user)) return 0;
    return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
}

ProcessResult run_process(const std::filesystem::path& executable, const std::vector<std::wstring>& args,
    const std::filesystem::path& cwd, HANDLE cancel, const RawOutput& output, DWORD deadlineMs, HANDLE parent, bool cleanEnvironment, HANDLE controlPipe) {
    ProcessResult result;
    if (!executable.is_absolute() || !cwd.is_absolute()) { result.error = ERROR_INVALID_PARAMETER; return result; }
    if ((cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) ||
        (parent && WaitForSingleObject(parent, 0) == WAIT_OBJECT_0)) {
        result.cancelled = true; result.exitCode = ERROR_CANCELLED; return result;
    }
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    Handle reader, writer, input(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr));
    if (!input || !CreatePipe(&reader.value, &writer.value, &sa, 0) || !SetHandleInformation(reader.value, HANDLE_FLAG_INHERIT, 0)) {
        result.error = GetLastError(); return result;
    }
    Handle job(CreateJobObjectW(nullptr, nullptr));
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job || !SetInformationJobObject(job.value, JobObjectExtendedLimitInformation, &limits, sizeof(limits))) {
        result.error = GetLastError(); return result;
    }
    SIZE_T size = 0; InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
    std::vector<unsigned char> attributeStorage(size);
    auto* attributes = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attributeStorage.data());
    if (!InitializeProcThreadAttributeList(attributes, 1, 0, &size)) { result.error = GetLastError(); return result; }
    struct AttributeGuard { LPPROC_THREAD_ATTRIBUTE_LIST p; ~AttributeGuard() { DeleteProcThreadAttributeList(p); } } guard{attributes};
    HANDLE inherited[] = {writer.value, input.value};
    if (!UpdateProcThreadAttribute(attributes, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, inherited, sizeof(inherited), nullptr, nullptr)) {
        result.error = GetLastError(); return result;
    }
    STARTUPINFOEXW start{}; start.StartupInfo.cb = sizeof(start); start.lpAttributeList = attributes;
    start.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    start.StartupInfo.hStdInput = input.value; start.StartupInfo.hStdOutput = writer.value; start.StartupInfo.hStdError = writer.value;
    std::wstring command = quote_argument(executable.native());
    for (const auto& arg : args) { command += L' '; command += quote_argument(arg); }
    std::vector<wchar_t> environment;
    if (cleanEnvironment) {
        wchar_t windows[MAX_PATH]{};
        if (!GetWindowsDirectoryW(windows, MAX_PATH)) { result.error = GetLastError(); return result; }
        const std::wstring system = std::wstring(windows) + L"\\System32";
        const std::array<std::wstring, 5> vars = {L"PATH=" + system, L"SystemRoot=" + std::wstring(windows),
            L"TEMP=" + cwd.native(), L"TMP=" + cwd.native(), L"WINDIR=" + std::wstring(windows)};
        for (const auto& value : vars) { environment.insert(environment.end(), value.begin(), value.end()); environment.push_back(L'\0'); }
        environment.push_back(L'\0');
    }
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(executable.c_str(), command.data(), nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
        environment.empty() ? nullptr : environment.data(), cwd.c_str(), &start.StartupInfo, &pi)) {
        result.error = GetLastError(); return result;
    }
    Handle process(pi.hProcess), thread(pi.hThread);
    writer.reset(); input.reset();
    if (!AssignProcessToJobObject(job.value, process.value)) {
        result.error = GetLastError(); TerminateProcess(process.value, ERROR_CANCELLED); WaitForSingleObject(process.value, 5000); return result;
    }
    if ((cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) ||
        (parent && WaitForSingleObject(parent, 0) == WAIT_OBJECT_0)) {
        result.cancelled = true; result.exitCode = ERROR_CANCELLED;
        TerminateJobObject(job.value, ERROR_CANCELLED); WaitForSingleObject(process.value, 5000); return result;
    }
    if (ResumeThread(thread.value) == static_cast<DWORD>(-1)) {
        result.error = GetLastError(); TerminateJobObject(job.value, ERROR_CANCELLED); WaitForSingleObject(process.value, 5000); return result;
    }
    thread.reset();
    const ULONGLONG began = GetTickCount64();
    std::array<char, 16384> buffer{};
    bool processDone = false, aborted = false, descendantsClosed = false;
    for (;;) {
        DWORD controlAvailable = 0;
        bool disconnected = controlPipe && !PeekNamedPipe(controlPipe, nullptr, 0, nullptr, &controlAvailable, nullptr);
        if (!aborted && ((cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) || disconnected ||
            (parent && WaitForSingleObject(parent, 0) == WAIT_OBJECT_0) ||
            (deadlineMs != INFINITE && GetTickCount64() - began >= deadlineMs))) {
            result.cancelled = true; aborted = true; TerminateJobObject(job.value, ERROR_CANCELLED);
        }
        DWORD available = 0;
        bool readable = PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr) != FALSE;
        // Drain in bounded chunks before checking cancellation again.
        DWORD budget = 256 * 1024;
        while (readable && available && budget) {
            DWORD read = 0;
            DWORD amount = (std::min)({available, static_cast<DWORD>(buffer.size()), budget});
            if (!ReadFile(reader.value, buffer.data(), amount, &read, nullptr) || !read) { readable = false; break; }
            budget -= read;
            if (output && !output(std::string_view(buffer.data(), read)) && !aborted) {
                result.cancelled = true; aborted = true; TerminateJobObject(job.value, ERROR_CANCELLED);
            }
            readable = PeekNamedPipe(reader.value, nullptr, 0, nullptr, &available, nullptr) != FALSE;
        }
        processDone = WaitForSingleObject(process.value, 0) == WAIT_OBJECT_0;
        if (processDone && !descendantsClosed) {
            TerminateJobObject(job.value, ERROR_CANCELLED); descendantsClosed = true;
        }
        if (processDone && (!readable || !available)) break;
        HANDLE waits[3] = {process.value}; DWORD count = 1;
        if (!aborted && cancel) waits[count++] = cancel;
        if (!aborted && parent) waits[count++] = parent;
        if (!processDone) WaitForMultipleObjects(count, waits, FALSE, 40);
        else if (!available) break;
    }
    if (!GetExitCodeProcess(process.value, &result.exitCode)) result.error = GetLastError();
    return result;
}

namespace {
struct Socket {
    SOCKET value = INVALID_SOCKET;
    Socket() = default; explicit Socket(SOCKET s) : value(s) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete; Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
    Socket& operator=(Socket&& other) noexcept { if (this != &other) { if (value != INVALID_SOCKET) closesocket(value); value = other.value; other.value = INVALID_SOCKET; } return *this; }
};
struct Winsock { bool ok = false; Winsock() { WSADATA data{}; ok = WSAStartup(MAKEWORD(2, 2), &data) == 0; } ~Winsock() { if (ok) WSACleanup(); } };
struct Connection { Socket socket; std::uint32_t port = 0; ULONGLONG began = 0; bool connected = false; std::string banner; };
std::wstring display_banner(std::string_view bytes) {
    if (bytes.empty()) return {};
    auto decoded = from_utf8(bytes);
    if (!decoded.empty()) return sanitize_text(decoded, 2048);
    // Non-UTF-8 protocols still provide evidence: preserve bytes as printable ASCII or explicit hex escapes.
    constexpr wchar_t hex[] = L"0123456789ABCDEF";
    std::wstring escaped; escaped.reserve(bytes.size() * 4);
    for (unsigned char byte : bytes) {
        if ((byte >= 32 && byte <= 126) || byte == '\r' || byte == '\n' || byte == '\t') escaped += static_cast<wchar_t>(byte);
        else { escaped += L"\\x"; escaped += hex[byte >> 4]; escaped += hex[byte & 15]; }
    }
    return escaped;
}
PortResult socket_result(std::uint32_t port, int error) {
    PortResult result; result.port = port;
    if (error == WSAECONNREFUSED) { result.state = L"closed"; result.reason = L"Connessione TCP rifiutata"; }
    else if (error == WSAETIMEDOUT) { result.state = L"filtered"; result.reason = L"Timeout: esito incerto; non prova che la porta sia chiusa"; }
    else { result.state = L"unknown"; result.reason = L"Errore TCP locale o di rete " + std::to_wstring(error) + L": " + win_error(error); }
    return result;
}
}

TcpRunResult run_tcp_range(const Config& config, std::uint32_t first, std::uint32_t last, HANDLE cancel,
    const std::function<void(const PortResult&)>& onResult, const OutputCallback& progress) {
    TcpRunResult stats;
    if (!valid_ipv4(config.ip) || first > last || last >= kPortCount || config.concurrency < 1 ||
        config.concurrency > 256 || config.connectionsPerSecond < 1 || config.connectionsPerSecond > 1024) return stats;
    Winsock winsock;
    if (!winsock.ok) { if (progress) progress(L"Winsock non disponibile; scansione parziale.\r\n"); return stats; }
    sockaddr_in target{}; target.sin_family = AF_INET;
    if (InetPtonW(AF_INET, config.ip.c_str(), &target.sin_addr) != 1) return stats;
    std::vector<Connection> active; active.reserve(config.concurrency);
    std::uint32_t next = first;
    const double spacingMs = 1000.0 / config.connectionsPerSecond;
    double nextStart = static_cast<double>(GetTickCount64());
    ULONGLONG lastProgress = GetTickCount64();
    // Windows may defer an explicit local refusal for roughly two seconds. The ping timeout is not a safe TCP floor.
    const DWORD connectTimeout = (std::max)(3000U, config.timeoutMs);
    constexpr DWORD bannerTimeout = 300;
    auto emit = [&](PortResult result) {
        ++stats.completed;
        if (result.state == L"open") ++stats.open;
        else if (result.state == L"closed") ++stats.closed;
        else ++stats.uncertain;
        if (onResult) onResult(result);
    };
    while (next <= last || !active.empty()) {
        if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) { stats.cancelled = true; break; }
        ULONGLONG now = GetTickCount64();
        if (next <= last && active.size() < config.concurrency && static_cast<double>(now) >= nextStart) {
            const auto port = next++; ++stats.attempted;
            // No accumulated burst after a stall; port counter is 32 bit through 65536.
            nextStart = static_cast<double>(now) + spacingMs;
            Socket socket(WSASocketW(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT));
            if (socket.value == INVALID_SOCKET) emit(socket_result(port, WSAGetLastError()));
            else {
                u_long mode = 1;
                if (ioctlsocket(socket.value, FIONBIO, &mode) != 0) emit(socket_result(port, WSAGetLastError()));
                else {
                    target.sin_port = htons(static_cast<u_short>(port));
                    int status = connect(socket.value, reinterpret_cast<sockaddr*>(&target), sizeof(target));
                    int error = status == 0 ? 0 : WSAGetLastError();
                    if (error && error != WSAEWOULDBLOCK && error != WSAEINPROGRESS) emit(socket_result(port, error));
                    else active.push_back(Connection{std::move(socket), port, now, status == 0, {}});
                }
            }
        }
        std::vector<WSAPOLLFD> descriptors; descriptors.reserve(active.size());
        for (const auto& connection : active) descriptors.push_back(WSAPOLLFD{connection.socket.value,
            static_cast<SHORT>(connection.connected ? POLLRDNORM : POLLWRNORM), 0});
        if (!descriptors.empty()) {
            // Zero-time poll only while scanning, followed by an event wait below.
            int status = WSAPoll(descriptors.data(), static_cast<ULONG>(descriptors.size()), 0);
            if (status == SOCKET_ERROR) {
                int error = WSAGetLastError();
                for (const auto& connection : active) emit(socket_result(connection.port, error));
                active.clear(); descriptors.clear();
            }
        }
        now = GetTickCount64();
        for (std::size_t i = active.size(); i > 0; --i) {
            auto& connection = active[i - 1]; bool finished = false;
            const SHORT events = descriptors[i - 1].revents;
            if (!connection.connected) {
                if (events & (POLLWRNORM | POLLERR | POLLHUP | POLLNVAL)) {
                    int error = 0; int length = sizeof(error);
                    if (getsockopt(connection.socket.value, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&error), &length) != 0) error = WSAGetLastError();
                    if (error) { emit(socket_result(connection.port, error)); finished = true; }
                    else { connection.connected = true; connection.began = now; }
                } else if (now - connection.began >= connectTimeout) { emit(socket_result(connection.port, WSAETIMEDOUT)); finished = true; }
            }
            if (!finished && connection.connected) {
                bool bannerDone = false;
                std::array<char, 2048> bytes{};
                int read = recv(connection.socket.value, bytes.data(), static_cast<int>(bytes.size() - connection.banner.size()), 0);
                if (read > 0) { connection.banner.append(bytes.data(), read); bannerDone = connection.banner.size() >= bytes.size(); }
                else if (read == 0 || (read == SOCKET_ERROR && WSAGetLastError() != WSAEWOULDBLOCK)) bannerDone = true;
                if (bannerDone || now - connection.began >= bannerTimeout) {
                    PortResult result; result.port = connection.port; result.state = L"open";
                    result.banner = display_banner(connection.banner);
                    result.reason = L"Connessione TCP riuscita; lettura passiva max 2048 byte / 300 ms; nessuna sonda applicativa";
                    emit(std::move(result)); finished = true;
                }
            }
            if (finished) active.erase(active.begin() + static_cast<std::ptrdiff_t>(i - 1));
        }
        if (progress && now - lastProgress >= 2000) {
            progress(L"TCP: " + std::to_wstring(stats.completed) + L" / " + std::to_wstring(last - first + 1) + L" esiti; " +
                std::to_wstring(stats.open) + L" aperte, " + std::to_wstring(stats.uncertain) + L" incerti.\r\n");
            lastProgress = now;
        }
        DWORD delay = 10;
        if (next <= last && active.size() < config.concurrency) {
            double remaining = nextStart - static_cast<double>(GetTickCount64());
            delay = static_cast<DWORD>((std::max)(1.0, (std::min)(10.0, remaining)));
        }
        if (next > last && active.empty()) break;
        if (cancel) { if (WaitForSingleObject(cancel, delay) == WAIT_OBJECT_0) { stats.cancelled = true; break; } }
        else Sleep(delay);
    }
    return stats;
}
PortResult run_tcp_probe_for_test(std::wstring_view ip, std::uint32_t port, DWORD timeoutMs, HANDLE cancel) {
    Config config; config.ip = ip; config.timeoutMs = timeoutMs; config.concurrency = 1;
    PortResult result; result.port = port; result.state = L"cancelled";
    run_tcp_range(config, port, port, cancel, [&](const PortResult& value) { result = value; }); return result;
}
PortResult classify_tcp_error_for_test(std::uint32_t port, int error) { return socket_result(port, error); }
}

namespace scaping {
namespace {
std::vector<std::filesystem::path> installed_nmap_paths() {
    std::vector<std::filesystem::path> result;
    for (const KNOWNFOLDERID* id : {&FOLDERID_ProgramFiles, &FOLDERID_ProgramFilesX86}) {
        wchar_t* path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*id, KF_FLAG_DEFAULT, nullptr, &path))) {
            result.emplace_back(std::filesystem::path(path) / L"Nmap" / L"nmap.exe"); CoTaskMemFree(path);
        }
    }
    return result;
}
bool inspect_nmap_path(const std::filesystem::path& input, std::filesystem::path& output, std::wstring& diagnostic) {
    std::error_code error;
    if (!input.is_absolute() || input.native().starts_with(L"\\\\") || _wcsicmp(input.filename().c_str(), L"nmap.exe") != 0) {
        diagnostic = L"Nmap deve essere un file locale assoluto denominato nmap.exe."; return false;
    }
    output = std::filesystem::canonical(input, error);
    if (error || !std::filesystem::is_regular_file(output, error)) { diagnostic = L"Eseguibile Nmap non trovato."; return false; }
    DWORD type = 0;
    if (!GetBinaryTypeW(output.c_str(), &type) || (type != SCS_32BIT_BINARY && type != SCS_64BIT_BINARY)) {
        diagnostic = L"Il percorso Nmap non contiene un eseguibile Windows valido."; return false;
    }
    auto size = std::filesystem::file_size(output, error);
    if (error || size < 4096 || size > 256 * 1024 * 1024) { diagnostic = L"Dimensione dell'eseguibile Nmap non valida."; return false; }
    return true;
}
bool npcap_admin_only() {
    DWORD adminOnly = 0, dataSize = sizeof(adminOnly);
    return RegGetValueW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\npcap\\Parameters", L"AdminOnly",
        RRF_RT_REG_DWORD, nullptr, &adminOnly, &dataSize) == ERROR_SUCCESS && adminOnly != 0;
}
bool npcap_installed(std::wstring& description) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) { description = L"Impossibile interrogare Npcap: " + net::win_error(GetLastError()); return false; }
    SC_HANDLE service = OpenServiceW(manager, L"npcap", SERVICE_QUERY_STATUS);
    if (!service) { CloseServiceHandle(manager); description = L"Npcap non installato o non accessibile; UDP non disponibile."; return false; }
    SERVICE_STATUS_PROCESS status{}; DWORD bytes = 0;
    bool queried = QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes) != FALSE;
    CloseServiceHandle(service); CloseServiceHandle(manager);
    description = queried && status.dwCurrentState == SERVICE_RUNNING ? L"Servizio Npcap in esecuzione." : L"Npcap installato; driver non confermato in esecuzione.";
    if (npcap_admin_only())
        description += L" Accesso Npcap limitato agli amministratori; può servire UAC.";
    return true;
}
struct ReportSink {
    std::ofstream report;
    OutputCallback callback;
    std::wstring pending;
    std::string utf8Carry;
    ULONGLONG lastFlush = GetTickCount64();
    bool good = true;
    explicit ReportSink(const std::filesystem::path& path, OutputCallback cb) : report(path, std::ios::binary), callback(std::move(cb)) { good = report.good(); }
    void flush() {
        if (!pending.empty() && callback) callback(std::move(pending));
        pending.clear(); lastFlush = GetTickCount64();
    }
    void text(std::wstring_view value) { raw(to_utf8(value)); }
    void raw(std::string_view value) {
        report.write(value.data(), static_cast<std::streamsize>(value.size())); good = good && report.good();
        utf8Carry.append(value);
        // Decode only complete UTF-8 sequences. Invalid bytes are shown as replacements, never silently dropped.
        std::size_t complete = utf8Carry.size();
        if (complete) {
            std::size_t start = complete - 1;
            while (start && (static_cast<unsigned char>(utf8Carry[start]) & 0xc0) == 0x80) --start;
            unsigned char lead = static_cast<unsigned char>(utf8Carry[start]);
            std::size_t wanted = lead < 0x80 ? 1 : (lead & 0xe0) == 0xc0 ? 2 : (lead & 0xf0) == 0xe0 ? 3 : (lead & 0xf8) == 0xf0 ? 4 : 1;
            if (complete - start < wanted) complete = start;
        }
        if (complete) {
            int length = MultiByteToWideChar(CP_UTF8, 0, utf8Carry.data(), static_cast<int>(complete), nullptr, 0);
            if (length > 0) {
                std::wstring decoded(length, L'\0');
                MultiByteToWideChar(CP_UTF8, 0, utf8Carry.data(), static_cast<int>(complete), decoded.data(), length);
                pending += sanitize_text(decoded, 32768);
            }
            utf8Carry.erase(0, complete);
        }
        if (pending.size() >= 8192 || GetTickCount64() - lastFlush >= 100) flush();
    }
    void finish() {
        if (!utf8Carry.empty()) { pending += L'\xfffd'; utf8Carry.clear(); }
        flush();
    }
};
std::filesystem::path create_report_directory() {
    std::filesystem::path base = std::filesystem::path(kRoot) / L"data" / L"reports";
    std::filesystem::create_directories(base);
    SYSTEMTIME time{}; GetLocalTime(&time); wchar_t stamp[64]{};
    swprintf_s(stamp, L"%04u%02u%02u-%02u%02u%02u", time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond);
    auto nonce = net::random_token(); if (nonce.empty()) throw std::runtime_error("random failure");
    auto path = base / (std::wstring(stamp) + L"-" + nonce.substr(0, 8));
    if (!std::filesystem::create_directory(path)) throw std::runtime_error("report directory failure");
    return path;
}
}

NmapInfo detect_nmap(std::wstring_view configuredPath) {
    NmapInfo info; info.elevated = net::process_elevated();
    std::wstring npcap; info.npcapAvailable = npcap_installed(npcap);
    try {
        std::vector<std::filesystem::path> candidates;
        if (!configuredPath.empty()) candidates.emplace_back(configuredPath); else candidates = installed_nmap_paths();
        for (const auto& candidate : candidates) {
            std::filesystem::path path; std::wstring diagnostic;
            if (!inspect_nmap_path(candidate, path, diagnostic)) { info.diagnostic = diagnostic; continue; }
            // Automatic discovery only uses protected installation trees. A manually chosen executable is never elevated here.
            if (configuredPath.empty() && !net::trusted_elevation_nmap(path, diagnostic)) { info.diagnostic = diagnostic; continue; }
            const auto trustDiagnostic = diagnostic;
            std::string version;
            auto result = net::run_process(path, {L"--version"}, path.parent_path(), nullptr,
                [&](std::string_view bytes) { if (version.size() + bytes.size() > 65536) return false; version.append(bytes); return true; }, 5000, nullptr, true);
            std::wstring decoded = sanitize_text(from_utf8(version), 65536);
            const auto marker = decoded.find(L"Nmap version ");
            if (result.error || result.cancelled || result.exitCode != 0 || marker == std::wstring::npos) {
                info.diagnostic = L"Verifica Nmap --version fallita; uso fallback TCP."; continue;
            }
            std::wstring majorText = decoded.substr(marker + 13, 4); wchar_t* end = nullptr;
            auto major = wcstoul(majorText.c_str(), &end, 10);
            if (end == majorText.c_str() || major < 7) { info.diagnostic = L"Profilo completo richiede Nmap 7 o successivo."; continue; }
            auto newline = decoded.find_first_of(L"\r\n", marker);
            info.available = true; info.path = path.native(); info.version = decoded.substr(marker, newline - marker);
            info.diagnostic = info.version + L". " + npcap + (trustDiagnostic.empty() ? L"" : L" " + trustDiagnostic);
            if (!configuredPath.empty()) info.diagnostic += L" Percorso selezionato manualmente: esecuzione ordinaria senza elevazione automatica di file non attendibili.";
            return info;
        }
    } catch (...) { info.diagnostic = L"Errore durante il rilevamento Nmap."; }
    if (info.diagnostic.empty()) info.diagnostic = L"Nmap non disponibile.";
    info.diagnostic += L" " + npcap; return info;
}

struct PingMonitor::Impl {
    std::mutex mutex;
    Config config;
    PingCallback callback;
    std::uint64_t generation = 0, revision = 0;
    bool enabled = false, shutdown = false;
    net::Handle changed{CreateEventW(nullptr, FALSE, FALSE, nullptr)};
    std::thread thread;
    Impl() {
        if (!changed) throw std::runtime_error("ping event failure");
        thread = std::thread([this] { run(); });
    }
    ~Impl() {
        { std::lock_guard lock(mutex); shutdown = true; enabled = false; ++revision; }
        SetEvent(changed.value); if (thread.joinable()) thread.join();
    }
    void run() {
        struct Icmp { HANDLE handle = IcmpCreateFile(); ~Icmp() { if (handle != INVALID_HANDLE_VALUE) IcmpCloseHandle(handle); } } icmp;
        net::Handle completed(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        for (;;) {
            Config snapshot; PingCallback cb; std::uint64_t activeRevision, activeGeneration;
            {
                std::lock_guard lock(mutex); if (shutdown) break;
                WaitForSingleObject(changed.value, 0);
                snapshot = config; cb = callback; activeRevision = revision; activeGeneration = generation;
                if (!enabled) cb = {};
            }
            if (!cb) { WaitForSingleObject(changed.value, INFINITE); continue; }
            PingResult result; result.generation = activeGeneration;
            ULONGLONG began = GetTickCount64();
            if (icmp.handle == INVALID_HANDLE_VALUE || !completed) {
                result.errorCode = ERROR_INVALID_HANDLE; result.error = L"API ICMP non disponibile";
            } else {
                IN_ADDR address{}; InetPtonW(AF_INET, snapshot.ip.c_str(), &address);
                alignas(ICMP_ECHO_REPLY) std::array<unsigned char, sizeof(ICMP_ECHO_REPLY) + 32 + 8> reply{};
                std::array<char, 32> payload{};
                ResetEvent(completed.value);
                DWORD replies = IcmpSendEcho2(icmp.handle, completed.value, nullptr, nullptr, address.S_un.S_addr,
                    payload.data(), static_cast<WORD>(payload.size()), nullptr, reply.data(), static_cast<DWORD>(reply.size()), snapshot.timeoutMs);
                DWORD error = replies ? ERROR_SUCCESS : GetLastError();
                if (!replies && error == ERROR_IO_PENDING) {
                    // The reply buffer and ICMP handle remain alive until the documented completion event, including reconfiguration.
                    WaitForSingleObject(completed.value, INFINITE);
                    replies = IcmpParseReplies(reply.data(), static_cast<DWORD>(reply.size()));
                    error = replies ? ERROR_SUCCESS : GetLastError();
                }
                if (replies) {
                    const auto* echo = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
                    result.success = echo->Status == IP_SUCCESS; result.rttMs = echo->RoundTripTime;
                    result.errorCode = echo->Status;
                } else result.errorCode = error;
                if (!result.success) result.error = result.errorCode == IP_REQ_TIMED_OUT ? L"Timeout ICMP: ping KO" : L"Ping KO: " + net::win_error(result.errorCode);
            }
            bool current = false;
            { std::lock_guard lock(mutex); current = !shutdown && enabled && revision == activeRevision; }
            if (current) { try { cb(std::move(result)); } catch (...) {} }
            const ULONGLONG elapsed = GetTickCount64() - began;
            const DWORD delay = elapsed >= snapshot.intervalMs ? 0 : static_cast<DWORD>(snapshot.intervalMs - elapsed);
            if (current && delay) WaitForSingleObject(changed.value, delay);
        }
    }
};
PingMonitor::PingMonitor() : impl_(std::make_unique<Impl>()) {}
PingMonitor::~PingMonitor() = default;
void PingMonitor::start(const Config& config, std::uint64_t generation, PingCallback callback) {
    if (validate_config(config).has_value()) { stop(); return; }
    { std::lock_guard lock(impl_->mutex); impl_->config = config; impl_->generation = generation;
      impl_->callback = std::move(callback); impl_->enabled = true; ++impl_->revision; }
    SetEvent(impl_->changed.value);
}
void PingMonitor::stop() {
    { std::lock_guard lock(impl_->mutex); impl_->enabled = false; impl_->callback = {}; ++impl_->revision; }
    SetEvent(impl_->changed.value);
}

struct ScanSession::Impl {
    std::atomic<bool> active{false};
    net::Handle cancel{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    std::thread thread;
    ~Impl() { if (cancel) SetEvent(cancel.value); if (thread.joinable()) thread.join(); }
    void scan(Config snapshot, OutputCallback output, CompletionCallback done) {
        ScanCompletion completion;
        try {
            const auto directory = create_report_directory(); completion.reportPath = directory / L"report.txt";
            ReportSink sink(completion.reportPath, output);
            if (!sink.good) throw std::runtime_error("report open failure");
            sink.text(L"SCAPING — target: " + snapshot.ip + L"\r\nRichiesta: TCP e UDP, porte 0..65535 incluse.\r\n");
            if (!sink.good) throw std::runtime_error("report write failure");
            auto info = detect_nmap(snapshot.nmapPath);
            sink.text(info.diagnostic + L"\r\n");
            if (WaitForSingleObject(cancel.value, 0) == WAIT_OBJECT_0) completion.cancelled = true;
            else if (!info.available) {
                sink.text(L"Solo TCP — modalità ridotta. Nessuna scansione UDP e nessun riconoscimento servizi.\r\n");
                sink.text(L"Timeout connessione TCP: " + std::to_wstring((std::max)(3000U, snapshot.timeoutMs)) +
                    L" ms (minimo 3000 ms, indipendente dal timeout ping più breve). Massimo " + std::to_wstring(snapshot.concurrency) +
                    L" connessioni contemporanee, " + std::to_wstring(snapshot.connectionsPerSecond) + L" avvii/s.\r\n");
                auto stats = net::run_tcp_range(snapshot, 0, kPortCount - 1, cancel.value,
                    [&](const PortResult& result) { sink.text(format_port(result) + L"\r\n"); if (!sink.good) SetEvent(cancel.value); },
                    [&](std::wstring text) { sink.text(text); });
                completion.cancelled = stats.cancelled;
                completion.tcpComplete = stats.completed == kPortCount && !stats.cancelled;
                completion.summary = L"PARZIALE — Solo TCP — modalità ridotta. TCP: " + std::to_wstring(stats.completed) +
                    L" / 65536 esiti; aperte " + std::to_wstring(stats.open) + L", chiuse " + std::to_wstring(stats.closed) +
                    L", incerte " + std::to_wstring(stats.uncertain) + L". UDP non eseguito; servizi non identificati.";
            } else {
                std::ofstream versionFile(directory / L"nmap-version.txt", std::ios::binary);
                versionFile << to_utf8(info.version);
                versionFile.flush(); if (!versionFile) throw std::runtime_error("Nmap version file write failure");
                bool servicesComplete = true;
                for (const auto protocol : {Protocol::Tcp, Protocol::Udp}) {
                    if (WaitForSingleObject(cancel.value, 0) == WAIT_OBJECT_0) { completion.cancelled = true; break; }
                    const std::wstring name = protocol == Protocol::Tcp ? L"TCP" : L"UDP";
                    if (protocol == Protocol::Udp && !info.npcapAvailable) { sink.text(L"UDP non eseguito: Npcap non disponibile. Stato finale PARZIALE.\r\n"); break; }
                    auto xml = directory / (protocol == Protocol::Tcp ? L"tcp.xml" : L"udp.xml");
                    sink.text(L"\r\nFase " + name + L": 65536 porte; rilevamento servizi attivo. UDP può richiedere molto tempo.\r\n");
                    std::wstring tail;
                    auto capture = [&](std::string_view bytes) {
                        sink.raw(bytes); tail += from_utf8(bytes); if (tail.size() > 32768) tail.erase(0, tail.size() - 32768);
                        return sink.good;
                    };
                    net::ProcessResult result;
                    const bool elevatedFirst = protocol == Protocol::Udp && !info.elevated && npcap_admin_only();
                    if (elevatedFirst) {
                        sink.text(L"Npcap AdminOnly: richiesta UAC al worker temporaneo prima della fase raw UDP.\r\n");
                        result = net::run_elevated_nmap(protocol, snapshot.ip, info.path, xml, cancel.value, capture);
                    } else result = net::run_process(info.path, nmap_arguments(protocol, snapshot.ip, xml),
                        std::filesystem::path(info.path).parent_path(), cancel.value, capture, INFINITE, nullptr, true);
                    auto lower = tail; std::transform(lower.begin(), lower.end(), lower.begin(), towlower);
                    const bool permissions = lower.find(L"permission") != std::wstring::npos || lower.find(L"privileg") != std::wstring::npos ||
                        lower.find(L"requires root") != std::wstring::npos || lower.find(L"failed to open device") != std::wstring::npos ||
                        lower.find(L"dnet: failed") != std::wstring::npos || lower.find(L"access is denied") != std::wstring::npos;
                    if (result.exitCode != 0 && !result.cancelled && !info.elevated && !elevatedFirst && info.npcapAvailable && permissions) {
                        sink.text(L"La fase " + name + L" richiede ulteriori permessi: richiesta UAC per worker temporaneo con profilo fisso.\r\n");
                        result = net::run_elevated_nmap(protocol, snapshot.ip, info.path, xml, cancel.value, capture);
                    }
                    if (result.cancelled) { completion.cancelled = true; sink.text(L"Fase " + name + L" interrotta.\r\n"); break; }
                    if (result.error || result.exitCode != 0) {
                        sink.text(L"Fase " + name + L" non riuscita: " + net::win_error(result.error ? result.error : result.exitCode) + L".\r\n");
                    }
                    auto parsed = parse_nmap_xml(xml, protocol, snapshot.ip);
                    sink.text(L"\r\nRisultati strutturati " + name + L":\r\n");
                    for (const auto& port : parsed.ports) sink.text(format_port(port) + L"\r\n");
                    sink.text(parsed.summary + L"\r\n" + parsed.diagnostic + L"\r\n");
                    const bool coverage = !result.error && result.exitCode == 0 && parsed.valid && parsed.finished && parsed.coverageComplete;
                    servicesComplete = servicesComplete && coverage && parsed.serviceDetectionComplete;
                    sink.text(name + L" copertura porte: " + (coverage ? L"65536 / 65536 verificata" : L"parziale o non verificabile") +
                        L"; rilevamento servizi: " + (parsed.serviceDetectionComplete && coverage ? L"terminato (possono restare servizi non identificati)" : L"non completato/verificato") + L".\r\n");
                    if (protocol == Protocol::Tcp) completion.tcpComplete = coverage; else completion.udpComplete = coverage;
                }
                completion.complete = completion.tcpComplete && completion.udpComplete && servicesComplete && !completion.cancelled;
                completion.summary = completion.complete ? L"COMPLETATA — copertura TCP e UDP 0..65535 verificata; gli stati incerti restano incerti." :
                    L"PARZIALE — TCP " + std::wstring(completion.tcpComplete ? L"coperto" : L"non completato") +
                    L", UDP " + std::wstring(completion.udpComplete ? L"coperto" : L"non completato") + L".";
                if (!servicesComplete) completion.summary += L" Rilevamento servizi non completato o non verificabile.";
            }
            if (completion.cancelled) { completion.complete = false; completion.summary = L"ANNULLATA — scansione PARZIALE. " + completion.summary; }
            if (completion.summary.empty()) completion.summary = L"PARZIALE — scansione non eseguita.";
            sink.text(L"\r\n" + completion.summary + L"\r\n");
            sink.report.flush(); sink.good = sink.good && sink.report.good();
            if (!sink.good) { completion.complete = false; completion.summary += L" Errore scrittura report: output su disco incompleto."; }
            sink.finish();
        } catch (const std::exception& exception) {
            completion.complete = false; completion.summary = L"PARZIALE — errore scansione: " + from_utf8(exception.what());
            if (output) { try { output(completion.summary + L"\r\n"); } catch (...) {} }
        } catch (...) { completion.complete = false; completion.summary = L"PARZIALE — errore scansione inatteso."; }
        active.store(false);
        if (done) { try { done(std::move(completion)); } catch (...) {} }
    }
};
ScanSession::ScanSession() : impl_(std::make_unique<Impl>()) {}
ScanSession::~ScanSession() = default;
bool ScanSession::start(const Config& snapshot, OutputCallback output, CompletionCallback complete) {
    if (validate_config(snapshot).has_value() || !impl_->cancel) return false;
    if (impl_->thread.joinable() && impl_->thread.get_id() == std::this_thread::get_id()) return false;
    bool expected = false; if (!impl_->active.compare_exchange_strong(expected, true)) return false;
    if (impl_->thread.joinable()) impl_->thread.join();
    ResetEvent(impl_->cancel.value);
    try { impl_->thread = std::thread([this, snapshot, output = std::move(output), complete = std::move(complete)]() mutable {
        impl_->scan(snapshot, std::move(output), std::move(complete));
    }); } catch (...) { impl_->active.store(false); return false; }
    return true;
}
void ScanSession::cancel() { if (impl_->cancel) SetEvent(impl_->cancel.value); }
bool ScanSession::running() const { return impl_->active.load(); }
}
