#include "network_internal.hpp"
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>
#include <shellapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <limits>
#include <optional>
#include <thread>

namespace scaping::net {
namespace {
constexpr DWORD wireMagic = 0x53435032;
constexpr DWORD wireVersion = 2;
constexpr DWORD textFrame = 1, xmlFrame = 2, finishFrame = 3;
constexpr DWORD maxFrame = 65536;
constexpr std::uint64_t maxXml = 64ULL * 1024 * 1024;
struct Request { DWORD magic = wireMagic; DWORD version = wireVersion; DWORD protocol = 1; DWORD language = 0; wchar_t ip[16]{}; };
struct Frame { DWORD type = 0, bytes = 0; };
struct Finish { DWORD exitCode = ERROR_GEN_FAILURE, error = 0, cancelled = 0; };

std::wstring sid_string(PSID sid) {
    wchar_t* value = nullptr;
    if (!sid || !IsValidSid(sid) || !ConvertSidToStringSidW(sid, &value)) return {};
    std::wstring text(value); LocalFree(value); return text;
}
bool administrative_sid(PSID sid) {
    const auto value = sid_string(sid);
    return value == L"S-1-5-18" || value == L"S-1-5-32-544" ||
        value == L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; // TrustedInstaller
}
bool protected_object(const std::filesystem::path& path, std::wstring& diagnostic) {
    DWORD attributes = GetFileAttributesW(path.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
        diagnostic = tr(L"Percorso Nmap mancante o con reparse point: elevazione rifiutata.", L"Nmap path is missing or contains a reparse point: elevation refused."); return false;
    }
    PACL dacl = nullptr; PSID owner = nullptr; PSECURITY_DESCRIPTOR security = nullptr;
    DWORD result = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &owner, nullptr, &dacl, nullptr, &security);
    if (result != ERROR_SUCCESS) { diagnostic = tr(L"Impossibile verificare ACL Nmap: ", L"Unable to verify Nmap ACLs: ") + win_error(result); return false; }
    struct Guard { PSECURITY_DESCRIPTOR p; ~Guard() { LocalFree(p); } } guard{security};
    if (!dacl || !administrative_sid(owner)) {
        diagnostic = tr(L"Proprietario o ACL Nmap non protetti da amministratori: elevazione rifiutata.",
            L"Nmap owner or ACLs are not protected by administrators: elevation refused."); return false;
    }
    constexpr ACCESS_MASK mutations = GENERIC_ALL | GENERIC_WRITE | DELETE | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD;
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(dacl, i, &raw)) { diagnostic = tr(L"ACL Nmap non valida.", L"Invalid Nmap ACL."); return false; }
        const auto* header = static_cast<const ACE_HEADER*>(raw);
        if (header->AceFlags & INHERIT_ONLY_ACE) continue;
        if (header->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw);
            if ((ace->Mask & mutations) && !administrative_sid(const_cast<DWORD*>(&ace->SidStart))) {
                diagnostic = tr(L"Installazione Nmap modificabile da utenti non amministratori: elevazione rifiutata.",
                    L"Nmap installation is writable by non-administrators: elevation refused."); return false;
            }
        } else if (header->AceType != ACCESS_DENIED_ACE_TYPE && header->AceType != SYSTEM_AUDIT_ACE_TYPE) {
            // Complex conditional/object grants are conservatively rejected instead of approximated.
            diagnostic = tr(L"ACL Nmap complessa non verificabile: elevazione rifiutata.", L"Complex Nmap ACL cannot be verified: elevation refused."); return false;
        }
    }
    return true;
}
std::vector<std::filesystem::path> trusted_roots() {
    std::vector<std::filesystem::path> roots;
    for (const KNOWNFOLDERID* id : {&FOLDERID_ProgramFiles, &FOLDERID_ProgramFilesX86}) {
        wchar_t* path = nullptr;
        if (SUCCEEDED(SHGetKnownFolderPath(*id, KF_FLAG_DEFAULT, nullptr, &path))) {
            roots.emplace_back(path); CoTaskMemFree(path);
        }
    }
    return roots;
}
bool same_path(const std::filesystem::path& left, const std::filesystem::path& right) {
    std::error_code error1, error2;
    auto first = std::filesystem::canonical(left, error1), second = std::filesystem::canonical(right, error2);
    return !error1 && !error2 && _wcsicmp(first.c_str(), second.c_str()) == 0;
}
bool valid_nonce(std::wstring_view nonce) {
    return nonce.size() == 32 && std::all_of(nonce.begin(), nonce.end(), [](wchar_t ch) { return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f'); });
}
std::optional<std::uint64_t> parse_unsigned(std::wstring_view text) {
    if (text.empty() || text.size() > 20) return {};
    std::uint64_t value = 0;
    for (auto ch : text) {
        if (ch < L'0' || ch > L'9' || value > ((std::numeric_limits<std::uint64_t>::max)() - (ch - L'0')) / 10) return {};
        value = value * 10 + (ch - L'0');
    }
    return value;
}
std::wstring pipe_name(DWORD pid, std::wstring_view nonce) { return L"\\\\.\\pipe\\Scaping-" + std::to_wstring(pid) + L"-" + std::wstring(nonce); }

bool transfer(HANDLE pipe, bool write, void* data, DWORD bytes, HANDLE cancel, HANDLE peer, DWORD timeout = INFINITE) {
    auto* buffer = static_cast<unsigned char*>(data);
    while (bytes) {
        Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
        if (!event) return false;
        OVERLAPPED ov{}; ov.hEvent = event.value;
        DWORD count = 0;
        BOOL ok = write ? WriteFile(pipe, buffer, bytes, &count, &ov) : ReadFile(pipe, buffer, bytes, &count, &ov);
        if (!ok && GetLastError() != ERROR_IO_PENDING) return false;
        if (!ok) {
            HANDLE waits[3] = {event.value}; DWORD n = 1;
            if (cancel) waits[n++] = cancel;
            if (peer) waits[n++] = peer;
            DWORD wait = WaitForMultipleObjects(n, waits, FALSE, timeout);
            if (wait != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &ov);
                GetOverlappedResult(pipe, &ov, &count, TRUE); // Never free an outstanding OVERLAPPED.
                return false;
            }
            if (!GetOverlappedResult(pipe, &ov, &count, FALSE)) return false;
        }
        if (!count || count > bytes) return false;
        buffer += count; bytes -= count;
    }
    return true;
}
bool send_frame(HANDLE pipe, DWORD kind, std::string_view bytes, HANDLE parent) {
    if (bytes.size() > maxFrame) return false;
    Frame frame{kind, static_cast<DWORD>(bytes.size())};
    return transfer(pipe, true, &frame, sizeof(frame), nullptr, parent, 10000) &&
        (bytes.empty() || transfer(pipe, true, const_cast<char*>(bytes.data()), static_cast<DWORD>(bytes.size()), nullptr, parent, 10000));
}

struct PrivateDirectory {
    std::filesystem::path path;
    std::filesystem::path xml;
    ~PrivateDirectory() {
        // Delete only the exact two owned paths; never recurse through a potentially changed tree.
        if (!xml.empty()) DeleteFileW(xml.c_str());
        if (!path.empty()) RemoveDirectoryW(path.c_str());
    }
    bool create() {
        wchar_t windows[MAX_PATH]{};
        if (!GetWindowsDirectoryW(windows, MAX_PATH)) return false;
        auto nonce = random_token(); if (nonce.empty()) return false;
        path = std::filesystem::path(windows) / L"Temp" / (L"ScapingWorker-" + nonce);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr)) return false;
        SECURITY_ATTRIBUTES attributes{sizeof(attributes), descriptor, FALSE};
        BOOL created = CreateDirectoryW(path.c_str(), &attributes); LocalFree(descriptor);
        if (!created) { path.clear(); return false; }
        xml = path / L"result.xml";
        return true;
    }
};

int serve_worker(DWORD parentPid, std::uint64_t created, std::wstring_view nonce) {
    if (!process_elevated()) return ERROR_ELEVATION_REQUIRED;
    Handle parent(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, parentPid));
    if (!parent || !created || process_creation(parent.value) != created || WaitForSingleObject(parent.value, 0) != WAIT_TIMEOUT) return ERROR_ACCESS_DENIED;
    const auto user = process_user_sid(GetCurrentProcess());
    if (user.empty() || process_user_sid(parent.value) != user) return ERROR_ACCESS_DENIED;
    std::wstring parentPath(32768, L'\0'); DWORD length = static_cast<DWORD>(parentPath.size());
    if (!QueryFullProcessImageNameW(parent.value, 0, parentPath.data(), &length)) return ERROR_ACCESS_DENIED;
    parentPath.resize(length);
    if (!same_path(parentPath, executable_path())) return ERROR_ACCESS_DENIED;
    auto name = pipe_name(parentPid, nonce);
    Handle pipe(CreateFileW(name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
        FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, nullptr));
    if (!pipe) return static_cast<int>(GetLastError());
    ULONG server = 0;
    if (!GetNamedPipeServerProcessId(pipe.value, &server) || server != parentPid) return ERROR_ACCESS_DENIED;
    Request request{};
    if (!transfer(pipe.value, false, &request, sizeof(request), nullptr, parent.value, 10000) || request.magic != wireMagic ||
        request.version != wireVersion || request.protocol > 1 || request.language > 1 || request.ip[15] != L'\0' || !valid_ipv4(request.ip)) return ERROR_INVALID_DATA;
    ScopedLanguage language(request.language == 1 ? Language::English : Language::Italian);
    PrivateDirectory temporary;
    if (!temporary.create()) return ERROR_ACCESS_DENIED;
    std::filesystem::path executable;
    std::wstring diagnostic;
    for (const auto& root : trusted_roots()) {
        auto candidate = root / L"Nmap" / L"nmap.exe";
        if (trusted_elevation_nmap(candidate, diagnostic)) { executable = candidate; break; }
    }
    if (executable.empty()) {
        send_frame(pipe.value, textFrame, to_utf8(tr(L"Worker UAC: installazione Nmap attendibile non disponibile. ",
            L"UAC worker: a trusted Nmap installation is unavailable. ") + diagnostic + L"\r\n"), parent.value);
        Finish finished{ERROR_ACCESS_DENIED, ERROR_ACCESS_DENIED, 0};
        send_frame(pipe.value, finishFrame, std::string_view(reinterpret_cast<const char*>(&finished), sizeof(finished)), parent.value);
        return ERROR_ACCESS_DENIED;
    }
    std::string version;
    auto check = run_process(executable, {L"--version"}, executable.parent_path(), nullptr,
        [&](std::string_view bytes) { if (version.size() + bytes.size() > maxFrame) return false; version.append(bytes); return true; },
        5000, parent.value, true, pipe.value);
    auto versionMarker = version.find("Nmap version ");
    unsigned long major = 0;
    if (versionMarker != std::string::npos) {
        const auto text = version.substr(versionMarker + 13, 4);
        char* end = nullptr; major = strtoul(text.c_str(), &end, 10);
        if (end == text.c_str()) major = 0;
    }
    if (check.error || check.exitCode || check.cancelled || major < 7) {
        Finish finished{ERROR_BAD_EXE_FORMAT, ERROR_BAD_EXE_FORMAT, 0};
        send_frame(pipe.value, finishFrame, std::string_view(reinterpret_cast<const char*>(&finished), sizeof(finished)), parent.value);
        return ERROR_BAD_EXE_FORMAT;
    }
    const Protocol protocol = request.protocol == 0 ? Protocol::Tcp : Protocol::Udp;
    const std::wstring profile = protocol == Protocol::Tcp ? L"TCP" : L"UDP";
    if (!send_frame(pipe.value, textFrame, to_utf8(tr(L"Worker UAC temporaneo; profilo ", L"Temporary UAC worker; fixed full ") + profile +
        tr(L" completo fisso.\r\n", L" profile.\r\n")) + version, parent.value)) return ERROR_CANCELLED;
    auto result = run_process(executable, nmap_arguments(protocol, request.ip, temporary.xml), temporary.path, nullptr,
        [&](std::string_view bytes) { return send_frame(pipe.value, textFrame, bytes, parent.value); }, INFINITE, parent.value, true, pipe.value);
    // XML is read from a worker-owned administrative directory, never from a caller-specified output path.
    std::error_code error;
    auto size = std::filesystem::file_size(temporary.xml, error);
    if (!error && size <= maxXml) {
        std::ifstream input(temporary.xml, std::ios::binary); std::array<char, maxFrame> bytes{};
        while (input) {
            input.read(bytes.data(), bytes.size()); const auto read = input.gcount();
            if (read && !send_frame(pipe.value, xmlFrame, std::string_view(bytes.data(), static_cast<std::size_t>(read)), parent.value)) return ERROR_CANCELLED;
        }
    } else if (!error) result.error = ERROR_FILE_TOO_LARGE;
    Finish finished{result.exitCode, result.error, result.cancelled ? 1UL : 0UL};
    send_frame(pipe.value, finishFrame, std::string_view(reinterpret_cast<const char*>(&finished), sizeof(finished)), parent.value);
    return static_cast<int>(result.exitCode);
}
}

bool trusted_elevation_nmap(const std::filesystem::path& path, std::wstring& diagnostic) {
    try {
        if (!path.is_absolute() || path.native().starts_with(L"\\\\") || _wcsicmp(path.filename().c_str(), L"nmap.exe")) {
            diagnostic = tr(L"Il worker accetta soltanto l'installazione Nmap locale prevista.", L"The worker accepts only the designated local Nmap installation."); return false;
        }
        std::filesystem::path root;
        for (const auto& candidate : trusted_roots()) {
            // Do not canonicalize away a reparse point before checking each expected component.
            auto expected = candidate / L"Nmap" / L"nmap.exe";
            if (_wcsicmp(path.lexically_normal().c_str(), expected.lexically_normal().c_str()) == 0) { root = candidate; break; }
        }
        if (root.empty()) { diagnostic = tr(L"Il worker eleva soltanto Nmap installato in Program Files\\Nmap.", L"The worker elevates only Nmap installed in Program Files\\Nmap."); return false; }
        if (!protected_object(root, diagnostic) || !protected_object(root / L"Nmap", diagnostic) || !protected_object(path, diagnostic)) return false;
        DWORD count = 0;
        for (const auto& item : std::filesystem::recursive_directory_iterator(root / L"Nmap")) {
            if (++count > 20000 || !protected_object(item.path(), diagnostic)) return false;
        }
        // A protected administrator-installed unsigned binary is allowed. A present but invalid signature is rejected.
        WINTRUST_FILE_INFO file{}; file.cbStruct = sizeof(file); file.pcwszFilePath = path.c_str();
        WINTRUST_DATA trust{}; trust.cbStruct = sizeof(trust); trust.dwUIChoice = WTD_UI_NONE;
        trust.fdwRevocationChecks = WTD_REVOKE_NONE; trust.dwUnionChoice = WTD_CHOICE_FILE; trust.pFile = &file;
        trust.dwStateAction = WTD_STATEACTION_VERIFY;
        trust.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE;
        GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG signedStatus = WinVerifyTrust(nullptr, &policy, &trust);
        trust.dwStateAction = WTD_STATEACTION_CLOSE; WinVerifyTrust(nullptr, &policy, &trust);
        if (signedStatus != ERROR_SUCCESS && signedStatus != TRUST_E_NOSIGNATURE) {
            diagnostic = tr(L"Firma Nmap presente ma non verificabile o non valida: elevazione rifiutata.",
                L"Nmap signature is present but invalid or unverifiable: elevation refused."); return false;
        }
        diagnostic = signedStatus == ERROR_SUCCESS ? tr(L"Nmap con firma verificata e installazione protetta.", L"Nmap signature verified and installation protected.") :
            tr(L"Nmap non firmato; attendibilità basata su installazione amministrativa interamente protetta da ACL.",
                L"Nmap is unsigned; trust is based on an administrator-installed tree entirely protected by ACLs.");
        return true;
    } catch (...) { diagnostic = tr(L"Impossibile verificare l'installazione protetta Nmap.", L"Unable to verify the protected Nmap installation."); return false; }
}

ProcessResult run_elevated_nmap(Protocol protocol, std::wstring_view ip, const std::filesystem::path& expectedNmap,
    const std::filesystem::path& xml, HANDLE cancel, const RawOutput& output) {
    ProcessResult result;
    std::wstring diagnostic;
    if ((protocol != Protocol::Tcp && protocol != Protocol::Udp) || !valid_ipv4(ip) || !trusted_elevation_nmap(expectedNmap, diagnostic)) {
        result.error = ERROR_ACCESS_DENIED;
        if (diagnostic.empty()) diagnostic = tr(L"Richiesta di scansione privilegiata non valida.", L"Invalid privileged scan request.");
        if (output) output(to_utf8(tr(L"Elevazione rifiutata: ", L"Elevation refused: ") + diagnostic + L"\r\n")); return result;
    }
    // Ensure the worker's automatic fixed installation selection is the same one used by the parent.
    std::filesystem::path selected;
    for (const auto& root : trusted_roots()) {
        auto candidate = root / L"Nmap" / L"nmap.exe";
        if (trusted_elevation_nmap(candidate, diagnostic)) { selected = candidate; break; }
    }
    if (selected.empty() || !same_path(expectedNmap, selected)) { result.error = ERROR_ACCESS_DENIED; return result; }
    auto nonce = random_token(); auto sid = process_user_sid(GetCurrentProcess()); auto ownPath = executable_path();
    if (nonce.empty() || sid.empty() || ownPath.empty()) { result.error = ERROR_INVALID_DATA; return result; }
    const DWORD parentPid = GetCurrentProcessId();
    auto name = pipe_name(parentPid, nonce);
    PSECURITY_DESCRIPTOR security = nullptr;
    // The UAC split token retains this user's SID. Elevation using another account is intentionally rejected.
    auto sddl = L"D:P(A;;GA;;;" + sid + L")";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &security, nullptr)) { result.error = GetLastError(); return result; }
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), security, FALSE};
    Handle pipe(CreateNamedPipeW(name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, maxFrame, maxFrame, 0, &attributes));
    LocalFree(security);
    if (!pipe) { result.error = GetLastError(); return result; }
    Handle connected(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    if (!connected) { result.error = GetLastError(); return result; }
    OVERLAPPED connection{}; connection.hEvent = connected.value;
    BOOL ready = ConnectNamedPipe(pipe.value, &connection);
    DWORD connectError = ready ? ERROR_SUCCESS : GetLastError();
    if (!ready && connectError != ERROR_IO_PENDING && connectError != ERROR_PIPE_CONNECTED) { result.error = connectError; return result; }
    if (connectError == ERROR_PIPE_CONNECTED || ready) SetEvent(connected.value);
    struct ConnectGuard {
        HANDLE pipe; OVERLAPPED* ov; bool pending = true;
        ~ConnectGuard() { if (pending) { DWORD bytes = 0; CancelIoEx(pipe, ov); GetOverlappedResult(pipe, ov, &bytes, TRUE); } }
    } connectionGuard{pipe.value, &connection, connectError == ERROR_IO_PENDING};
    auto parameters = L"--scaping-worker " + std::to_wstring(parentPid) + L" " + std::to_wstring(process_creation(GetCurrentProcess())) + L" " + quote_argument(nonce);
    struct UacLaunch {
        Handle ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
        Handle process;
        DWORD error = ERROR_GEN_FAILURE;
    };
    auto launchState = std::make_shared<UacLaunch>();
    if (!launchState->ready) { result.error = GetLastError(); return result; }
    // Consent can stay on the secure desktop indefinitely. This transient thread owns all of its state;
    // closing the GUI or cancelling the scan does not have to wait for the user's answer to UAC.
    const Language launchLanguage = current_language();
    std::thread([launchState, ownPath, parameters, launchLanguage] {
        ScopedLanguage language(launchLanguage);
        HRESULT com = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        SHELLEXECUTEINFOW launch{}; launch.cbSize = sizeof(launch);
        launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI;
        launch.lpVerb = L"runas"; launch.lpFile = ownPath.c_str(); launch.lpParameters = parameters.c_str();
        launch.lpDirectory = kRoot; launch.nShow = SW_HIDE;
        if (ShellExecuteExW(&launch)) { launchState->process.reset(launch.hProcess); launchState->error = ERROR_SUCCESS; }
        else launchState->error = GetLastError();
        SetEvent(launchState->ready.value);
        if (SUCCEEDED(com)) CoUninitialize();
    }).detach();
    HANDLE launchWaits[2] = {launchState->ready.value, cancel};
    DWORD launchWait = WaitForMultipleObjects(cancel ? 2 : 1, launchWaits, FALSE, INFINITE);
    if (launchWait != WAIT_OBJECT_0) {
        result.cancelled = true; result.error = ERROR_CANCELLED;
        // The original pipe is destroyed on return. A later consent result cannot start a scan.
        return result;
    }
    if (launchState->error) {
        result.error = launchState->error; result.cancelled = result.error == ERROR_CANCELLED;
        if (output) output(to_utf8(tr(L"UAC non accordata o worker non avviato: ", L"UAC was not granted or the worker did not start: ") +
            win_error(result.error) + tr(L". Scansione parziale.\r\n", L". Partial scan.\r\n")));
        return result;
    }
    Handle worker(launchState->process.release());
    if (!worker) { result.error = ERROR_INVALID_HANDLE; return result; }
    HANDLE waits[3] = {connected.value, worker.value}; DWORD count = 2;
    if (cancel) waits[count++] = cancel;
    DWORD wait = WaitForMultipleObjects(count, waits, FALSE, 30000);
    if (wait != WAIT_OBJECT_0) {
        result.cancelled = cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0;
        result.error = result.cancelled ? ERROR_CANCELLED : ERROR_PIPE_NOT_CONNECTED;
        if (connectionGuard.pending) {
            DWORD bytes = 0; CancelIoEx(pipe.value, &connection); GetOverlappedResult(pipe.value, &connection, &bytes, TRUE);
            connectionGuard.pending = false;
        }
        pipe.reset(); WaitForSingleObject(worker.value, 12000); return result;
    }
    DWORD transferred = 0;
    if (connectionGuard.pending && !GetOverlappedResult(pipe.value, &connection, &transferred, FALSE)) { result.error = GetLastError(); return result; }
    connectionGuard.pending = false;
    ULONG clientPid = 0;
    if (!GetNamedPipeClientProcessId(pipe.value, &clientPid) || clientPid != GetProcessId(worker.value)) { result.error = ERROR_ACCESS_DENIED; return result; }
    Request request; request.protocol = protocol == Protocol::Tcp ? 0 : 1;
    request.language = current_language() == Language::English ? 1 : 0;
    wcsncpy_s(request.ip, std::wstring(ip).c_str(), _TRUNCATE);
    if (!transfer(pipe.value, true, &request, sizeof(request), cancel, worker.value, 10000)) {
        result.error = ERROR_BROKEN_PIPE; result.cancelled = cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0; return result;
    }
    // Only the unelevated parent writes the caller's report path.
    std::ofstream xmlFile(xml, std::ios::binary | std::ios::trunc);
    if (!xmlFile) { result.error = ERROR_WRITE_FAULT; return result; }
    std::uint64_t xmlBytes = 0;
    bool gotFinish = false;
    for (;;) {
        Frame frame;
        if (!transfer(pipe.value, false, &frame, sizeof(frame), cancel, worker.value)) break;
        if (frame.bytes > maxFrame || (frame.type != textFrame && frame.type != xmlFrame && frame.type != finishFrame)) { result.error = ERROR_INVALID_DATA; break; }
        std::vector<char> bytes(frame.bytes);
        if (frame.bytes && !transfer(pipe.value, false, bytes.data(), frame.bytes, cancel, worker.value, 10000)) break;
        if (frame.type == textFrame) {
            if (output && !output(std::string_view(bytes.data(), bytes.size()))) { result.error = ERROR_WRITE_FAULT; break; }
        } else if (frame.type == xmlFrame) {
            xmlBytes += bytes.size(); if (xmlBytes > maxXml) { result.error = ERROR_FILE_TOO_LARGE; break; }
            xmlFile.write(bytes.data(), static_cast<std::streamsize>(bytes.size())); if (!xmlFile) { result.error = ERROR_WRITE_FAULT; break; }
        } else {
            if (frame.bytes != sizeof(Finish)) { result.error = ERROR_INVALID_DATA; break; }
            Finish finished{}; memcpy(&finished, bytes.data(), sizeof(finished));
            result.exitCode = finished.exitCode; result.error = finished.error; result.cancelled = finished.cancelled != 0; gotFinish = true; break;
        }
    }
    if (!gotFinish && !result.error) result.error = ERROR_BROKEN_PIPE;
    if (cancel && WaitForSingleObject(cancel, 0) == WAIT_OBJECT_0) { result.cancelled = true; result.error = ERROR_CANCELLED; }
    // Disconnect is the worker's cancellation signal. Its pending IPC writes abort and its Job Object kills all children.
    pipe.reset();
    WaitForSingleObject(worker.value, 12000);
    xmlFile.flush(); if (!xmlFile && !result.error) result.error = ERROR_WRITE_FAULT;
    return result;
}
}

namespace scaping {
int worker_entry(int argc, wchar_t** argv) {
    if (argc < 2 || !argv || wcscmp(argv[1], L"--scaping-worker") != 0) return -1;
    if (argc != 5) return ERROR_INVALID_PARAMETER;
    auto pid = net::parse_unsigned(argv[2]), created = net::parse_unsigned(argv[3]);
    if (!pid || !created || *pid == 0 || *pid > MAXDWORD || !net::valid_nonce(argv[4])) return ERROR_INVALID_PARAMETER;
    try { return net::serve_worker(static_cast<DWORD>(*pid), *created, argv[4]); }
    catch (...) { return ERROR_GEN_FAILURE; }
}
}
