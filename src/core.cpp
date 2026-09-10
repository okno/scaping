#include "scaping/core.hpp"
#include <windows.h>
#include <objbase.h>
#include <objidl.h>
#include <xmllite.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <bitset>
#include <climits>
#include <cwctype>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace scaping {
namespace {
constexpr std::uint64_t kMaxXmlBytes = 64ull * 1024 * 1024;
constexpr std::uint64_t kMaxConfigBytes = 64 * 1024;
struct Handle {
    HANDLE value = INVALID_HANDLE_VALUE;
    ~Handle() { if (value != INVALID_HANDLE_VALUE && value) CloseHandle(value); }
};
template<class T> struct ComPtr {
    T* ptr = nullptr;
    ~ComPtr() { if (ptr) ptr->Release(); }
    T* operator->() const { return ptr; }
};
bool number(std::wstring_view value, std::uint32_t& result) {
    if (value.empty() || value.size() > 10) return false;
    std::uint64_t n = 0;
    for (wchar_t c : value) {
        if (c < L'0' || c > L'9') return false;
        n = n * 10 + static_cast<unsigned>(c - L'0');
        if (n > UINT32_MAX) return false;
    }
    result = static_cast<std::uint32_t>(n);
    return true;
}
std::wstring trim(std::wstring_view value) {
    while (!value.empty() && (value.front() == L' ' || value.front() == L'\t' || value.front() == L'\r')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == L' ' || value.back() == L'\t' || value.back() == L'\r')) value.remove_suffix(1);
    return std::wstring(value);
}
bool read_bounded(const std::filesystem::path& file, std::uint64_t limit, std::string& bytes) {
    Handle handle{CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr)};
    if (handle.value == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(handle.value, &size) || size.QuadPart < 0 || static_cast<std::uint64_t>(size.QuadPart) > limit) return false;
    bytes.resize(static_cast<std::size_t>(size.QuadPart));
    DWORD read = 0;
    return bytes.empty() || (ReadFile(handle.value, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) && read == bytes.size());
}
std::wstring field(std::wstring_view value) {
    auto result = sanitize_text(value, 8192);
    for (auto& c : result) if (c == L'\r' || c == L'\n' || c == L'\t') c = L' ';
    return result;
}
bool state_valid(std::wstring_view value) {
    return value == L"open" || value == L"closed" || value == L"filtered" || value == L"unfiltered" || value == L"open|filtered" || value == L"closed|filtered";
}
bool full_range(std::wstring_view text) {
    if (text.empty() || text.size() > 512 * 1024) return false;
    std::bitset<kPortCount> found;
    while (!text.empty()) {
        const auto comma = text.find(L',');
        auto part = text.substr(0, comma);
        const auto dash = part.find(L'-');
        std::uint32_t first = 0, last = 0;
        if (dash == std::wstring_view::npos) {
            if (!number(part, first)) return false;
            last = first;
        } else {
            if (!number(part.substr(0, dash), first) || !number(part.substr(dash + 1), last)) return false;
        }
        if (first > last || last >= kPortCount) return false;
        for (std::uint32_t port = first; port <= last; ++port) {
            if (found[port]) return false;
            found.set(port);
        }
        if (comma == std::wstring_view::npos) break;
        text.remove_prefix(comma + 1);
        if (text.empty()) return false;
    }
    return found.all();
}
bool has_service_flag(std::wstring_view args) {
    // The process launcher supplies this fixed switch. Never interpret or execute XML args.
    if (args.empty()) return false;
    int count = 0;
    auto arguments = CommandLineToArgvW(std::wstring(args).c_str(), &count);
    if (!arguments) return false;
    bool found = false;
    for (int index = 1; index < count; ++index) if (std::wstring_view(arguments[index]) == L"-sV") found = true;
    LocalFree(arguments);
    return found;
}
using Attributes = std::map<std::wstring, std::wstring>;
bool attributes(IXmlReader* reader, Attributes& values, bool scanInfo) {
    auto status = reader->MoveToFirstAttribute();
    std::size_t count = 0;
    while (status == S_OK) {
        const wchar_t *name = nullptr, *value = nullptr;
        UINT nameLength = 0, valueLength = 0;
        if (++count > 64 || FAILED(reader->GetQualifiedName(&name, &nameLength)) || FAILED(reader->GetValue(&value, &valueLength))) return false;
        if (nameLength > 128 || valueLength > ((scanInfo && std::wstring_view(name, nameLength) == L"services") ? 512u * 1024u : 32768u)) return false;
        if (!values.emplace(std::wstring(name, nameLength), std::wstring(value, valueLength)).second) return false;
        status = reader->MoveToNextAttribute();
    }
    return !FAILED(status) && SUCCEEDED(reader->MoveToElement());
}
std::wstring get(const Attributes& values, const wchar_t* key) {
    const auto it = values.find(key);
    return it == values.end() ? std::wstring{} : it->second;
}
}

bool valid_ipv4(std::wstring_view ip) {
    if (ip.empty() || ip.size() > 15) return false;
    for (int component = 0; component < 4; ++component) {
        const auto dot = ip.find(L'.');
        const auto part = ip.substr(0, dot);
        std::uint32_t value = 0;
        if (part.empty() || part.size() > 3 || (part.size() > 1 && part.front() == L'0') || !number(part, value) || value > 255) return false;
        if (component == 3) return dot == std::wstring_view::npos;
        if (dot == std::wstring_view::npos) return false;
        ip.remove_prefix(dot + 1);
    }
    return false;
}

std::optional<std::wstring> validate_config(const Config& c, bool allowEmptyIp) {
    if (c.language != Language::Italian && c.language != Language::English) return tr(L"Lingua non supportata.", L"Unsupported language.");
    if (!(allowEmptyIp && c.ip.empty()) && !valid_ipv4(c.ip)) return tr(L"Inserire un IPv4 numerico valido (esempio: 192.0.2.1), senza spazi, zeri iniziali, URL o liste.", L"Enter a valid numeric IPv4 address (for example, 192.0.2.1), without spaces, leading zeros, URLs or lists.");
    if (c.intervalMs < 250 || c.intervalMs > 60000) return tr(L"L'intervallo deve essere compreso tra 250 e 60000 ms.", L"The interval must be between 250 and 60000 ms.");
    if (c.timeoutMs < 100 || c.timeoutMs > 60000) return tr(L"Il timeout deve essere compreso tra 100 e 60000 ms.", L"The timeout must be between 100 and 60000 ms.");
    if (!c.slowMs || c.slowMs >= c.timeoutMs) return tr(L"La soglia ping lento deve essere positiva e inferiore al timeout.", L"The slow ping threshold must be positive and lower than the timeout.");
    if (!c.concurrency || c.concurrency > 256) return tr(L"La concorrenza deve essere compresa tra 1 e 256.", L"Concurrency must be between 1 and 256.");
    if (!c.connectionsPerSecond || c.connectionsPerSecond > 1024) return tr(L"La velocita deve essere compresa tra 1 e 1024 connessioni al secondo.", L"The rate must be between 1 and 1024 connections per second.");
    if (!c.nmapPath.empty()) {
        if (c.nmapPath.size() > 32700 || c.nmapPath.find_first_of(L"\r\n\t\"<>|") != std::wstring::npos || c.nmapPath.find(L'\0') != std::wstring::npos) return tr(L"Il percorso Nmap contiene caratteri non validi.", L"The Nmap path contains invalid characters.");
        const std::filesystem::path path(c.nmapPath);
        if (!path.is_absolute() || c.nmapPath.starts_with(L"\\\\") || path.filename().empty() || _wcsicmp(path.filename().c_str(), L"nmap.exe") != 0) return tr(L"Il percorso Nmap deve essere locale, assoluto e indicare nmap.exe.", L"The Nmap path must be local, absolute and point to nmap.exe.");
    }
    return std::nullopt;
}

ConfigLoad load_config(const std::filesystem::path& file) {
    ConfigLoad result;
    const auto attr = GetFileAttributesW(file.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND)) return result;
    result.existed = true;
    auto bad = [&]() {
        result.config = Config{};
        result.valid = false;
        result.diagnostic = tr(L"Configurazione non leggibile, corrotta o non supportata: ripristinati i valori iniziali. IP non configurato.", L"Configuration unreadable, corrupted or unsupported: default settings restored. IP not configured.");
        return result;
    };
    std::string bytes;
    if (!read_bounded(file, kMaxConfigBytes, bytes) || bytes.empty() || bytes.find('\0') != std::string::npos) return bad();
    if (bytes.starts_with("\xef\xbb\xbf")) bytes.erase(0, 3);
    auto text = from_utf8(bytes);
    if (text.empty()) return bad();
    std::wistringstream input(text);
    std::wstring line;
    bool section = false;
    std::map<std::wstring, std::wstring> values;
    const std::set<std::wstring> keys{L"version", L"ip", L"interval_ms", L"timeout_ms", L"slow_ms", L"auto_start", L"nmap_path", L"concurrency", L"connections_per_second", L"language"};
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line.front() == L';' || line.front() == L'#') continue;
        if (line == L"[scaping]") { if (section) return bad(); section = true; continue; }
        if (!section) return bad();
        auto equal = line.find(L'=');
        if (equal == std::wstring::npos) return bad();
        auto key = trim(std::wstring_view(line).substr(0, equal));
        auto value = trim(std::wstring_view(line).substr(equal + 1));
        if (!keys.contains(key) || !values.emplace(key, value).second) return bad();
    }
    const bool legacy = values[L"version"] == L"1";
    if (legacy) {
        if (values.size() != keys.size() - 1 || values.contains(L"language")) return bad();
    } else {
        if (values[L"version"] != L"2" || values.size() != keys.size() || !values.contains(L"language")) return bad();
        if (values[L"language"] != L"it" && values[L"language"] != L"en") return bad();
    }
    auto& c = result.config;
    c.language = !legacy && values[L"language"] == L"en" ? Language::English : Language::Italian;
    c.ip = values[L"ip"];
    c.nmapPath = values[L"nmap_path"];
    if (!number(values[L"interval_ms"], c.intervalMs) || !number(values[L"timeout_ms"], c.timeoutMs) || !number(values[L"slow_ms"], c.slowMs) || !number(values[L"concurrency"], c.concurrency) || !number(values[L"connections_per_second"], c.connectionsPerSecond)) return bad();
    if (values[L"auto_start"] != L"0" && values[L"auto_start"] != L"1") return bad();
    c.autoStart = values[L"auto_start"] == L"1";
    if (validate_config(c, true)) return bad();
    return result;
}

bool save_config(const std::filesystem::path& file, const Config& c, std::wstring& error) {
    error.clear();
    if (auto invalid = validate_config(c, true)) { error = *invalid; return false; }
    if (!file.is_absolute()) { error = tr(L"Il percorso configurazione deve essere assoluto.", L"The configuration path must be absolute."); return false; }
    std::error_code ec;
    std::filesystem::create_directories(file.parent_path(), ec);
    if (ec) { error = tr(L"Impossibile creare la cartella di configurazione.", L"Cannot create the configuration directory."); return false; }
    std::wostringstream ini;
    ini << L"[scaping]\r\nversion=2\r\nlanguage=" << (c.language == Language::English ? L"en" : L"it")
        << L"\r\nip=" << c.ip << L"\r\ninterval_ms=" << c.intervalMs << L"\r\ntimeout_ms=" << c.timeoutMs
        << L"\r\nslow_ms=" << c.slowMs << L"\r\nauto_start=" << (c.autoStart ? 1 : 0) << L"\r\nnmap_path=" << c.nmapPath
        << L"\r\nconcurrency=" << c.concurrency << L"\r\nconnections_per_second=" << c.connectionsPerSecond << L"\r\n";
    auto bytes = to_utf8(ini.str());
    if (bytes.empty() || bytes.size() > kMaxConfigBytes) { error = tr(L"Configurazione troppo grande o codifica non valida.", L"Configuration too large or invalid encoding."); return false; }
    std::filesystem::path temporary;
    bool written = false;
    for (unsigned attempt = 0; attempt < 32 && !written; ++attempt) {
        temporary = file.wstring() + L".tmp." + std::to_wstring(GetCurrentProcessId()) + L"." + std::to_wstring(GetTickCount64()) + L"." + std::to_wstring(attempt);
        Handle handle{CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
        if (handle.value == INVALID_HANDLE_VALUE) {
            if (GetLastError() == ERROR_FILE_EXISTS || GetLastError() == ERROR_ALREADY_EXISTS) continue;
            error = tr(L"Impossibile creare il file temporaneo di configurazione.", L"Cannot create the temporary configuration file."); return false;
        }
        DWORD count = 0;
        written = WriteFile(handle.value, bytes.data(), static_cast<DWORD>(bytes.size()), &count, nullptr) && count == bytes.size() && FlushFileBuffers(handle.value);
        if (!written) {
            CloseHandle(handle.value); handle.value = INVALID_HANDLE_VALUE;
            DeleteFileW(temporary.c_str()); error = tr(L"Scrittura configurazione non riuscita.", L"Failed to write the configuration."); return false;
        }
    }
    if (!written) { error = tr(L"Impossibile creare un file temporaneo esclusivo.", L"Cannot create an exclusive temporary file."); return false; }
    // Same-directory rename provides atomic replacement; never truncate the current file.
    if (!MoveFileExW(temporary.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        DeleteFileW(temporary.c_str()); error = tr(L"Sostituzione atomica configurazione non riuscita.", L"Atomic configuration replacement failed."); return false;
    }
    return true;
}

PingColor ping_color(const PingResult& result, std::uint32_t slowMs) {
    if (!result.success) return PingColor::Red;
    return result.rttMs < slowMs ? PingColor::Green : PingColor::Orange;
}
bool accept_ping_generation(std::uint64_t active, const PingResult& result) { return active == result.generation; }
std::wstring sanitize_text(std::wstring_view input, std::size_t limit) {
    std::wstring result;
    result.reserve(std::min(input.size(), limit));
    for (std::size_t index = 0; index < input.size() && result.size() < limit; ++index) {
        wchar_t c = input[index];
        if ((c < 32 && c != L'\r' && c != L'\n' && c != L'\t') || (c >= 0x7f && c <= 0x9f) || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0x200e || c == 0x200f) c = L'?';
        if (c >= 0xd800 && c <= 0xdbff) {
            if (index + 1 < input.size() && input[index + 1] >= 0xdc00 && input[index + 1] <= 0xdfff && result.size() + 2 <= limit) {
                result += c; result += input[++index]; continue;
            }
            c = L'?';
        } else if (c >= 0xdc00 && c <= 0xdfff) c = L'?';
        result += c;
    }
    return result;
}
std::wstring from_utf8(std::string_view input) {
    if (input.empty() || input.size() > INT_MAX) return {};
    const int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0);
    if (!size) return {};
    std::wstring output(static_cast<std::size_t>(size), 0);
    MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), size);
    return output;
}
std::string to_utf8(std::wstring_view input) {
    if (input.empty() || input.size() > INT_MAX) return {};
    const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), nullptr, 0, nullptr, nullptr);
    if (!size) return {};
    std::string output(static_cast<std::size_t>(size), 0);
    WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input.data(), static_cast<int>(input.size()), output.data(), size, nullptr, nullptr);
    return output;
}
std::wstring quote_argument(std::wstring_view arg) {
    // Windows CommandLineToArgvW/CRT quoting: double slashes preceding a quote or the final quote.
    if (arg.find(L'\0') != std::wstring_view::npos) return {};
    std::wstring result = L"\"";
    std::size_t slashes = 0;
    for (wchar_t c : arg) {
        if (c == L'\\') { ++slashes; continue; }
        result.append(c == L'\"' ? slashes * 2 + 1 : slashes, L'\\');
        slashes = 0;
        result += c;
    }
    result.append(slashes * 2, L'\\');
    result += L'\"';
    return result;
}
std::vector<std::wstring> nmap_arguments(Protocol protocol, std::wstring_view ip, const std::filesystem::path& xmlFile) {
    if (!valid_ipv4(ip) || !xmlFile.is_absolute() || xmlFile.wstring().find_first_of(L"\r\n\"") != std::wstring::npos || xmlFile.wstring().find(L'\0') != std::wstring::npos) return {};
    return {protocol == Protocol::Tcp ? L"-sT" : L"-sU", L"-n", L"-Pn", L"-p0-65535", L"-sV", L"--version-light", L"-T3", L"--reason", L"--stats-every", L"2s", L"-oX", xmlFile.wstring(), std::wstring(ip)};
}

NmapResult parse_nmap_xml(const std::filesystem::path& file, Protocol expected, std::wstring_view expectedIp) {
    NmapResult result;
    auto fail = [&](std::wstring message) {
        result.valid = false; result.finished = false; result.coverageComplete = false; result.serviceDetectionComplete = false;
        result.diagnostic = std::move(message);
        return result;
    };
    if (!expectedIp.empty() && !valid_ipv4(expectedIp)) return fail(tr(L"Target atteso non valido.", L"Invalid expected target."));
    std::string bytes;
    if (!read_bounded(file, kMaxXmlBytes, bytes) || bytes.empty()) return fail(tr(L"XML assente, illeggibile o superiore al limite di 64 MiB.", L"XML missing, unreadable or larger than the 64 MiB limit."));
    // Nmap emits this inert declaration without a DTD. All external/internal subsets are rejected.
    if (auto position = bytes.find("<!DOCTYPE"); position != std::string::npos) {
        constexpr std::string_view inert = "<!DOCTYPE nmaprun>";
        if (bytes.compare(position, inert.size(), inert) != 0 || bytes.find("<!DOCTYPE", position + inert.size()) != std::string::npos) return fail(tr(L"XML rifiutato: DTD o entita esterne non ammesse.", L"XML rejected: DTDs and external entities are not allowed."));
        bytes.erase(position, inert.size());
    }
    if (bytes.find("<!ENTITY") != std::string::npos) return fail(tr(L"XML rifiutato: dichiarazioni di entita non ammesse.", L"XML rejected: entity declarations are not allowed."));
    ComPtr<IStream> stream{SHCreateMemStream(reinterpret_cast<const BYTE*>(bytes.data()), static_cast<UINT>(bytes.size()))};
    ComPtr<IXmlReader> reader;
    if (!stream.ptr || FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(&reader.ptr), nullptr))) return fail(tr(L"Impossibile inizializzare il parser XML.", L"Cannot initialize the XML parser."));
    if (FAILED(reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) || FAILED(reader->SetProperty(XmlReaderProperty_XmlResolver, 0)) || FAILED(reader->SetProperty(XmlReaderProperty_MaxElementDepth, 64)) || FAILED(reader->SetInput(stream.ptr))) return fail(tr(L"Impossibile configurare il parser XML sicuro.", L"Cannot configure the secure XML parser."));
    std::vector<std::wstring> path;
    std::optional<PortResult> current;
    std::bitset<kPortCount> explicitPorts;
    bool rootSeen = false, rootClosed = false, scanInfoSeen = false, fullRange = false, serviceRequested = false, finishedSeen = false, hostUp = false;
    unsigned hosts = 0, portContainers = 0, finishedCount = 0, ipv4Addresses = 0;
    std::uint32_t declaredPorts = 0;
    std::uint64_t aggregateCount = 0;
    std::map<std::wstring, std::uint32_t> aggregateStates;
    std::size_t nodes = 0;
    XmlNodeType type{};
    HRESULT status = S_OK;
    const std::wstring protocol = expected == Protocol::Tcp ? L"tcp" : L"udp";
    auto completePort = [&]() {
        if (!current || !state_valid(current->state) || explicitPorts[current->port]) return false;
        explicitPorts.set(current->port);
        result.ports.push_back(std::move(*current)); current.reset(); return true;
    };
    while ((status = reader->Read(&type)) == S_OK) {
        if (++nodes > 2000000) return fail(tr(L"XML rifiutato: troppi nodi.", L"XML rejected: too many nodes."));
        UINT depth = 0;
        if (FAILED(reader->GetDepth(&depth)) || depth > 64) return fail(tr(L"XML rifiutato: annidamento eccessivo.", L"XML rejected: excessive nesting."));
        if (type == XmlNodeType_DocumentType) return fail(tr(L"XML rifiutato: DTD o entita non ammesse.", L"XML rejected: DTDs and entities are not allowed."));
        if (type != XmlNodeType_Element && type != XmlNodeType_EndElement) continue;
        const wchar_t* rawName = nullptr;
        UINT length = 0;
        if (FAILED(reader->GetQualifiedName(&rawName, &length)) || length > 128) return fail(tr(L"Nome XML non valido.", L"Invalid XML name."));
        std::wstring name(rawName, length);
        if (type == XmlNodeType_EndElement) {
            if (path.empty() || path.back() != name) return fail(tr(L"Struttura XML non valida.", L"Invalid XML structure."));
            if (path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports", L"port"} && !completePort()) return fail(tr(L"Porta duplicata o senza stato valido.", L"Duplicate port or port without a valid state."));
            if (path.size() == 1 && name == L"nmaprun") rootClosed = true;
            path.pop_back();
            continue;
        }
        const bool empty = reader->IsEmptyElement() != FALSE;
        Attributes attr;
        if (!attributes(reader.ptr, attr, name == L"scaninfo")) return fail(tr(L"XML rifiutato: attributi eccessivi o non validi.", L"XML rejected: excessive or invalid attributes."));
        const auto parent = path.empty() ? std::wstring{} : path.back();
        if (path.empty()) {
            if (rootSeen || name != L"nmaprun" || get(attr, L"scanner") != L"nmap") return fail(tr(L"Il file non e un risultato Nmap valido.", L"The file is not a valid Nmap result."));
            rootSeen = true; serviceRequested = has_service_flag(get(attr, L"args"));
        } else if (name == L"scaninfo" && path.size() == 1) {
            if (scanInfoSeen || get(attr, L"protocol") != protocol || !number(get(attr, L"numservices"), declaredPorts) || declaredPorts > kPortCount) return fail(tr(L"Copertura o protocollo scaninfo non validi.", L"Invalid scaninfo coverage or protocol."));
            const auto scanType = get(attr, L"type");
            if ((expected == Protocol::Tcp && scanType != L"connect" && scanType != L"syn") || (expected == Protocol::Udp && scanType != L"udp")) return fail(tr(L"Tipo di scansione inatteso.", L"Unexpected scan type."));
            scanInfoSeen = true; fullRange = declaredPorts == kPortCount && full_range(get(attr, L"services"));
        } else if (name == L"host" && path.size() == 1) {
            if (++hosts != 1) return fail(tr(L"XML rifiutato: deve contenere un solo host.", L"XML rejected: it must contain exactly one host."));
            if (get(attr, L"timedout") == L"true") return fail(tr(L"Nmap ha interrotto l'host per timeout: risultato parziale.", L"Nmap stopped the host scan after a timeout: partial result."));
        } else if (name == L"status" && path == std::vector<std::wstring>{L"nmaprun", L"host"}) {
            hostUp = get(attr, L"state") == L"up";
        } else if (name == L"address" && path == std::vector<std::wstring>{L"nmaprun", L"host"} && get(attr, L"addrtype") == L"ipv4") {
            const auto address = get(attr, L"addr");
            if (++ipv4Addresses != 1 || !valid_ipv4(address) || (!expectedIp.empty() && address != expectedIp)) return fail(tr(L"L'indirizzo XML non corrisponde al target richiesto.", L"The XML address does not match the requested target."));
        } else if (name == L"ports" && path == std::vector<std::wstring>{L"nmaprun", L"host"}) {
            if (++portContainers != 1) return fail(tr(L"Sezione porte duplicata.", L"Duplicate ports section."));
        } else if (name == L"extraports" && path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports"}) {
            std::uint32_t count = 0;
            auto state = get(attr, L"state");
            if (!state_valid(state) || !number(get(attr, L"count"), count) || !count || count > kPortCount || aggregateStates.contains(state)) return fail(tr(L"Conteggio o stato aggregato delle porte non valido.", L"Invalid aggregate port count or state."));
            aggregateCount += count;
            if (aggregateCount > kPortCount) return fail(tr(L"Conteggio aggregato delle porte eccessivo.", L"Excessive aggregate port count."));
            aggregateStates[state] = count;
        } else if (name == L"port" && path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports"}) {
            std::uint32_t port = 0;
            if (current || !number(get(attr, L"portid"), port) || port >= kPortCount || get(attr, L"protocol") != protocol || explicitPorts[port] || empty) return fail(tr(L"Protocollo, porta o duplicato non valido.", L"Invalid protocol, port or duplicate entry."));
            current = PortResult{}; current->protocol = expected; current->port = port;
        } else if (name == L"state" && path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports", L"port"}) {
            if (!current || !current->state.empty() || !state_valid(get(attr, L"state"))) return fail(tr(L"Stato di porta non valido.", L"Invalid port state."));
            current->state = get(attr, L"state"); current->reason = field(get(attr, L"reason"));
        } else if (name == L"service" && path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports", L"port"}) {
            if (!current || !current->service.empty()) return fail(tr(L"Servizio duplicato o fuori contesto.", L"Duplicate or misplaced service."));
            current->service = field(get(attr, L"name")); current->product = field(get(attr, L"product"));
            current->version = field(get(attr, L"version")); current->extra = field(get(attr, L"extrainfo"));
            current->serviceFromResponse = get(attr, L"method") == L"probed";
        } else if (name == L"script" && current && path == std::vector<std::wstring>{L"nmaprun", L"host", L"ports", L"port"}) {
            // Only a real, explicitly present banner field is a banner; service fingerprints are not.
            if (get(attr, L"id") == L"banner") current->banner = field(get(attr, L"output"));
        } else if (name == L"finished" && path == std::vector<std::wstring>{L"nmaprun", L"runstats"}) {
            if (++finishedCount != 1) return fail(tr(L"Risultato finale Nmap duplicato.", L"Duplicate Nmap completion result."));
            finishedSeen = true; result.finished = get(attr, L"exit") == L"success";
            if (!result.finished) result.diagnostic = tr(L"Nmap ha terminato con errore: risultato parziale. ", L"Nmap finished with an error: partial result. ") + field(get(attr, L"errormsg"));
        }
        if (!empty) path.push_back(name);
        else if (path.empty() && name == L"nmaprun") rootClosed = true;
    }
    if (FAILED(status) || !rootSeen || !rootClosed || !path.empty() || current) return fail(tr(L"XML incompleto o malformato: risultato parziale.", L"Incomplete or malformed XML: partial result."));
    if (!expectedIp.empty() && ipv4Addresses != 1) return fail(tr(L"XML privo dell'indirizzo IPv4 atteso.", L"XML does not contain the expected IPv4 address."));
    if (!scanInfoSeen || aggregateCount + result.ports.size() > kPortCount || aggregateCount + result.ports.size() > declaredPorts) return fail(tr(L"Conteggio delle porte incoerente con scaninfo.", L"Port count does not match scaninfo."));
    result.valid = true;
    result.scannedPorts = static_cast<std::uint32_t>(aggregateCount + result.ports.size());
    result.coverageComplete = fullRange && hosts == 1 && hostUp && portContainers == 1 && result.scannedPorts == kPortCount && finishedSeen && result.finished;
    result.serviceDetectionComplete = result.coverageComplete && serviceRequested;
    if (!result.coverageComplete && result.diagnostic.empty()) result.diagnostic = tr(L"Copertura incompleta: la fase resta parziale.", L"Incomplete coverage: this phase remains partial.");
    std::wostringstream summary;
    summary << (expected == Protocol::Tcp ? L"TCP" : L"UDP") << tr(L": copertura ", L": coverage ") << result.scannedPorts << tr(L"/65536 porte; ", L"/65536 ports; ") << (result.coverageComplete ? tr(L"port scanning completo", L"port scanning complete") : tr(L"port scanning parziale", L"port scanning partial")) << tr(L"; rilevamento servizi ", L"; service detection ") << (result.serviceDetectionComplete ? tr(L"terminato (esclusioni standard Nmap e servizi non identificati possibili)", L"finished (standard Nmap exclusions apply; services may remain unidentified)") : tr(L"non completato o non verificabile", L"incomplete or unverifiable")) << L".\r\n";
    for (const auto& [state, count] : aggregateStates) summary << tr(L"Stato aggregato ", L"Aggregate state ") << state << L": " << count << tr(L" porte (numeri individuali non presenti nell'XML).\r\n", L" ports (individual port numbers are not present in the XML).\r\n");
    if (expected == Protocol::Udp) summary << tr(L"UDP: open|filtered significa aperta oppure filtrata; il silenzio non dimostra che una porta sia chiusa.\r\n", L"UDP: open|filtered means open or filtered; silence does not prove that a port is closed.\r\n");
    result.summary = summary.str();
    return result;
}

std::wstring format_port(const PortResult& p) {
    std::wostringstream output;
    output << (p.protocol == Protocol::Tcp ? L"TCP" : L"UDP") << L" " << p.port << L" | " << field(p.state) << tr(L" | servizio: ", L" | service: ");
    if (p.service.empty()) output << tr(L"non identificato", L"unidentified");
    else output << field(p.service) << (p.serviceFromResponse ? tr(L" (risposta)", L" (response-based)") : tr(L" (nome convenzionale)", L" (conventional port name)"));
    output << tr(L" | prodotto: ", L" | product: ") << (p.product.empty() ? tr(L"non identificato", L"unidentified") : field(p.product)) << tr(L" | versione: ", L" | version: ") << (p.version.empty() ? tr(L"non identificata", L"unidentified") : field(p.version));
    if (!p.extra.empty()) output << tr(L" | informazioni: ", L" | information: ") << field(p.extra);
    output << L" | banner: " << (p.banner.empty() ? tr(L"non disponibile", L"not available") : field(p.banner));
    if (!p.reason.empty()) output << tr(L" | motivo: ", L" | reason: ") << field(p.reason);
    output << L"\r\n";
    return output.str();
}
}
