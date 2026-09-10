#include "scaping/core.hpp"
#include <windows.h>
#include <shellapi.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace {
int checks = 0;
void require(bool condition, const char* message) {
    ++checks;
    if (!condition) throw std::runtime_error(message);
}
void write(const std::filesystem::path& file, std::string_view text) {
    std::ofstream output(file, std::ios::binary | std::ios::trunc);
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    require(output.good(), "fixture write");
}
std::string nmap_xml(std::string_view protocol, std::string_view ports, std::string_view services = "0-65535", std::string_view count = "65536", std::string_view ending = "success", bool versionDetection = true) {
    std::ostringstream xml;
    xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE nmaprun>\n<nmaprun scanner=\"nmap\" args=\"nmap " << (versionDetection ? "-sV" : "-n") << " -p0-65535 192.0.2.1\">"
        << "<scaninfo type=\"" << (protocol == "tcp" ? "connect" : "udp") << "\" protocol=\"" << protocol << "\" numservices=\"" << count << "\" services=\"" << services << "\"/>"
        << "<host><status state=\"up\" reason=\"user-set\"/><address addr=\"192.0.2.1\" addrtype=\"ipv4\"/><ports>" << ports
        << "</ports></host><runstats><finished exit=\"" << ending << "\"/></runstats></nmaprun>";
    return xml.str();
}
void test_ipv4() {
    for (const auto* ip : {L"0.0.0.0", L"255.255.255.255", L"192.0.2.1", L"127.0.0.1", L"1.2.3.4"}) require(scaping::valid_ipv4(ip), "valid IPv4 rejected");
    for (const auto* ip : {L"", L"example.invalid", L"256.0.0.1", L"1.2.3", L"1.2.3.4.5", L"1..3.4", L"01.2.3.4", L"+1.2.3.4", L"-sV", L"192.0.2.1/24", L"192.0.2.1-2", L"192.0.2.1,192.0.2.2", L"192.0.2.1\r\n", L" 192.0.2.1", L"192.0.2.1 ", L"http://192.0.2.1", L"1.2.3.４", L"0x7f000001", L"127.1", L"2130706433", L"1.2.3.4&calc"}) require(!scaping::valid_ipv4(ip), "invalid IPv4 accepted");
    const wchar_t nulIp[]{L'1',L'.',L'2',L'.',L'3',L'.',L'4',0,L'5'};
    require(!scaping::valid_ipv4(std::wstring_view(nulIp, std::size(nulIp))), "embedded NUL IPv4 accepted");
}
void test_colors() {
    scaping::PingResult result;
    result.generation = 17; result.success = true; result.rttMs = 0;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Green, "zero RTT green");
    result.rttMs = 149;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Green, "below threshold green");
    result.rttMs = 150;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Orange, "equal threshold orange");
    result.rttMs = 999;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Orange, "above threshold orange");
    result.success = false; result.rttMs = 0; result.errorCode = 11010;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Red, "simulated ICMP timeout red");
    result.errorCode = 11003;
    require(scaping::ping_color(result, 150) == scaping::PingColor::Red, "simulated negative ICMP red");
    require(scaping::accept_ping_generation(17, result), "current generation rejected");
    require(!scaping::accept_ping_generation(18, result), "stale pending ping accepted");
}
void test_config(const std::filesystem::path& temporary) {
    scaping::Config config;
    require(scaping::validate_config(config).has_value(), "empty target must be rejected by settings");
    require(!scaping::validate_config(config, true), "default empty config invalid");
    config.ip = L"192.0.2.1";
    require(!scaping::validate_config(config), "defaults invalid");
    const auto good = config;
    for (const auto value : {0u, 249u, 60001u, UINT32_MAX}) { config = good; config.intervalMs = value; require(scaping::validate_config(config).has_value(), "invalid interval accepted"); }
    for (const auto value : {0u, 99u, 60001u, UINT32_MAX}) { config = good; config.timeoutMs = value; require(scaping::validate_config(config).has_value(), "invalid timeout accepted"); }
    for (const auto value : {0u, 800u, 801u, UINT32_MAX}) { config = good; config.slowMs = value; require(scaping::validate_config(config).has_value(), "invalid threshold accepted"); }
    for (const auto value : {0u, 257u, UINT32_MAX}) { config = good; config.concurrency = value; require(scaping::validate_config(config).has_value(), "invalid concurrency accepted"); }
    for (const auto value : {0u, 1025u, UINT32_MAX}) { config = good; config.connectionsPerSecond = value; require(scaping::validate_config(config).has_value(), "invalid rate accepted"); }
    for (const auto* path : {L"nmap.exe", L"D:\\synthetic\\other.exe", L"D:\\synthetic\\nmap.exe\n-sV"}) { config = good; config.nmapPath = path; require(scaping::validate_config(config).has_value(), "invalid nmap path accepted"); }
    auto file = temporary / L"config.ini";
    auto missing = scaping::load_config(file);
    require(!missing.existed && missing.valid && missing.config.ip.empty(), "missing config behavior");
    config = good;
    config.nmapPath = L"D:\\synthetic installazione\\nmap.exe";
    config.autoStart = true;
    std::wstring error;
    require(scaping::save_config(file, config, error), "atomic config save failed");
    auto loaded = scaping::load_config(file);
    require(loaded.existed && loaded.valid && loaded.config.ip == config.ip && loaded.config.nmapPath == config.nmapPath && loaded.config.autoStart, "config roundtrip failed");
    config.ip = L"192.0.2.2";
    require(scaping::save_config(file, config, error), "atomic config replacement failed");
    require(scaping::load_config(file).config.ip == L"192.0.2.2", "replacement not persisted");
    config.slowMs = config.timeoutMs;
    require(!scaping::save_config(file, config, error), "invalid config saved");
    require(scaping::load_config(file).config.ip == L"192.0.2.2", "rejected save changed previous config");
    config = good; config.ip = L"192.0.2.3";
    const auto locked = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    require(locked != INVALID_HANDLE_VALUE, "lock old config for failure simulation");
    const bool replacementSucceeded = scaping::save_config(file, config, error);
    CloseHandle(locked);
    require(!replacementSucceeded && scaping::load_config(file).config.ip == L"192.0.2.2", "failed atomic replace damaged prior config");
    for (const auto* invalid : {"", "[scaping]\nversion=2\n", "[scaping]\nversion=1\nip=192.0.2.1\nip=192.0.2.2\n", "[scaping]\nversion=1\nunknown=1\n", "[other]\nversion=1\n", "\xff\xfe"}) {
        write(file, invalid); loaded = scaping::load_config(file);
        require(loaded.existed && !loaded.valid && loaded.config.ip.empty() && !loaded.diagnostic.empty(), "corrupt config did not reset safely");
    }
    config = good;
    require(scaping::save_config(file, config, error), "save restored config");
    std::ifstream original(file, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(original)), std::istreambuf_iterator<char>());
    original.close();
    for (const auto* badValue : {"4294967296", "-1", "+1000", "1000ms", "1.5"}) {
        auto corrupt = text;
        auto pos = corrupt.find("interval_ms=1000");
        corrupt.replace(pos, std::string("interval_ms=1000").size(), std::string("interval_ms=") + badValue);
        write(file, corrupt); require(!scaping::load_config(file).valid, "corrupt numeric config accepted");
    }
    write(file, std::string(65537, 'x'));
    require(!scaping::load_config(file).valid, "oversize config accepted");
    config = good; config.ip.clear();
    require(scaping::save_config(file, config, error) && scaping::load_config(file).valid, "initial blank config roundtrip");
    require(!scaping::save_config(L"relative.ini", config, error), "relative config output accepted");
}
void test_localization(const std::filesystem::path& temporary) {
    using scaping::Language;
    const auto originalLanguage = scaping::current_language();
    const auto file = temporary / L"language.ini";
    const std::string legacy = "[scaping]\nversion=1\nip=192.0.2.42\ninterval_ms=2345\ntimeout_ms=987\nslow_ms=321\nauto_start=1\nnmap_path=D:\\synthetic\\nmap.exe\nconcurrency=47\nconnections_per_second=91\n";
    write(file, legacy);
    auto loaded = scaping::load_config(file);
    require(loaded.valid && loaded.config.language == Language::Italian, "legacy config language migration");
    require(loaded.config.ip == L"192.0.2.42" && loaded.config.intervalMs == 2345 && loaded.config.timeoutMs == 987 && loaded.config.slowMs == 321 && loaded.config.autoStart && loaded.config.nmapPath == L"D:\\synthetic\\nmap.exe" && loaded.config.concurrency == 47 && loaded.config.connectionsPerSecond == 91, "legacy migration changed user settings");
    {
        std::ifstream unchanged(file, std::ios::binary);
        const std::string bytes((std::istreambuf_iterator<char>(unchanged)), std::istreambuf_iterator<char>());
        require(bytes == legacy, "reading a legacy configuration rewrote it");
    }
    std::wstring error;
    auto config = loaded.config;
    config.language = Language::English;
    require(scaping::save_config(file, config, error), "save English configuration");
    loaded = scaping::load_config(file);
    require(loaded.valid && loaded.config.language == Language::English && loaded.config.ip == config.ip && loaded.config.timeoutMs == config.timeoutMs, "English configuration roundtrip lost settings");
    std::ifstream saved(file, std::ios::binary);
    const std::string english((std::istreambuf_iterator<char>(saved)), std::istreambuf_iterator<char>());
    saved.close();
    require(english.find("version=2\r\n") != std::string::npos && english.find("language=en\r\n") != std::string::npos, "language schema is not versioned");
    for (const auto* language : {"fr", "EN", "", "en;anything", "en\r\nlanguage=it"}) {
        auto invalid = english;
        invalid.replace(invalid.find("language=en"), std::string("language=en").size(), std::string("language=") + language);
        write(file, invalid);
        require(!scaping::load_config(file).valid, "invalid language value accepted");
    }
    auto missing = english;
    missing.erase(missing.find("language=en\r\n"), std::string("language=en\r\n").size());
    write(file, missing);
    require(!scaping::load_config(file).valid, "v2 configuration without language accepted");
    write(file, legacy + "language=en\n");
    require(!scaping::load_config(file).valid, "v1 configuration accepted unexpected language field");
    config.language = static_cast<Language>(99);
    require(scaping::validate_config(config).has_value(), "invalid language enum accepted");
    for (auto language : {Language::Italian, Language::English}) {
        const scaping::ScopedLanguage scope(language);
        scaping::Config invalid;
        const auto message = scaping::validate_config(invalid);
        require(message && message->find(language == Language::English ? L"Enter a valid numeric IPv4" : L"Inserire un IPv4 numerico valido") != std::wstring::npos, "validation did not use selected language");
        const auto xmlError = scaping::parse_nmap_xml(temporary / L"missing.xml", scaping::Protocol::Udp);
        require(xmlError.diagnostic.find(language == Language::English ? L"XML missing" : L"XML assente") != std::wstring::npos, "XML diagnostic did not use selected language");
        invalid.language = language;
        require(scaping::save_config(file, invalid, error) && scaping::load_config(file).config.language == language, "language selection before entering an IP failed");
    }
    require(scaping::current_language() == originalLanguage, "language scope did not restore caller");
    std::array<std::wstring, 2> messages;
    std::thread italian([&] { const scaping::ScopedLanguage scope(Language::Italian); messages[0] = *scaping::validate_config(scaping::Config{}); });
    std::thread englishThread([&] { const scaping::ScopedLanguage scope(Language::English); messages[1] = *scaping::validate_config(scaping::Config{}); });
    italian.join(); englishThread.join();
    require(messages[0].find(L"Inserire") != std::wstring::npos && messages[1].find(L"Enter") != std::wstring::npos, "concurrent workers leaked language");
    require(scaping::current_language() == originalLanguage, "worker language changed the caller");
}
void test_text_and_arguments(const std::filesystem::path& temporary) {
    const std::wstring sample = L"Configurazione: unita \u00e8 \u00fc \u03a9 \U0001f600";
    require(scaping::from_utf8(scaping::to_utf8(sample)) == sample, "UTF-8 roundtrip");
    require(scaping::from_utf8(std::string("\xff", 1)).empty(), "invalid UTF-8 accepted");
    require(scaping::to_utf8(std::wstring(1, wchar_t(0xd800))).empty(), "invalid UTF-16 accepted");
    require(scaping::sanitize_text(L"one\x001b[2J\x202e two").find(L'\x001b') == std::wstring::npos, "ANSI escape not neutralized");
    require(scaping::sanitize_text(L"abc\r\ndef", 5).size() == 5, "text size limit");
    require(scaping::sanitize_text(L"\U0001f600", 1) == L"?", "surrogate limit creates invalid UTF16");
    for (const auto* argument : {L"", L"plain", L"D:\\synthetic space\\nmap.exe", L"quote\"inside", L"trailing\\", L"double\\\\\"quote", L"&whoami", L"$(never)", L"two\r\nlines"}) {
        std::wstring line = L"test.exe " + scaping::quote_argument(argument);
        int count = 0;
        auto parsed = CommandLineToArgvW(line.c_str(), &count);
        require(parsed && count == 2 && std::wstring(parsed[1]) == argument, "Windows argument quoting roundtrip");
        if (parsed) LocalFree(parsed);
    }
    const std::wstring withNull(L"x\0y", 3);
    require(scaping::quote_argument(withNull).empty(), "embedded NUL command arg accepted");
    for (const auto protocol : {scaping::Protocol::Tcp, scaping::Protocol::Udp}) {
        const auto args = scaping::nmap_arguments(protocol, L"192.0.2.1", temporary / L"synthetic results.xml");
        require(args.size() == 13, "profile unexpected argument count");
        require(args.front() == (protocol == scaping::Protocol::Tcp ? L"-sT" : L"-sU"), "wrong scan profile");
        require(std::find(args.begin(), args.end(), L"-p0-65535") != args.end(), "profile omits port 0");
        require(std::find(args.begin(), args.end(), L"-Pn") != args.end(), "profile depends on discovery");
        require(std::find(args.begin(), args.end(), L"--allports") == args.end(), "unsafe printer probing default");
        require(std::find(args.begin(), args.end(), L"-A") == args.end(), "unexpected aggressive profile");
    }
    require(scaping::nmap_arguments(scaping::Protocol::Tcp, L"-iL file", temporary / L"out.xml").empty(), "injection target accepted");
    require(scaping::nmap_arguments(scaping::Protocol::Tcp, L"192.0.2.1", L"relative.xml").empty(), "relative XML accepted");
    scaping::PortResult port; port.port = 65535; port.state = L"open|filtered"; port.service = L"synthetic\r\nFAKE";
    auto line = scaping::format_port(port);
    const bool english = scaping::current_language() == scaping::Language::English;
    require(line.find(L"open|filtered") != std::wstring::npos && line.find(english ? L"conventional port name" : L"nome convenzionale") != std::wstring::npos && line.find(english ? L"not available" : L"non disponibile") != std::wstring::npos, "format missing uncertainty or origin");
    require(line.find(L"\r\nFAKE") == std::wstring::npos, "field newline injection");
}
void test_xml(const std::filesystem::path& temporary) {
    const auto file = temporary / L"synthetic.xml";
    const std::string extremes = "<extraports state=\"closed\" count=\"65534\"><extrareasons reason=\"conn-refused\" count=\"65534\"/></extraports><port protocol=\"tcp\" portid=\"0\"><state state=\"open\" reason=\"syn-ack\"/><service name=\"synthetic\" product=\"Fixture server\" version=\"1.0\" extrainfo=\"generated\" method=\"probed\"/></port><port protocol=\"tcp\" portid=\"65535\"><state state=\"filtered\" reason=\"no-response\"/><service name=\"unknown\" method=\"table\"/></port>";
    write(file, nmap_xml("tcp", extremes));
    auto result = scaping::parse_nmap_xml(file, scaping::Protocol::Tcp);
    require(result.valid && result.finished && result.coverageComplete && result.serviceDetectionComplete && result.scannedPorts == 65536 && result.ports.size() == 2, "full XML coverage with aggregates failed");
    require(result.ports.front().port == 0 && result.ports.back().port == 65535, "port boundary parsing");
    require(result.ports.front().serviceFromResponse && !result.ports.back().serviceFromResponse, "service method distinction");
    require(result.ports.front().banner.empty(), "invented banner from product");
    require(scaping::parse_nmap_xml(file, scaping::Protocol::Tcp, L"192.0.2.1").coverageComplete, "expected target not accepted");
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp, L"192.0.2.2").valid, "mismatched XML target accepted");
    auto missingAddress = nmap_xml("tcp", extremes);
    const auto addressPosition = missingAddress.find("<address ");
    const auto addressEnd = missingAddress.find("/>", addressPosition);
    missingAddress.erase(addressPosition, addressEnd + 2 - addressPosition);
    write(file, missingAddress);
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp, L"192.0.2.1").valid, "missing XML target accepted");
    write(file, nmap_xml("udp", "<extraports state=\"open|filtered\" count=\"65536\"/>"));
    result = scaping::parse_nmap_xml(file, scaping::Protocol::Udp);
    require(result.valid && result.coverageComplete && result.summary.find(L"open|filtered") != std::wstring::npos, "UDP aggregate uncertainty lost");
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "cross-protocol XML accepted");
    write(file, nmap_xml("tcp", "<extraports state=\"closed\" count=\"65535\"/>", "1-65535", "65535"));
    result = scaping::parse_nmap_xml(file, scaping::Protocol::Tcp);
    require(result.valid && !result.coverageComplete && result.scannedPorts == 65535, "missing port zero marked complete");
    write(file, nmap_xml("tcp", extremes, "0-65535", "65536", "error"));
    result = scaping::parse_nmap_xml(file, scaping::Protocol::Tcp);
    require(result.valid && !result.finished && !result.coverageComplete && !result.serviceDetectionComplete, "error finish marked complete");
    write(file, nmap_xml("tcp", extremes, "0-65535", "65536", "success", false));
    result = scaping::parse_nmap_xml(file, scaping::Protocol::Tcp);
    require(result.coverageComplete && !result.serviceDetectionComplete, "service detection invented");
    auto quotedFlag = nmap_xml("tcp", extremes, "0-65535", "65536", "success", false);
    const auto argumentsPosition = quotedFlag.find("nmap -n -p0-65535");
    quotedFlag.replace(argumentsPosition, std::string("nmap -n -p0-65535").size(), "nmap -n -oX &quot;synthetic -sV result.xml&quot; -p0-65535");
    write(file, quotedFlag);
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).serviceDetectionComplete, "service flag inferred from quoted filename");
    for (const auto* range : {"0-65534", "1-65535", "0-65535,65535", "0-65536", "0-65535,", "65535-0", "-1-65535", "0-65535,0"}) {
        write(file, nmap_xml("tcp", extremes, range));
        require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).coverageComplete, "bad coverage range complete");
    }
    write(file, nmap_xml("tcp", "<extraports state=\"closed\" count=\"65536\"/><port protocol=\"tcp\" portid=\"0\"><state state=\"open\"/></port>"));
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "aggregate overflow accepted");
    for (const auto* port : {"65536", "-1", "4294967296", "abc"}) {
        write(file, nmap_xml("tcp", std::string("<port protocol=\"tcp\" portid=\"") + port + "\"><state state=\"open\"/></port>"));
        require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "invalid port accepted");
    }
    write(file, nmap_xml("tcp", "<port protocol=\"tcp\" portid=\"0\"><state state=\"open\"/></port><port protocol=\"tcp\" portid=\"0\"><state state=\"closed\"/></port>"));
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "duplicate port accepted");
    write(file, nmap_xml("tcp", "<port protocol=\"tcp\" portid=\"0\"><state state=\"maybe\"/></port>"));
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "unknown state accepted");
    auto incomplete = nmap_xml("tcp", extremes); incomplete.resize(incomplete.size() - 25); write(file, incomplete);
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "incomplete XML accepted");
    write(file, "<nmaprun scanner=\"nmap\"><broken></nmaprun>");
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "malformed XML accepted");
    for (const auto* dtd : {"<!DOCTYPE nmaprun SYSTEM \"https://example.invalid/never.dtd\">", "<!DOCTYPE nmaprun [<!ENTITY external SYSTEM \"file:///D:/synthetic/secret.txt\">]>", "<!DOCTYPE nmaprun [<!ENTITY a \"expanded\">]>", "<!DOCTYPE nmaprun PUBLIC \"synthetic\" \"https://example.invalid/never.dtd\">"}) {
        auto xml = nmap_xml("tcp", extremes); auto pos = xml.find("<!DOCTYPE nmaprun>"); xml.replace(pos, std::string("<!DOCTYPE nmaprun>").size(), dtd); write(file, xml);
        require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "DTD/XXE accepted");
    }
    std::string deep = "<nmaprun scanner=\"nmap\">"; for (int i = 0; i < 70; ++i) deep += "<a>"; for (int i = 0; i < 70; ++i) deep += "</a>"; deep += "</nmaprun>"; write(file, deep);
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "deep XML accepted");
    std::filesystem::resize_file(file, 64ull * 1024 * 1024 + 1);
    require(!scaping::parse_nmap_xml(file, scaping::Protocol::Tcp).valid, "oversized XML accepted");
    std::ostringstream everyPort;
    for (std::uint32_t port = 0; port < scaping::kPortCount; ++port) everyPort << "<port protocol=\"tcp\" portid=\"" << port << "\"><state state=\"closed\"/></port>";
    write(file, nmap_xml("tcp", everyPort.str()));
    result = scaping::parse_nmap_xml(file, scaping::Protocol::Tcp);
    require(result.valid && result.coverageComplete && result.ports.size() == 65536, "full explicit ports loop overflow or skipped port");
    for (std::uint32_t port = 0; port < scaping::kPortCount; ++port) require(result.ports[port].port == port, "explicit port gap");
}
}

int wmain(int argc, wchar_t** argv) {
    if (argc == 2 && std::wstring_view(argv[1]) == L"--language=en") scaping::set_language(scaping::Language::English);
    else if (argc != 1) return 2;
    wchar_t base[MAX_PATH]{};
    if (!GetTempPathW(MAX_PATH, base)) return 2;
    const auto temporary = std::filesystem::path(base) / (L"scaping-synthetic-tests-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()));
    bool ownedDirectory = false;
    try {
        ownedDirectory = std::filesystem::create_directory(temporary);
        require(ownedDirectory, "unique test directory creation");
        test_ipv4(); test_colors(); test_config(temporary); test_localization(temporary); test_text_and_arguments(temporary); test_xml(temporary);
        std::cout << "Core checks passed: " << checks << "\n";
        std::filesystem::remove_all(temporary);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "TEST FAILURE after " << checks << " checks: " << error.what() << "\n";
        std::error_code ec; if (ownedDirectory) std::filesystem::remove_all(temporary, ec);
        return 1;
    }
}
