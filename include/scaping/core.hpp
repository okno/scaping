#pragma once
#include "scaping/language.hpp"
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace scaping {
inline constexpr wchar_t kRoot[] = L"D:\\scaping";
inline constexpr std::uint32_t kPortCount = 65536;
struct Config {
    std::wstring ip;
    std::uint32_t intervalMs = 1000;
    std::uint32_t timeoutMs = 800;
    std::uint32_t slowMs = 150;
    bool autoStart = false;
    std::wstring nmapPath;
    std::uint32_t concurrency = 64;
    std::uint32_t connectionsPerSecond = 128;
    Language language = Language::Italian;
};
bool valid_ipv4(std::wstring_view ip);
std::optional<std::wstring> validate_config(const Config& config, bool allowEmptyIp = false);
struct ConfigLoad { Config config; bool existed = false; bool valid = true; std::wstring diagnostic; };
ConfigLoad load_config(const std::filesystem::path& file);
bool save_config(const std::filesystem::path& file, const Config& config, std::wstring& error);
enum class PingColor { Gray, Green, Orange, Red };
struct PingResult {
    std::uint64_t generation = 0;
    bool success = false;
    std::uint32_t rttMs = 0;
    std::uint32_t errorCode = 0;
    std::wstring error;
};
PingColor ping_color(const PingResult& result, std::uint32_t slowMs);
bool accept_ping_generation(std::uint64_t active, const PingResult& result);
std::wstring sanitize_text(std::wstring_view input, std::size_t limit = 65536);
std::wstring from_utf8(std::string_view input);
std::string to_utf8(std::wstring_view input);
std::wstring quote_argument(std::wstring_view arg);
enum class Protocol { Tcp, Udp };
std::vector<std::wstring> nmap_arguments(Protocol protocol, std::wstring_view ip, const std::filesystem::path& xmlFile);
struct PortResult {
    Protocol protocol = Protocol::Tcp;
    std::uint32_t port = 0;
    std::wstring state, service, product, version, extra, banner, reason;
    bool serviceFromResponse = false;
};
struct NmapResult {
    bool valid = false;
    bool finished = false;
    bool coverageComplete = false;
    bool serviceDetectionComplete = false;
    std::uint32_t scannedPorts = 0;
    std::wstring diagnostic;
    std::vector<PortResult> ports;
    std::wstring summary;
};
NmapResult parse_nmap_xml(const std::filesystem::path& file, Protocol expected, std::wstring_view expectedIp = {});
std::wstring format_port(const PortResult& result);
}
