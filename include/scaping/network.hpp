#pragma once
#include "scaping/core.hpp"
#include <functional>
#include <memory>

namespace scaping {
using OutputCallback = std::function<void(std::wstring)>;
using PingCallback = std::function<void(PingResult)>;
struct NmapInfo {
    bool available = false;
    bool npcapAvailable = false;
    bool elevated = false;
    std::wstring path, version, diagnostic;
};
NmapInfo detect_nmap(std::wstring_view configuredPath = {});
class PingMonitor {
public:
    PingMonitor();
    ~PingMonitor();
    PingMonitor(const PingMonitor&) = delete;
    PingMonitor& operator=(const PingMonitor&) = delete;
    void start(const Config& config, std::uint64_t generation, PingCallback callback);
    void stop();
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
struct ScanCompletion {
    bool complete = false;
    bool cancelled = false;
    bool tcpComplete = false;
    bool udpComplete = false;
    std::wstring summary;
    std::filesystem::path reportPath;
};
using CompletionCallback = std::function<void(ScanCompletion)>;
class ScanSession {
public:
    ScanSession();
    ~ScanSession();
    ScanSession(const ScanSession&) = delete;
    ScanSession& operator=(const ScanSession&) = delete;
    bool start(const Config& snapshot, OutputCallback output, CompletionCallback complete);
    void cancel();
    bool running() const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
// Returns -1 for the ordinary GUI command line; otherwise handles only the fixed worker protocol.
int worker_entry(int argc, wchar_t** argv);
}
