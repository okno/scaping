#include "scaping/network.hpp"
#include "scaping/ui.hpp"
#include "scaping/language.hpp"
#include <shellapi.h>
#include <commctrl.h>
#include <memory>

namespace {
struct ArgumentsDeleter {
    void operator()(wchar_t** value) const noexcept { if (value) LocalFree(value); }
};
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
    int argc = 0;
    std::unique_ptr<wchar_t*, ArgumentsDeleter> argv(CommandLineToArgvW(GetCommandLineW(), &argc));
    if (!argv) return 1;
    // The elevated process only accepts the fixed, validated worker protocol.
    const int workerResult = scaping::worker_entry(argc, argv.get());
    if (workerResult != -1) return workerResult;
    bool languageKnown = false;
    try {
        const auto loaded = scaping::load_config(std::filesystem::path(scaping::kRoot) / L"data" / L"config.ini");
        if (loaded.existed && loaded.valid) {
            scaping::set_language(loaded.config.language);
            languageKnown = true;
        }
    } catch (...) {
        // A missing drive or unreadable configuration must still produce an understandable error.
    }
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&controls);
    if (!SetCurrentDirectoryW(scaping::kRoot)) {
        MessageBoxW(nullptr, languageKnown ? scaping::tr(
            L"Impossibile aprire D:\\scaping. Verifica che il disco D: e la cartella del progetto siano disponibili.",
            L"Unable to open D:\\scaping. Check that drive D: and the project folder are available.") :
            L"Impossibile aprire D:\\scaping. Verifica il disco e la cartella.\r\n\r\n"
            L"Unable to open D:\\scaping. Check that the drive and folder are available.",
            L"Scaping", MB_OK | MB_ICONERROR);
        return 1;
    }
    try { return scaping::run_gui(instance); }
    catch (...) {
        MessageBoxW(nullptr, scaping::tr(L"Scaping non è riuscito ad avviarsi. Risorse di sistema insufficienti o errore inatteso.",
            L"Scaping could not start. Insufficient system resources or an unexpected error occurred."),
            L"Scaping", MB_OK | MB_ICONERROR);
        return 1;
    }
}
