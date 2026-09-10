#include "scaping/network.hpp"
#include "scaping/ui.hpp"
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
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    INITCOMMONCONTROLSEX controls{sizeof(controls), ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS};
    InitCommonControlsEx(&controls);
    if (!SetCurrentDirectoryW(scaping::kRoot)) {
        MessageBoxW(nullptr,
            L"Impossibile aprire D:\\scaping. Verifica che il disco D: e la cartella del progetto siano disponibili.",
            L"Scaping — cartella non disponibile", MB_OK | MB_ICONERROR);
        return 1;
    }
    try { return scaping::run_gui(instance); }
    catch (...) {
        MessageBoxW(nullptr, L"Scaping non è riuscito ad avviarsi. Risorse di sistema insufficienti o errore inatteso.",
            L"Scaping", MB_OK | MB_ICONERROR);
        return 1;
    }
}
