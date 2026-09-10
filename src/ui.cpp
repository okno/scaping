#include "scaping/ui.hpp"
#include "scaping/core.hpp"
#include "scaping/language.hpp"
#include "scaping/network.hpp"
#include <windowsx.h>
#include <shellapi.h>
#include <commdlg.h>
#include <commctrl.h>
#include <sddl.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <cwchar>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace scaping {
namespace {
constexpr wchar_t kResidentClass[] = L"Scaping.Resident.v1";
constexpr wchar_t kConfigClass[] = L"Scaping.Configuration.v1";
constexpr wchar_t kResultsClass[] = L"Scaping.Results.v1";
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kMailboxMessage = WM_APP + 2;
constexpr UINT_PTR kBatchTimer = 1;
constexpr UINT_PTR kTrayRetryTimer = 2;
constexpr std::size_t kVisibleLimit = 256 * 1024;
constexpr std::size_t kPendingLimit = 256 * 1024;
constexpr int kExit = 101, kConfigure = 102, kScan = 103;
constexpr int kIp = 201, kInterval = 202, kTimeout = 203, kSlow = 204;
constexpr int kAutostart = 205, kNmap = 206, kBrowse = 207;
constexpr int kConcurrency = 208, kRate = 209, kApply = 210, kDismiss = 211;
constexpr int kConfigStatus = 212, kLanguage = 213;
constexpr int kOutput = 301, kCancelScan = 302, kCopy = 303, kSave = 304;
constexpr int kHideResults = 305, kTarget = 306, kScanStatus = 307, kProgress = 308;

template<class T, auto Close>
class Owned {
public:
    Owned() = default;
    explicit Owned(T value) : value_(value) {}
    ~Owned() { reset(); }
    Owned(const Owned&) = delete;
    Owned& operator=(const Owned&) = delete;
    Owned(Owned&& other) noexcept : value_(other.release()) {}
    Owned& operator=(Owned&& other) noexcept { reset(other.release()); return *this; }
    T get() const noexcept { return value_; }
    T release() noexcept { T result = value_; value_ = nullptr; return result; }
    void reset(T value = nullptr) noexcept { if (value_) Close(value_); value_ = value; }
    explicit operator bool() const noexcept { return value_ != nullptr; }
private:
    T value_ = nullptr;
};
using OwnedHandle = Owned<HANDLE, CloseHandle>;
using OwnedIcon = Owned<HICON, DestroyIcon>;
using OwnedGdi = Owned<HGDIOBJ, DeleteObject>;
using OwnedMenu = Owned<HMENU, DestroyMenu>;
using OwnedKey = Owned<HKEY, RegCloseKey>;

int scale(int value, UINT dpi) { return MulDiv(value, static_cast<int>(dpi), 96); }

std::wstring window_text(HWND control) {
    const int length = GetWindowTextLengthW(control);
    if (length <= 0) return {};
    std::wstring text(static_cast<std::size_t>(length) + 1, L'\0');
    const int copied = GetWindowTextW(control, text.data(), length + 1);
    text.resize(static_cast<std::size_t>((std::max)(0, copied)));
    return text;
}

void foreground(HWND window) {
    if (!window) return;
    ShowWindow(window, IsIconic(window) ? SW_RESTORE : SW_SHOW);
    SetForegroundWindow(window);
    BringWindowToTop(window);
}

OwnedIcon square_icon(COLORREF color, int size) {
    BITMAPV5HEADER header{};
    header.bV5Size = sizeof(header);
    header.bV5Width = size;
    header.bV5Height = -size;
    header.bV5Planes = 1;
    header.bV5BitCount = 32;
    header.bV5Compression = BI_BITFIELDS;
    header.bV5RedMask = 0x00FF0000;
    header.bV5GreenMask = 0x0000FF00;
    header.bV5BlueMask = 0x000000FF;
    header.bV5AlphaMask = 0xFF000000;
    void* pixels = nullptr;
    OwnedGdi bitmap(CreateDIBSection(nullptr, reinterpret_cast<BITMAPINFO*>(&header), DIB_RGB_COLORS, &pixels, nullptr, 0));
    if (!bitmap || !pixels) return {};
    const DWORD pixel = 0xFF000000u | (static_cast<DWORD>(GetRValue(color)) << 16) |
        (static_cast<DWORD>(GetGValue(color)) << 8) | GetBValue(color);
    std::fill_n(static_cast<DWORD*>(pixels), static_cast<std::size_t>(size) * size, pixel);
    const std::size_t maskStride = ((static_cast<std::size_t>(size) + 15) / 16) * 2;
    std::vector<BYTE> maskBits(maskStride * size, 0);
    OwnedGdi mask(CreateBitmap(size, size, 1, 1, maskBits.data()));
    if (!mask) return {};
    ICONINFO info{};
    info.fIcon = TRUE;
    info.hbmMask = static_cast<HBITMAP>(mask.get());
    info.hbmColor = static_cast<HBITMAP>(bitmap.get());
    return OwnedIcon(CreateIconIndirect(&info));
}

std::wstring user_mutex_name() {
    HANDLE rawToken = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) throw std::runtime_error("token");
    OwnedHandle token(rawToken);
    DWORD bytes = 0;
    GetTokenInformation(token.get(), TokenUser, nullptr, 0, &bytes);
    if (!bytes || bytes > 64 * 1024) throw std::runtime_error("token size");
    std::vector<BYTE> buffer(bytes);
    if (!GetTokenInformation(token.get(), TokenUser, buffer.data(), bytes, &bytes)) throw std::runtime_error("token user");
    LPWSTR rawSid = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(buffer.data())->User.Sid, &rawSid)) throw std::runtime_error("sid");
    std::wstring name;
    try { name = L"Local\\Scaping.Resident.v1." + std::wstring(rawSid); }
    catch (...) { LocalFree(rawSid); throw; }
    LocalFree(rawSid);
    return name;
}

struct Mailbox {
    std::mutex mutex;
    bool alive = true;
    HWND window = nullptr;
    std::optional<PingResult> ping;
    std::wstring output;
    bool outputDropped = false;
    std::optional<ScanCompletion> completion;
};

struct ConfigPosition { int id, x, y, width, height; };
constexpr ConfigPosition kConfigPositions[] = {
    {400,16,16,470,20}, {kIp,16,39,474,27},
    {401,16,82,150,20}, {402,178,82,150,20}, {403,340,82,150,20},
    {kInterval,16,105,150,27}, {kTimeout,178,105,150,27}, {kSlow,340,105,150,27},
    {kAutostart,16,150,474,24},
    {404,16,191,474,20}, {kNmap,16,214,377,27}, {kBrowse,405,214,85,27},
    {405,16,246,474,40},
    {406,16,294,474,105}, {407,30,319,214,20}, {408,261,319,215,20},
    {kConcurrency,30,344,214,27}, {kRate,261,344,215,27},
    {kConfigStatus,16,412,474,46}, {409,16,481,120,20}, {kLanguage,142,477,128,120},
    {kApply,282,475,99,31}, {kDismiss,392,475,98,31}
};

enum class FinalState { None, FailedToStart, Complete, Cancelled, Partial };

class Application {
public:
    explicit Application(HINSTANCE instance) : instance_(instance), mailbox_(std::make_shared<Mailbox>()) {}
    ~Application() { shutdown(); }
    bool initialize();
    int loop();
private:
    HINSTANCE instance_ = nullptr;
    HWND resident_ = nullptr, configuration_ = nullptr, results_ = nullptr;
    UINT taskbarCreated_ = 0, activate_ = 0;
    OwnedHandle instanceMutex_;
    std::wstring residentTitle_;
    std::array<OwnedIcon, 4> icons_;
    OwnedGdi configFont_, resultsFont_, monoFont_;
    Config config_;
    std::wstring configDiagnostic_;
    PingColor color_ = PingColor::Gray;
    std::optional<PingResult> lastPing_;
    std::optional<std::uint32_t> lastRtt_;
    std::uint64_t generation_ = 0;
    bool suspended_ = false, shuttingDown_ = false, trayAdded_ = false, trayVersion4_ = false, secondInstance_ = false;
    std::shared_ptr<Mailbox> mailbox_;
    PingMonitor ping_;
    ScanSession scan_;
    bool scanning_ = false, cancellationRequested_ = false;
    std::wstring scanTarget_;
    Language scanLanguage_ = Language::Italian;
    FinalState finalState_ = FinalState::None;
    std::filesystem::path reportPath_;
    std::chrono::steady_clock::time_point scanStart_;
    std::chrono::seconds finalElapsed_{0};

    static LRESULT CALLBACK resident_proc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK config_proc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK results_proc(HWND, UINT, WPARAM, LPARAM);
    static Application* context(HWND, UINT, LPARAM);
    bool register_class(const wchar_t*, WNDPROC, HBRUSH);
    HWND child(HWND, const wchar_t*, const wchar_t*, DWORD, int, DWORD = 0);
    void create_config_controls();
    void create_result_controls();
    void size_config();
    void size_results();
    void set_fonts(HWND, bool);
    void refresh_language();
    std::wstring final_status() const;
    void show_configuration();
    void fill_configuration();
    void apply_configuration();
    void browse_nmap();
    void configuration_error(const std::wstring&, int = kIp);
    bool set_autostart_and_save(const Config&, std::wstring&);
    void show_results();
    void start_scan();
    void cancel_scan();
    void save_report();
    void copy_output();
    void append_output(std::wstring);
    void flush_mailbox();
    void update_scan_status();
    void restart_ping();
    void update_tray(bool = false);
    void tray_menu(POINT);
    void shutdown();
};

Application* Application::context(HWND window, UINT message, LPARAM param) {
    if (message == WM_NCCREATE) {
        auto create = reinterpret_cast<CREATESTRUCTW*>(param);
        SetWindowLongPtrW(window, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(create->lpCreateParams));
    }
    return reinterpret_cast<Application*>(GetWindowLongPtrW(window, GWLP_USERDATA));
}

bool Application::register_class(const wchar_t* name, WNDPROC procedure, HBRUSH brush) {
    WNDCLASSEXW type{sizeof(type)};
    type.style = CS_DBLCLKS;
    type.lpfnWndProc = procedure;
    type.hInstance = instance_;
    type.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    type.hbrBackground = brush;
    type.lpszClassName = name;
    type.hIcon = icons_[0].get();
    type.hIconSm = icons_[0].get();
    return RegisterClassExW(&type) != 0 || GetLastError() == ERROR_CLASS_ALREADY_EXISTS;
}

bool Application::initialize() {
    auto loaded = load_config(std::filesystem::path(kRoot) / L"data" / L"config.ini");
    config_ = loaded.config;
    set_language(config_.language);
    configDiagnostic_ = loaded.diagnostic;
    activate_ = RegisterWindowMessageW(L"Scaping.Activate.v1");
    taskbarCreated_ = RegisterWindowMessageW(L"TaskbarCreated");
    if (!activate_ || !taskbarCreated_) return false;
    const auto mutexName = user_mutex_name();
    residentTitle_ = mutexName;
    instanceMutex_.reset(CreateMutexW(nullptr, FALSE, mutexName.c_str()));
    const DWORD mutexError = GetLastError();
    if (!instanceMutex_) return false;
    if (mutexError == ERROR_ALREADY_EXISTS) {
        secondInstance_ = true;
        // Allow the first process time to create its hidden window if both starts raced.
        for (int attempt = 0; attempt < 60; ++attempt) {
            HWND previous = FindWindowW(kResidentClass, residentTitle_.c_str());
            if (previous) {
                DWORD process = 0;
                GetWindowThreadProcessId(previous, &process);
                if (process) AllowSetForegroundWindow(process);
                PostMessageW(previous, activate_, 0, 0);
                return true;
            }
            Sleep(50);
        }
        MessageBoxW(nullptr, tr(L"Scaping è già in esecuzione nella sessione. L'icona sarà disponibile nella system tray.", L"Scaping is already running in this session. Its icon is available in the system tray."), L"Scaping", MB_OK | MB_ICONINFORMATION);
        return true;
    }
    const int iconSize = (std::max)(16, GetSystemMetrics(SM_CXSMICON));
    constexpr COLORREF colors[]{RGB(128,128,128), RGB(30,174,72), RGB(242,147,32), RGB(215,49,49)};
    for (std::size_t i = 0; i < icons_.size(); ++i) {
        icons_[i] = square_icon(colors[i], iconSize);
        if (!icons_[i]) return false;
    }
    if (!register_class(kResidentClass, resident_proc, nullptr) ||
        !register_class(kConfigClass, config_proc, reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1)) ||
        !register_class(kResultsClass, results_proc, reinterpret_cast<HBRUSH>(COLOR_BTNFACE + 1))) return false;
    resident_ = CreateWindowExW(WS_EX_TOOLWINDOW, kResidentClass, residentTitle_.c_str(), WS_OVERLAPPED,
        0, 0, 0, 0, nullptr, nullptr, instance_, this);
    if (!resident_) return false;
    {
        std::lock_guard lock(mailbox_->mutex);
        mailbox_->window = resident_;
    }
    update_tray(true);
    restart_ping();
    return true;
}

int Application::loop() {
    if (secondInstance_) return 0;
    MSG message{};
    BOOL result = 0;
    while ((result = GetMessageW(&message, nullptr, 0, 0)) > 0) {
        if (configuration_ && IsWindowVisible(configuration_) && IsDialogMessageW(configuration_, &message)) continue;
        if (results_ && IsWindowVisible(results_) && IsDialogMessageW(results_, &message)) continue;
        TranslateMessage(&message);
        DispatchMessageW(&message);
    }
    return result == -1 ? 1 : static_cast<int>(message.wParam);
}

HWND Application::child(HWND parent, const wchar_t* type, const wchar_t* text, DWORD style, int id, DWORD extended) {
    HWND control = CreateWindowExW(extended, type, text, WS_CHILD | WS_VISIBLE | style,
        0, 0, 1, 1, parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)), instance_, nullptr);
    if (!control) throw std::runtime_error("control creation");
    return control;
}

void Application::set_fonts(HWND window, bool resultWindow) {
    const UINT dpi = GetDpiForWindow(window);
    OwnedGdi font(CreateFontW(-MulDiv(10, static_cast<int>(dpi), 72), 0, 0, 0, FW_NORMAL,
        FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI"));
    if (!font) return;
    EnumChildWindows(window, [](HWND control, LPARAM value) -> BOOL {
        SendMessageW(control, WM_SETFONT, static_cast<WPARAM>(value), TRUE);
        return TRUE;
    }, reinterpret_cast<LPARAM>(font.get()));
    if (resultWindow) {
        resultsFont_ = std::move(font);
        OwnedGdi mono(CreateFontW(-MulDiv(10, static_cast<int>(dpi), 72), 0, 0, 0, FW_NORMAL,
            FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas"));
        if (mono) {
            SendDlgItemMessageW(window, kOutput, WM_SETFONT, reinterpret_cast<WPARAM>(mono.get()), TRUE);
            monoFont_ = std::move(mono);
        }
    } else configFont_ = std::move(font);
}

void Application::create_config_controls() {
    child(configuration_, L"STATIC", L"", 0, 400);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, kIp, WS_EX_CLIENTEDGE);
    // Each static label directly precedes its field in the native accessibility order.
    child(configuration_, L"STATIC", L"", 0, 401);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, kInterval, WS_EX_CLIENTEDGE);
    child(configuration_, L"STATIC", L"", 0, 402);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, kTimeout, WS_EX_CLIENTEDGE);
    child(configuration_, L"STATIC", L"", 0, 403);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, kSlow, WS_EX_CLIENTEDGE);
    child(configuration_, L"BUTTON", L"", WS_TABSTOP | BS_AUTOCHECKBOX, kAutostart);
    child(configuration_, L"STATIC", L"", 0, 404);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_AUTOHSCROLL, kNmap, WS_EX_CLIENTEDGE);
    child(configuration_, L"BUTTON", L"", WS_TABSTOP | BS_PUSHBUTTON, kBrowse);
    child(configuration_, L"STATIC", L"", 0, 405);
    child(configuration_, L"BUTTON", L"", BS_GROUPBOX, 406);
    child(configuration_, L"STATIC", L"", 0, 407);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, kConcurrency, WS_EX_CLIENTEDGE);
    child(configuration_, L"STATIC", L"", 0, 408);
    child(configuration_, L"EDIT", L"", WS_TABSTOP | ES_NUMBER | ES_AUTOHSCROLL, kRate, WS_EX_CLIENTEDGE);
    child(configuration_, L"STATIC", L"", 0, kConfigStatus);
    child(configuration_, L"STATIC", L"Lingua / Language", 0, 409);
    HWND language = child(configuration_, L"COMBOBOX", L"", WS_TABSTOP | WS_VSCROLL | CBS_DROPDOWNLIST | CBS_HASSTRINGS, kLanguage);
    SendMessageW(language, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Italiano"));
    SendMessageW(language, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"English"));
    child(configuration_, L"BUTTON", L"", WS_TABSTOP | BS_DEFPUSHBUTTON, kApply);
    child(configuration_, L"BUTTON", L"", WS_TABSTOP | BS_PUSHBUTTON, kDismiss);
    SendDlgItemMessageW(configuration_, kIp, EM_SETLIMITTEXT, 15, 0);
    SendDlgItemMessageW(configuration_, kNmap, EM_SETLIMITTEXT, 32700, 0);
    for (int id : {kInterval, kTimeout, kSlow, kConcurrency, kRate}) SendDlgItemMessageW(configuration_, id, EM_SETLIMITTEXT, 8, 0);
    set_fonts(configuration_, false);
    refresh_language();
    size_config();
}

void Application::refresh_language() {
    if (configuration_) {
        SetWindowTextW(configuration_, tr(L"Scaping — Configura IP", L"Scaping — Configure IP"));
        const std::pair<int, const wchar_t*> labels[]{
            {400, tr(L"IP da monitorare — IPv4 numerico", L"IP to monitor — numeric IPv4")},
            {401, tr(L"Intervallo ping (ms)", L"Ping interval (ms)")},
            {402, tr(L"Timeout (ms)", L"Timeout (ms)")},
            {403, tr(L"Soglia ping lento (ms)", L"Slow ping threshold (ms)")},
            {kAutostart, tr(L"Avvio con Windows (solo utente corrente)", L"Start with Windows (current user only)")},
            {404, tr(L"Percorso Nmap (facoltativo)", L"Nmap path (optional)")},
            {kBrowse, tr(L"Sfoglia…", L"Browse…")},
            {405, tr(L"Campo vuoto: rilevamento automatico durante la scansione.\r\nSenza Nmap: Solo TCP — modalità ridotta.",
                L"Leave blank to detect Nmap automatically when scanning.\r\nWithout Nmap: TCP only — reduced mode.")},
            {406, tr(L"Limiti avanzati del fallback TCP", L"Advanced TCP fallback limits")},
            {407, tr(L"Connessioni contemporanee", L"Concurrent connections")},
            {408, tr(L"Nuove connessioni al secondo", L"New connections per second")},
            {kApply, tr(L"Applica", L"Apply")},
            {kDismiss, tr(L"Chiudi", L"Close")}
        };
        for (const auto& [id, text] : labels) SetDlgItemTextW(configuration_, id, text);
        if (configDiagnostic_.empty()) SetDlgItemTextW(configuration_, kConfigStatus,
            tr(L"La soglia deve essere inferiore al timeout. La scansione usa un'istantanea dell'IP e parte solo dal menu tray.",
               L"The threshold must be below the timeout. Scans use a snapshot of the IP and start only from the tray menu."));
    }
    if (results_) {
        SetWindowTextW(results_, tr(L"Scaping — Risultati", L"Scaping — Results"));
        SetDlgItemTextW(results_, kCancelScan, tr(L"Annulla scansione", L"Cancel scan"));
        SetDlgItemTextW(results_, kCopy, tr(L"Copia", L"Copy"));
        SetDlgItemTextW(results_, kSave, tr(L"Salva report", L"Save report"));
        SetDlgItemTextW(results_, kHideResults, tr(L"Chiudi finestra", L"Close window"));
        SetDlgItemTextW(results_, kTarget, (L"Target: " + scanTarget_ +
            tr(L"  |  Porte 0–65535 TCP e UDP richieste", L"  |  TCP and UDP ports 0–65535 requested")).c_str());
        update_scan_status();
    }
    update_tray();
}

std::wstring Application::final_status() const {
    switch (finalState_) {
    case FinalState::FailedToStart: return tr(L"Parziale — impossibile avviare il worker di scansione.", L"Partial — unable to start the scan worker.");
    case FinalState::Complete: return tr(L"Completata — TCP e UDP", L"Completed — TCP and UDP");
    case FinalState::Cancelled: return tr(L"Parziale — scansione annullata", L"Partial — scan cancelled");
    case FinalState::Partial: return tr(L"Parziale", L"Partial");
    default: return tr(L"Nessuna scansione avviata", L"No scan started");
    }
}

void Application::size_config() {
    if (!configuration_) return;
    const UINT dpi = GetDpiForWindow(configuration_);
    HDWP positions = BeginDeferWindowPos(static_cast<int>(std::size(kConfigPositions)));
    for (const auto& p : kConfigPositions) {
        if (!positions) break;
        positions = DeferWindowPos(positions, GetDlgItem(configuration_, p.id), nullptr,
            scale(p.x, dpi), scale(p.y, dpi), scale(p.width, dpi), scale(p.height, dpi), SWP_NOZORDER | SWP_NOACTIVATE);
    }
    if (positions) EndDeferWindowPos(positions);
}

void Application::show_configuration() {
    if (!configuration_) {
        const UINT dpi = GetDpiForSystem();
        RECT bounds{0,0,scale(506,dpi),scale(522,dpi)};
        constexpr DWORD style = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
        AdjustWindowRectExForDpi(&bounds, style, FALSE, WS_EX_APPWINDOW, dpi);
        configuration_ = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_CONTROLPARENT, kConfigClass, tr(L"Scaping — Configura IP", L"Scaping — Configure IP"),
            style, CW_USEDEFAULT, CW_USEDEFAULT, bounds.right - bounds.left, bounds.bottom - bounds.top,
            resident_, nullptr, instance_, this);
        if (!configuration_) {
            MessageBoxW(resident_, tr(L"Impossibile aprire la configurazione.", L"Unable to open configuration."), L"Scaping", MB_OK | MB_ICONERROR);
            return;
        }
    }
    fill_configuration();
    foreground(configuration_);
    SetFocus(GetDlgItem(configuration_, kIp));
}

void Application::fill_configuration() {
    SetDlgItemTextW(configuration_, kIp, config_.ip.c_str());
    SetDlgItemTextW(configuration_, kInterval, std::to_wstring(config_.intervalMs).c_str());
    SetDlgItemTextW(configuration_, kTimeout, std::to_wstring(config_.timeoutMs).c_str());
    SetDlgItemTextW(configuration_, kSlow, std::to_wstring(config_.slowMs).c_str());
    CheckDlgButton(configuration_, kAutostart, config_.autoStart ? BST_CHECKED : BST_UNCHECKED);
    SetDlgItemTextW(configuration_, kNmap, config_.nmapPath.c_str());
    SetDlgItemTextW(configuration_, kConcurrency, std::to_wstring(config_.concurrency).c_str());
    SetDlgItemTextW(configuration_, kRate, std::to_wstring(config_.connectionsPerSecond).c_str());
    SendDlgItemMessageW(configuration_, kLanguage, CB_SETCURSEL, config_.language == Language::English ? 1 : 0, 0);
    const auto note = configDiagnostic_.empty() ?
        tr(L"La soglia deve essere inferiore al timeout. La scansione usa un'istantanea dell'IP e parte solo dal menu tray.",
           L"The threshold must be below the timeout. Scans use a snapshot of the IP and start only from the tray menu.") : configDiagnostic_.c_str();
    SetDlgItemTextW(configuration_, kConfigStatus, note);
}

void Application::configuration_error(const std::wstring& message, int control) {
    SetDlgItemTextW(configuration_, kConfigStatus, message.c_str());
    MessageBoxW(configuration_, message.c_str(), tr(L"Scaping — configurazione non valida", L"Scaping — invalid configuration"), MB_OK | MB_ICONWARNING);
    SetFocus(GetDlgItem(configuration_, control));
}

bool Application::set_autostart_and_save(const Config& next, std::wstring& error) {
    HKEY rawKey = nullptr;
    const auto open = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0,
        nullptr, 0, KEY_QUERY_VALUE | KEY_SET_VALUE, nullptr, &rawKey, nullptr);
    if (open != ERROR_SUCCESS) {
        error = tr(L"Impossibile aggiornare l'avvio con Windows per l'utente corrente (errore ", L"Unable to update startup for the current user (error ") + std::to_wstring(open) + L").";
        return false;
    }
    OwnedKey key(rawKey);
    DWORD oldType = 0, oldSize = 0;
    LSTATUS query = RegQueryValueExW(key.get(), L"Scaping", nullptr, &oldType, nullptr, &oldSize);
    const bool existed = query == ERROR_SUCCESS;
    if ((!existed && query != ERROR_FILE_NOT_FOUND) || oldSize > 64 * 1024) {
        error = tr(L"Impossibile leggere in sicurezza l'impostazione di avvio esistente.", L"Unable to read the existing startup setting safely.");
        return false;
    }
    std::vector<BYTE> previous(oldSize);
    if (existed && RegQueryValueExW(key.get(), L"Scaping", nullptr, &oldType, previous.data(), &oldSize) != ERROR_SUCCESS) {
        error = tr(L"L'impostazione di avvio è cambiata. Riprova ad applicare la configurazione.", L"The startup setting changed. Try applying the configuration again.");
        return false;
    }
    LSTATUS modified = ERROR_SUCCESS;
    if (next.autoStart) {
        const std::wstring command = quote_argument(std::filesystem::path(kRoot).append(L"scaping.exe").wstring());
        modified = RegSetValueExW(key.get(), L"Scaping", 0, REG_SZ,
            reinterpret_cast<const BYTE*>(command.c_str()), static_cast<DWORD>((command.size() + 1) * sizeof(wchar_t)));
    } else {
        modified = RegDeleteValueW(key.get(), L"Scaping");
        if (modified == ERROR_FILE_NOT_FOUND) modified = ERROR_SUCCESS;
    }
    if (modified != ERROR_SUCCESS) {
        error = tr(L"Impossibile modificare l'avvio con Windows (errore ", L"Unable to change Windows startup (error ") + std::to_wstring(modified) + L").";
        return false;
    }
    if (save_config(std::filesystem::path(kRoot) / L"data" / L"config.ini", next, error)) return true;
    LSTATUS restored = existed ? RegSetValueExW(key.get(), L"Scaping", 0, oldType, previous.data(), oldSize) : RegDeleteValueW(key.get(), L"Scaping");
    if (restored != ERROR_SUCCESS && restored != ERROR_FILE_NOT_FOUND) error += tr(L" Anche il ripristino dell'avvio automatico non è riuscito: verifica l'impostazione in Windows.", L" Restoring the startup setting also failed: check it in Windows.");
    return false;
}

void Application::apply_configuration() {
    Config next;
    next.ip = window_text(GetDlgItem(configuration_, kIp));
    next.nmapPath = window_text(GetDlgItem(configuration_, kNmap));
    next.autoStart = IsDlgButtonChecked(configuration_, kAutostart) == BST_CHECKED;
    next.language = SendDlgItemMessageW(configuration_, kLanguage, CB_GETCURSEL, 0, 0) == 1 ? Language::English : Language::Italian;
    const std::array<std::pair<int,std::uint32_t*>,5> numeric{{
        {kInterval,&next.intervalMs}, {kTimeout,&next.timeoutMs}, {kSlow,&next.slowMs},
        {kConcurrency,&next.concurrency}, {kRate,&next.connectionsPerSecond}
    }};
    for (auto [id, destination] : numeric) {
        const auto value = window_text(GetDlgItem(configuration_, id));
        std::uint64_t number = 0;
        bool valid = !value.empty();
        for (wchar_t c : value) {
            if (c < L'0' || c > L'9') { valid = false; break; }
            number = number * 10 + static_cast<unsigned>(c - L'0');
            if (number > (std::numeric_limits<std::uint32_t>::max)()) { valid = false; break; }
        }
        if (!valid) { configuration_error(tr(L"Inserisci valori numerici interi positivi nei campi di tempo e di velocità.", L"Enter positive whole numbers for time and connection limits."), id); return; }
        *destination = static_cast<std::uint32_t>(number);
    }
    // A language preference may be saved before the first target is configured.
    const bool allowUnconfigured = config_.ip.empty() && next.ip.empty();
    if (auto invalid = validate_config(next, allowUnconfigured)) { configuration_error(*invalid); return; }
    std::wstring error;
    if (!set_autostart_and_save(next, error)) { configuration_error(error); return; }
    config_ = std::move(next);
    set_language(config_.language);
    configDiagnostic_.clear();
    restart_ping();
    refresh_language();
    ShowWindow(configuration_, SW_HIDE);
}

void Application::browse_nmap() {
    std::array<wchar_t,32768> path{};
    const auto current = window_text(GetDlgItem(configuration_, kNmap));
    if (current.size() < path.size()) std::copy(current.begin(), current.end(), path.begin());
    OPENFILENAMEW selection{sizeof(selection)};
    selection.hwndOwner = configuration_;
    selection.lpstrFilter = tr(L"Nmap (nmap.exe)\0nmap.exe\0Eseguibili (*.exe)\0*.exe\0\0", L"Nmap (nmap.exe)\0nmap.exe\0Executables (*.exe)\0*.exe\0\0");
    selection.lpstrFile = path.data();
    selection.nMaxFile = static_cast<DWORD>(path.size());
    selection.lpstrTitle = tr(L"Seleziona l'eseguibile Nmap", L"Select the Nmap executable");
    selection.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (GetOpenFileNameW(&selection)) SetDlgItemTextW(configuration_, kNmap, path.data());
}

void Application::create_result_controls() {
    child(results_, L"STATIC", L"", SS_ENDELLIPSIS, kTarget);
    child(results_, L"STATIC", L"", SS_ENDELLIPSIS, kScanStatus);
    child(results_, PROGRESS_CLASSW, L"", PBS_MARQUEE, kProgress);
    child(results_, L"EDIT", L"", WS_TABSTOP | WS_VSCROLL | WS_HSCROLL | ES_LEFT | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
        kOutput, WS_EX_CLIENTEDGE);
    SendDlgItemMessageW(results_, kOutput, EM_SETLIMITTEXT, kVisibleLimit + 65536, 0);
    child(results_, L"BUTTON", tr(L"Annulla scansione", L"Cancel scan"), WS_TABSTOP | BS_PUSHBUTTON, kCancelScan);
    child(results_, L"BUTTON", tr(L"Copia", L"Copy"), WS_TABSTOP | BS_PUSHBUTTON, kCopy);
    child(results_, L"BUTTON", tr(L"Salva report", L"Save report"), WS_TABSTOP | BS_PUSHBUTTON, kSave);
    child(results_, L"BUTTON", tr(L"Chiudi finestra", L"Close window"), WS_TABSTOP | BS_PUSHBUTTON, kHideResults);
    set_fonts(results_, true);
    size_results();
}

void Application::size_results() {
    if (!results_) return;
    RECT area{};
    GetClientRect(results_, &area);
    const UINT dpi = GetDpiForWindow(results_);
    auto s = [dpi](int n) { return scale(n, dpi); };
    const int width = area.right, height = area.bottom, margin = s(14);
    const int buttonY = height - s(48), buttonHeight = s(32);
    struct Position { int id,x,y,w,h; };
    const Position positions[]{
        {kTarget,margin,s(12),width-2*margin,s(23)},
        {kScanStatus,margin,s(39),width-2*margin,s(23)},
        {kProgress,margin,s(68),width-2*margin,s(7)},
        {kOutput,margin,s(87),width-2*margin,(std::max)(s(100),buttonY-s(99))},
        {kCancelScan,margin,buttonY,s(155),buttonHeight},
        {kCopy,margin+s(166),buttonY,s(78),buttonHeight},
        {kSave,margin+s(255),buttonY,s(115),buttonHeight},
        {kHideResults,width-margin-s(137),buttonY,s(137),buttonHeight}
    };
    HDWP placement = BeginDeferWindowPos(static_cast<int>(std::size(positions)));
    for (const auto& p : positions) {
        if (!placement) break;
        placement = DeferWindowPos(placement, GetDlgItem(results_,p.id), nullptr,p.x,p.y,p.w,p.h,SWP_NOZORDER | SWP_NOACTIVATE);
    }
    if (placement) EndDeferWindowPos(placement);
}

void Application::show_results() {
    if (!results_) {
        const UINT dpi = GetDpiForSystem();
        RECT bounds{0,0,scale(910,dpi),scale(590,dpi)};
        AdjustWindowRectExForDpi(&bounds, WS_OVERLAPPEDWINDOW, FALSE, WS_EX_APPWINDOW, dpi);
        results_ = CreateWindowExW(WS_EX_APPWINDOW | WS_EX_CONTROLPARENT, kResultsClass, tr(L"Scaping — Risultati", L"Scaping — Results"),
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, bounds.right-bounds.left,bounds.bottom-bounds.top,
            resident_, nullptr, instance_, this);
        if (!results_) {
            MessageBoxW(resident_, tr(L"Impossibile aprire la finestra dei risultati.", L"Unable to open the results window."), L"Scaping", MB_OK | MB_ICONERROR);
            return;
        }
    }
    foreground(results_);
}

void Application::start_scan() {
    if (scanning_) { show_results(); return; }
    if (!valid_ipv4(config_.ip)) {
        show_configuration();
        configuration_error(tr(L"Configura e applica un indirizzo IPv4 numerico prima di avviare la scansione.", L"Configure and apply a numeric IPv4 address before starting a scan."));
        return;
    }
    show_results();
    if (!results_) return;
    flush_mailbox();
    reportPath_.clear();
    finalState_ = FinalState::None;
    cancellationRequested_ = false;
    scanTarget_ = config_.ip;
    scanLanguage_ = config_.language;
    scanStart_ = std::chrono::steady_clock::now();
    finalElapsed_ = std::chrono::seconds(0);
    SetDlgItemTextW(results_, kOutput, L"");
    SetDlgItemTextW(results_, kTarget, (L"Target: " + scanTarget_ + tr(L"  |  Porte 0–65535 TCP e UDP richieste", L"  |  TCP and UDP ports 0–65535 requested")).c_str());
    append_output(tr(L"SCAPING — INVENTARIO PORTE\r\nTarget della scansione: ", L"SCAPING — PORT INVENTORY\r\nScan target: ") + scanTarget_ +
        tr(L"\r\nIl target rimane invariato se modifichi l'IP monitorato.\r\n"
           L"Scansione su richiesta; usa soltanto sistemi che sei autorizzato a verificare.\r\n"
           L"UDP può richiedere molto tempo; open|filtered rimane un esito incerto.\r\n"
           L"Il testo visibile è limitato; il report completo è salvato localmente.\r\n\r\n",
           L"\r\nThe target remains unchanged if you edit the monitored IP.\r\n"
           L"On-demand scan; only scan systems you are authorized to assess.\r\n"
           L"UDP may take a long time; open|filtered remains uncertain.\r\n"
           L"Visible text is limited; the full report is saved locally.\r\n\r\n"));
    const std::weak_ptr<Mailbox> weak = mailbox_;
    const bool started = scan_.start(config_, [weak](std::wstring text) {
        if (auto box = weak.lock()) {
            std::lock_guard lock(box->mutex);
            if (!box->alive) return;
            if (text.size() > kPendingLimit) {
                text.erase(0, text.size() - kPendingLimit);
                box->outputDropped = true;
            }
            if (box->output.size() + text.size() > kPendingLimit) {
                box->output.erase(0, box->output.size() + text.size() - kPendingLimit);
                box->outputDropped = true;
            }
            box->output += text;
        }
    }, [weak](ScanCompletion completion) {
        if (auto box = weak.lock()) {
            std::lock_guard lock(box->mutex);
            if (!box->alive) return;
            box->completion = std::move(completion);
            PostMessageW(box->window, kMailboxMessage, 0, 0);
        }
    });
    scanning_ = started;
    if (!started) {
        finalState_ = FinalState::FailedToStart;
        append_output(final_status() + L"\r\n");
    } else SetTimer(resident_, kBatchTimer, 150, nullptr);
    EnableWindow(GetDlgItem(results_, kCancelScan), scanning_);
    EnableWindow(GetDlgItem(results_, kSave), FALSE);
    SendDlgItemMessageW(results_, kProgress, PBM_SETMARQUEE, scanning_, 35);
    update_scan_status();
}

void Application::cancel_scan() {
    if (!scanning_ || cancellationRequested_) return;
    cancellationRequested_ = true;
    scan_.cancel();
    EnableWindow(GetDlgItem(results_, kCancelScan), FALSE);
    update_scan_status();
}

void Application::append_output(std::wstring text) {
    if (!results_ || text.empty()) return;
    // Input remains plain text. Control codes are never interpreted by the UI.
    text = sanitize_text(text, kPendingLimit);
    std::wstring normalized;
    normalized.reserve(text.size() + text.size()/16);
    for (std::size_t i=0;i<text.size();++i) {
        if (text[i] == L'\r') {
            normalized += L"\r\n";
            if (i + 1 < text.size() && text[i+1] == L'\n') ++i;
        } else if (text[i] == L'\n') normalized += L"\r\n";
        else normalized += text[i];
    }
    if (normalized.size() > kVisibleLimit) normalized.erase(0, normalized.size() - kVisibleLimit);
    HWND edit = GetDlgItem(results_,kOutput);
    DWORD selectionStart=0,selectionEnd=0;
    SendMessageW(edit,EM_GETSEL,reinterpret_cast<WPARAM>(&selectionStart),reinterpret_cast<LPARAM>(&selectionEnd));
    const int originalLength = GetWindowTextLengthW(edit);
    SCROLLINFO scroll{sizeof(scroll),SIF_ALL};
    GetScrollInfo(edit,SB_VERT,&scroll);
    const bool followEnd = scroll.nPos + static_cast<int>(scroll.nPage) >= scroll.nMax;
    const LRESULT firstLine = SendMessageW(edit,EM_GETFIRSTVISIBLELINE,0,0);
    SendMessageW(edit,WM_SETREDRAW,FALSE,0);
    std::size_t removed=0;
    const std::size_t total = static_cast<std::size_t>(originalLength) + normalized.size();
    if (total > kVisibleLimit) {
        removed = (std::min)(static_cast<std::size_t>(originalLength), total - kVisibleLimit + 4096);
        SendMessageW(edit,EM_SETSEL,0,static_cast<LPARAM>(removed));
        SendMessageW(edit,EM_REPLACESEL,FALSE,reinterpret_cast<LPARAM>(L""));
    }
    const int length = GetWindowTextLengthW(edit);
    SendMessageW(edit,EM_SETSEL,length,length);
    SendMessageW(edit,EM_REPLACESEL,FALSE,reinterpret_cast<LPARAM>(normalized.c_str()));
    if (selectionStart != selectionEnd || !followEnd) {
        const DWORD shift = static_cast<DWORD>(removed);
        SendMessageW(edit,EM_SETSEL,selectionStart > shift ? selectionStart-shift : 0,selectionEnd > shift ? selectionEnd-shift : 0);
        const LRESULT now = SendMessageW(edit,EM_GETFIRSTVISIBLELINE,0,0);
        SendMessageW(edit,EM_LINESCROLL,0,firstLine-now);
    } else SendMessageW(edit,EM_SCROLLCARET,0,0);
    SendMessageW(edit,WM_SETREDRAW,TRUE,0);
    InvalidateRect(edit,nullptr,TRUE);
}

void Application::flush_mailbox() {
    std::optional<PingResult> ping;
    std::optional<ScanCompletion> completion;
    std::wstring output;
    bool dropped = false;
    {
        std::lock_guard lock(mailbox_->mutex);
        ping.swap(mailbox_->ping);
        completion.swap(mailbox_->completion);
        output.swap(mailbox_->output);
        dropped = mailbox_->outputDropped;
        mailbox_->outputDropped = false;
    }
    if (ping && !suspended_ && accept_ping_generation(generation_, *ping)) {
        lastPing_ = std::move(*ping);
        if (lastPing_->success) lastRtt_ = lastPing_->rttMs;
        color_ = ping_color(*lastPing_,config_.slowMs);
        update_tray();
    }
    if (dropped) {
        const ScopedLanguage reportLanguage(scanLanguage_);
        append_output(tr(L"\r\n[Alcune righe precedenti sono presenti soltanto nel report completo su disco.]\r\n",
            L"\r\n[Some earlier lines are available only in the full report on disk.]\r\n"));
    }
    append_output(std::move(output));
    if (completion) {
        scanning_ = false;
        KillTimer(resident_,kBatchTimer);
        finalElapsed_ = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-scanStart_);
        reportPath_ = std::move(completion->reportPath);
        const bool allComplete = completion->complete && completion->tcpComplete && completion->udpComplete && !completion->cancelled;
        finalState_ = allComplete ? FinalState::Complete : (completion->cancelled ? FinalState::Cancelled : FinalState::Partial);
        {
            // A language change updates window chrome, never the active report's language.
            const ScopedLanguage reportLanguage(scanLanguage_);
            auto summary = final_status();
            if (!completion->summary.empty()) summary += L" · " + sanitize_text(completion->summary,1500);
            append_output(tr(L"\r\nSTATO FINALE: ", L"\r\nFINAL STATUS: ") + summary + L"\r\n" +
                (reportPath_.empty() ? std::wstring(tr(L"Report completo non disponibile.\r\n", L"Full report is unavailable.\r\n")) :
                    tr(L"Report completo: ", L"Full report: ") + reportPath_.wstring() + L"\r\n"));
        }
        if (results_) {
            EnableWindow(GetDlgItem(results_,kCancelScan),FALSE);
            EnableWindow(GetDlgItem(results_,kSave),!reportPath_.empty());
            SendDlgItemMessageW(results_,kProgress,PBM_SETMARQUEE,FALSE,0);
        }
    }
    update_scan_status();
}

void Application::update_scan_status() {
    if (!results_) return;
    const auto elapsed = scanning_ ? std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now()-scanStart_) : finalElapsed_;
    const auto seconds = elapsed.count();
    wchar_t duration[64]{};
    swprintf_s(duration,L"%02lld:%02lld:%02lld",seconds/3600,(seconds/60)%60,seconds%60);
    std::wstring state = scanning_ ? (cancellationRequested_ ? tr(L"Annullamento in corso…", L"Cancelling…") :
        tr(L"In corso — motore, fase e avanzamento nel testo", L"Running — engine, phase and progress in output")) : final_status();
    const std::wstring label = tr(L"Tempo trascorso: ", L"Elapsed time: ") + std::wstring(duration) + L"  |  " + state;
    SetDlgItemTextW(results_,kScanStatus,label.c_str());
}

void Application::copy_output() {
    if (!results_) return;
    HWND edit = GetDlgItem(results_,kOutput);
    DWORD first=0,last=0;
    SendMessageW(edit,EM_GETSEL,reinterpret_cast<WPARAM>(&first),reinterpret_cast<LPARAM>(&last));
    if (first == last) SendMessageW(edit,EM_SETSEL,0,-1);
    SendMessageW(edit,WM_COPY,0,0);
    if (first == last) SendMessageW(edit,EM_SETSEL,first,last);
}

void Application::save_report() {
    if (reportPath_.empty()) return;
    std::array<wchar_t,32768> path{};
    constexpr wchar_t defaultName[] = L"scaping-report.txt";
    std::copy(std::begin(defaultName),std::end(defaultName),path.begin());
    OPENFILENAMEW selection{sizeof(selection)};
    selection.hwndOwner=results_;
    selection.lpstrFilter=tr(L"Report di testo (*.txt)\0*.txt\0Tutti i file (*.*)\0*.*\0\0", L"Text reports (*.txt)\0*.txt\0All files (*.*)\0*.*\0\0");
    selection.lpstrFile=path.data();
    selection.nMaxFile=static_cast<DWORD>(path.size());
    selection.lpstrDefExt=L"txt";
    selection.lpstrInitialDir=kRoot;
    selection.lpstrTitle=tr(L"Salva il report completo", L"Save the full report");
    selection.Flags=OFN_PATHMUSTEXIST | OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR | OFN_EXPLORER;
    if (!GetSaveFileNameW(&selection)) return;
    const std::filesystem::path destination(path.data());
    std::error_code ec;
    if (std::filesystem::equivalent(reportPath_,destination,ec)) return;
    if (!CopyFileW(reportPath_.c_str(),destination.c_str(),FALSE)) {
        MessageBoxW(results_,tr(L"Impossibile copiare il report nella destinazione scelta. Il file originale resta nella cartella data.",
            L"Unable to copy the report to the selected destination. The original file remains in the data folder."),
            tr(L"Scaping — salvataggio report", L"Scaping — save report"),MB_OK | MB_ICONERROR);
    }
}

void Application::restart_ping() {
    ++generation_;
    ping_.stop();
    lastPing_.reset();
    lastRtt_.reset();
    color_=PingColor::Gray;
    update_tray();
    if (config_.ip.empty() || suspended_ || shuttingDown_) return;
    const std::weak_ptr<Mailbox> weak=mailbox_;
    ping_.start(config_,generation_,[weak](PingResult result) {
        if (auto box=weak.lock()) {
            std::lock_guard lock(box->mutex);
            if (!box->alive) return;
            box->ping=std::move(result);
            PostMessageW(box->window,kMailboxMessage,0,0);
        }
    });
}

void Application::update_tray(bool add) {
    if (!resident_ || shuttingDown_) return;
    std::wstring tooltip;
    if (config_.ip.empty()) tooltip=tr(L"IP non configurato", L"IP not configured");
    else if (suspended_) tooltip=config_.ip+tr(L" · Monitoraggio sospeso", L" · Monitoring suspended");
    else if (!lastPing_) tooltip=config_.ip+tr(L" · In attesa del primo risultato", L" · Waiting for first result");
    else if (lastPing_->success) tooltip=config_.ip + (color_ == PingColor::Orange ? tr(L" · Ping lento · ", L" · Slow ping · ") : L" · Ping OK · ") + std::to_wstring(lastPing_->rttMs)+L" ms";
    else {
        tooltip=config_.ip+tr(L" · Ping KO: ", L" · Ping failed: ")+sanitize_text(lastPing_->error.empty() ? tr(L"errore ICMP", L"ICMP error") : lastPing_->error,60);
        if (lastRtt_) tooltip+=tr(L" · Ultimo RTT ", L" · Last RTT ")+std::to_wstring(*lastRtt_)+L" ms";
    }
    if (tooltip.size()>127) tooltip.resize(127);
    NOTIFYICONDATAW icon{sizeof(icon)};
    icon.hWnd=resident_;
    icon.uID=1;
    icon.uFlags=NIF_ICON | NIF_MESSAGE | NIF_TIP | NIF_SHOWTIP;
    icon.uCallbackMessage=kTrayMessage;
    icon.hIcon=icons_[static_cast<std::size_t>(color_)].get();
    wcsncpy_s(icon.szTip,tooltip.c_str(),_TRUNCATE);
    const DWORD operation=(add || !trayAdded_) ? NIM_ADD : NIM_MODIFY;
    if (!Shell_NotifyIconW(operation,&icon)) {
        trayAdded_=false;
        SetTimer(resident_,kTrayRetryTimer,2000,nullptr);
        return;
    }
    trayAdded_=true;
    KillTimer(resident_,kTrayRetryTimer);
    if (operation==NIM_ADD) {
        icon.uVersion=NOTIFYICON_VERSION_4;
        trayVersion4_ = Shell_NotifyIconW(NIM_SETVERSION,&icon) != FALSE;
    }
}

void Application::tray_menu(POINT point) {
    OwnedMenu menu(CreatePopupMenu());
    if (!menu) return;
    AppendMenuW(menu.get(),MF_STRING,kExit,tr(L"Chiudi", L"Exit"));
    AppendMenuW(menu.get(),MF_STRING,kConfigure,tr(L"Configura IP", L"Configure IP"));
    AppendMenuW(menu.get(),MF_STRING,kScan,tr(L"Scansiona TUTTE le porte", L"Scan ALL ports"));
    if (point.x==-1 && point.y==-1) GetCursorPos(&point);
    SetForegroundWindow(resident_);
    const UINT choice=TrackPopupMenuEx(menu.get(),TPM_RETURNCMD | TPM_RIGHTBUTTON | TPM_NONOTIFY,
        point.x,point.y,resident_,nullptr);
    PostMessageW(resident_,WM_NULL,0,0);
    if (choice) PostMessageW(resident_,WM_COMMAND,choice,0);
}

void Application::shutdown() {
    if (shuttingDown_) return;
    shuttingDown_=true;
    ++generation_;
    {
        std::lock_guard lock(mailbox_->mutex);
        mailbox_->alive=false;
        mailbox_->window=nullptr;
        mailbox_->output.clear();
        mailbox_->ping.reset();
        mailbox_->completion.reset();
    }
    ping_.stop();
    scan_.cancel();
    if (resident_) {
        KillTimer(resident_,kBatchTimer);
        KillTimer(resident_,kTrayRetryTimer);
        NOTIFYICONDATAW icon{sizeof(icon)};
        icon.hWnd=resident_;
        icon.uID=1;
        Shell_NotifyIconW(NIM_DELETE,&icon);
        trayAdded_=false;
    }
    if (configuration_ && IsWindow(configuration_)) DestroyWindow(configuration_);
    if (results_ && IsWindow(results_)) DestroyWindow(results_);
    if (resident_ && IsWindow(resident_)) DestroyWindow(resident_);
}

LRESULT CALLBACK Application::resident_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    Application* app=context(window,message,lparam);
    if (!app) return DefWindowProcW(window,message,wparam,lparam);
    try {
        if (message==app->taskbarCreated_) { app->trayAdded_=false; app->update_tray(true); return 0; }
        if (message==app->activate_) { app->show_configuration(); return 0; }
        switch(message) {
        case kMailboxMessage: app->flush_mailbox(); return 0;
        case kTrayMessage: {
            const UINT action=app->trayVersion4_ ? LOWORD(lparam) : static_cast<UINT>(lparam);
            if ((app->trayVersion4_ && action==WM_CONTEXTMENU) || (!app->trayVersion4_ && action==WM_RBUTTONUP)) {
                POINT point{-1,-1};
                if (app->trayVersion4_) point={GET_X_LPARAM(wparam),GET_Y_LPARAM(wparam)};
                app->tray_menu(point);
            } else if (action==WM_LBUTTONDBLCLK || action==NIN_KEYSELECT) app->show_configuration();
            return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wparam)==kExit) { app->shutdown(); PostQuitMessage(0); }
            else if (LOWORD(wparam)==kConfigure) app->show_configuration();
            else if (LOWORD(wparam)==kScan) app->start_scan();
            return 0;
        case WM_TIMER:
            if (wparam==kBatchTimer) app->flush_mailbox();
            else if (wparam==kTrayRetryTimer) app->update_tray(true);
            return 0;
        case WM_POWERBROADCAST:
            if (wparam==PBT_APMSUSPEND) {
                app->suspended_=true;
                app->restart_ping();
                if (app->scanning_) {
                    {
                        const ScopedLanguage reportLanguage(app->scanLanguage_);
                        app->append_output(tr(L"\r\n[Sospensione del sistema: scansione annullata, risultato parziale.]\r\n",
                            L"\r\n[System suspend: scan cancelled, partial result.]\r\n"));
                    }
                    app->cancel_scan();
                }
            } else if (wparam==PBT_APMRESUMEAUTOMATIC || wparam==PBT_APMRESUMESUSPEND) {
                if (app->suspended_) { app->suspended_=false; app->restart_ping(); }
            }
            return TRUE;
        case WM_QUERYENDSESSION: return TRUE;
        case WM_ENDSESSION:
            if (wparam) { app->shutdown(); PostQuitMessage(0); }
            return 0;
        case WM_CLOSE: app->shutdown(); PostQuitMessage(0); return 0;
        case WM_DESTROY: app->resident_=nullptr; PostQuitMessage(0); return 0;
        }
    } catch (...) {
        MessageBoxW(window,tr(L"Operazione non riuscita. Verifica le risorse di sistema e la configurazione.", L"Operation failed. Check system resources and configuration."),L"Scaping",MB_OK | MB_ICONERROR);
        return 0;
    }
    return DefWindowProcW(window,message,wparam,lparam);
}

LRESULT CALLBACK Application::config_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    Application* app=context(window,message,lparam);
    if (!app) return DefWindowProcW(window,message,wparam,lparam);
    try {
        switch(message) {
        case WM_CREATE: app->configuration_=window; app->create_config_controls(); return 0;
        case WM_SIZE: app->size_config(); return 0;
        case WM_DPICHANGED: {
            const RECT* bounds=reinterpret_cast<const RECT*>(lparam);
            SetWindowPos(window,nullptr,bounds->left,bounds->top,bounds->right-bounds->left,bounds->bottom-bounds->top,SWP_NOZORDER | SWP_NOACTIVATE);
            app->set_fonts(window,false); app->size_config(); return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wparam)==kApply || LOWORD(wparam)==IDOK) app->apply_configuration();
            else if (LOWORD(wparam)==kDismiss || LOWORD(wparam)==IDCANCEL) ShowWindow(window,SW_HIDE);
            else if (LOWORD(wparam)==kBrowse) app->browse_nmap();
            return 0;
        case WM_CLOSE: ShowWindow(window,SW_HIDE); return 0;
        case WM_DESTROY: app->configuration_=nullptr; return 0;
        }
    } catch (...) {
        if (message==WM_CREATE) return -1;
        MessageBoxW(window,tr(L"Impossibile completare l'operazione di configurazione.", L"Unable to complete the configuration operation."),L"Scaping",MB_OK | MB_ICONERROR);
        return 0;
    }
    return DefWindowProcW(window,message,wparam,lparam);
}

LRESULT CALLBACK Application::results_proc(HWND window,UINT message,WPARAM wparam,LPARAM lparam) {
    Application* app=context(window,message,lparam);
    if (!app) return DefWindowProcW(window,message,wparam,lparam);
    try {
        switch(message) {
        case WM_CREATE: app->results_=window; app->create_result_controls(); return 0;
        case WM_SIZE: app->size_results(); return 0;
        case WM_GETMINMAXINFO: {
            auto limits=reinterpret_cast<MINMAXINFO*>(lparam);
            const UINT dpi=GetDpiForWindow(window);
            limits->ptMinTrackSize={scale(640,dpi),scale(400,dpi)}; return 0;
        }
        case WM_DPICHANGED: {
            const RECT* bounds=reinterpret_cast<const RECT*>(lparam);
            SetWindowPos(window,nullptr,bounds->left,bounds->top,bounds->right-bounds->left,bounds->bottom-bounds->top,SWP_NOZORDER | SWP_NOACTIVATE);
            app->set_fonts(window,true); app->size_results(); return 0;
        }
        case WM_COMMAND:
            if (LOWORD(wparam)==kCancelScan) app->cancel_scan();
            else if (LOWORD(wparam)==kCopy) app->copy_output();
            else if (LOWORD(wparam)==kSave) app->save_report();
            else if (LOWORD(wparam)==kHideResults || LOWORD(wparam)==IDCANCEL) ShowWindow(window,SW_HIDE);
            return 0;
        case WM_CLOSE: ShowWindow(window,SW_HIDE); return 0;
        case WM_DESTROY: app->results_=nullptr; return 0;
        }
    } catch (...) {
        if (message==WM_CREATE) return -1;
        MessageBoxW(window,tr(L"Impossibile completare l'operazione sui risultati. Il report completo resta su disco.", L"Unable to complete the results operation. The full report remains on disk."),L"Scaping",MB_OK | MB_ICONERROR);
        return 0;
    }
    return DefWindowProcW(window,message,wparam,lparam);
}
}

int run_gui(HINSTANCE instance) {
    Application application(instance);
    if (!application.initialize()) {
        MessageBoxW(nullptr,tr(L"Impossibile inizializzare Scaping o la system tray.", L"Unable to initialize Scaping or the system tray."),L"Scaping",MB_OK | MB_ICONERROR);
        return 1;
    }
    return application.loop();
}
}
