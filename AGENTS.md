# SCAPING engineering rules

Native C++20 / Win32, Windows 10 x64 (minimum 1809), MSVC, static Release runtime. GUI resident starts in tray with gray status until a real ICMP result. Required root and working directory: `D:\scaping`. No default network target, telemetry, driver installation or external scans in tests.

Ownership: UI agent owns `src/main.cpp`, `src/ui.cpp`, `include/scaping/ui.hpp`, resources. Networking agent owns `src/network.cpp`, `src/worker.cpp` and networking internals. QA/core agent owns `src/core.cpp`, `tests/*`. Lead owns shared public headers, CMake, scripts, docs, integration and Git. Coordinate interface changes before editing another module. No parallel edits to the same file.

For the localization update: lead owns core/config/tests/shared language header, CMake and scripts; UI agent owns UI/main/resources; networking agent owns network/worker; documentation agent owns README and docs translations. Text selection uses `tr(italian, english)` and thread-local `ScopedLanguage`: each scan keeps its snapshot language, while UI language can change. Config schema v2 adds `language=it|en`; legacy v1 loads as Italian with all values preserved. Never translate protocol tokens, process arguments, XML data, banners or external tool output.

Interfaces live in `include/scaping/core.hpp` and `include/scaping/network.hpp`. UI callbacks from workers must be marshalled and bounded. One ping and one scan at a time; reconfiguration rejects stale ping generations. Full scan means 0..65535 TCP AND UDP. Missing UDP, cancellation or error means partial. UDP silence is uncertain. Never launch a shell for processes; use absolute paths, fixed arguments, job cleanup and restricted elevated worker IPC.

Build: `powershell -NoProfile -File scripts/build.ps1`. Tests: `powershell -NoProfile -File scripts/test.ps1`. Package: `powershell -NoProfile -File scripts/package.ps1`. Start: `powershell -NoProfile -File scripts/run.ps1`.

Commit only synthetic source, fixtures and documentation. Ignore data/build/dist, real config, reports, XML outputs, logs, dumps, credentials, private IDE files and agent artifacts. Never publish prompts, conversation history, Windows profile paths or personal identifiers. Local repository identity: Scaping Development <dev@scaping.invalid>. Private remote only, no force push; verify staged content and author/committer before push.
