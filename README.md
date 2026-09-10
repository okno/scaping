# SCAPING

[English](README.md) · [Italiano](README.it.md)

An ICMP monitor and port inventory tool for Windows, built with C++20 and native Win32 APIs. The application runs in the system tray and opens no console or main window at startup. It contains no telemetry, automatic update checks, Windows services, or web runtime.

## Requirements and startup

Windows 10 x64 version 1809 or later. The Release build is a GUI executable with a statically linked C/C++ runtime. See [the verification record](docs/VERIFICATION.md) for the Windows version actually tested, test results, and measurements.

Required project folder and working directory: `D:\scaping`. Executable: `D:\scaping\scaping.exe`. The application explicitly selects this working directory even when launched elsewhere and shows an error if it is unavailable.

```powershell
powershell -NoProfile -File D:\scaping\scripts\build.ps1
powershell -NoProfile -File D:\scaping\scripts\test.ps1 -SkipBuild
powershell -NoProfile -File D:\scaping\scripts\package.ps1 -SkipBuild
powershell -NoProfile -File D:\scaping\scripts\run.ps1
```

Run the build, test, and packaging commands from a source checkout. Building requires Visual Studio 2022 Build Tools with **Desktop development with C++**, MSVC x64, the Windows SDK, and **C++ CMake tools for Windows**. CMake 3.24 or later is required; the scripts also detect the CMake installation bundled with Visual Studio. The Release build copies the executable to the project root. Close SCAPING before rebuilding. Debug builds remain in `build\Debug`.

The ZIP package in `dist` contains the executable, instructions, a neutral configuration example, and deployment/startup scripts. It excludes local settings, reports, symbols, Nmap, and Npcap. Extract the package and use `scripts\deploy.ps1` to copy the executable to `D:\scaping`; the script refuses to overwrite an existing executable.

## Language

Version 1.1.0 supports English and Italian. New installations initially use Italian. To select English, open **Configura IP** from the tray menu, choose **English** under **Lingua / Language**, and click **Applica**. The interface changes immediately and the setting is saved. In English, the same commands are **Configure IP** and **Apply**. Select **Italiano** to switch back.

During initial setup, you can save a language choice while the IP field is still empty; the icon stays gray and no target is contacted. Once an IP has been configured, a valid IPv4 address is required when applying settings: clearing the target does not bypass validation.

Each scan keeps the language and target selected when it started. Changing the interface language does not translate output already collected or change the language of a running scan. External Nmap output, banners, service names, protocol tokens, and other received data are never machine-translated.

## Tray and monitoring

At first launch, the square is gray and its tooltip reports that the IP is not configured (**IP non configurato** with the initial Italian setting). There is no default network target. Windows controls whether the icon appears directly in the tray or in its hidden-icons area; SCAPING does not change that preference.

| Color | Last completed ICMP attempt |
| --- | --- |
| Green | Valid reply with an RTT below the slow-ping threshold |
| Orange | Valid reply with an RTT at or above the threshold |
| Red | Ping failed: timeout, negative ICMP reply, or another error; this does not prove the system is powered off |
| Gray | No IP configured, awaiting the first result, or monitoring being reinitialized |

The English right-click menu contains **Exit**, **Configure IP**, and **Scan ALL ports**. The Italian menu contains **Chiudi**, **Configura IP**, and **Scansiona TUTTE le porte**. Double-click the icon with the left mouse button to open settings. A second launch brings forward the existing instance in the same user session. Closing a settings or results window keeps monitoring active; **Exit** also stops the application's owned work. The icon is restored after Explorer restarts.

Pings use asynchronous `IcmpSendEcho2`, without running `ping.exe`. Only one attempt can be outstanding. Each configuration change starts a new generation, so a reply from a previous generation cannot update the color. Changing the IP or resuming monitoring restarts the cycle. Ping results remain in memory, with no disk write for each attempt.

## Configuration

A single numeric IPv4 address is required, such as `127.0.0.1` for a test on your own PC. URLs, hostnames, CIDR notation, lists, ranges, and command arguments are rejected. IPv6 is not implemented.

Initial values are a 1000 ms interval, an 800 ms timeout, a 150 ms slow-ping threshold, and startup with Windows disabled. The threshold must be lower than the timeout. Advanced settings control concurrent TCP connections and the rate at which new connections start, initially 64 and 128 per second.

Local configuration is saved atomically to `D:\scaping\data\config.ini`. Schema version 2 includes `language=it` or `language=en`. Existing version 1 files are loaded as Italian with their target and other settings preserved; migration takes place in memory and the next successful save writes version 2. Invalid files are reported and do not cause traffic to an unvalidated target.

Startup with Windows uses the current user's HKCU Run key. It can be reversed from the same settings window and does not require elevation. The example in `resources\config.example.ini` contains no target.

Leave the Nmap path field empty to use installation-directory detection, or select the executable manually. The application does not blindly select an `nmap.exe` from the working directory or PATH.

## Full scanning and limitations

Scan only systems you are authorized to examine. Every scan starts on request and keeps a snapshot of its target and language. Changing the monitored IP does not redirect an active scan. Only one scan can run at a time; further clicks bring its results window forward.

**ALL** means 65,536 TCP ports and 65,536 UDP ports, including both 0 and 65535. Nmap runs one TCP phase and one UDP phase, one at a time, with these fixed profiles, plus `-oX` with an absolute local output path and the validated IP:

```text
TCP: -sT -n -Pn -p0-65535 -sV --version-light -T3 --reason --stats-every 2s
UDP: -sU -n -Pn -p0-65535 -sV --version-light -T3 --reason --stats-every 2s
```

`-Pn` allows scanning even when the target does not answer pings. `-sV` enables service/version detection. SCAPING adds no vulnerability scripts, brute force, `-A`, or authentication attempts. TCP port 9100 remains in the port scan, while Nmap's standard version-probe exclusions remain active to avoid unwanted printing. SCAPING does not pass `--allports`.

The states `open`, `closed`, `filtered`, and `open|filtered` remain distinct. **UDP silence does not mean a port is closed.** ICMP rate limiting can make a full UDP scan take a long time. No duration is guaranteed, and the application does not silently reduce the port range or omit phases.

Port-scan coverage and service-detection completion are reported separately. A missing phase, an error, or cancellation produces a **partial** result. A complete scan can still contain uncertain states and unidentified services.

Service, product, version, and extra information come from Nmap XML. A conventional name from a port table is distinguished from identification based on a response. Nmap fingerprints are not presented as banners. Missing information is reported as unidentified or unavailable.

### Nmap unavailable: native TCP fallback

Ping monitoring continues normally. Scanning uses **TCP only — reduced mode**: nonblocking Winsock connections, bounded concurrency and start rate, and timeout results distinguished from local errors. The TCP connection timeout is at least 3000 ms; a higher configured timeout takes precedence. This gives the Windows stack time to report a delayed refusal instead of prematurely recording an uncertain result. The ping timeout remains the configured value, initially 800 ms. Reports show the effective TCP timeout. The fallback also traverses 0..65535 using a counter of at least 32 bits. It does not create one thread per port.

On open ports, it attempts only a passive banner read, bounded to 2048 bytes and 300 ms. Nontext bytes are escaped. It sends no application probes and does not imitate Nmap's identification database. A timeout remains uncertain, and local errors are not reported as closed ports. There is no UDP fallback; overall coverage is explicitly partial.

### Results, cancellation, and reports

The resizable results window contains a read-only, selectable, monospaced multiline text box with scrollbars, plus **Cancel scan**, **Copy**, **Save report**, and **Close window**. Output and phase information update in batches. An indeterminate progress indicator is used when no reliable percentage is available.

The visible text buffer is bounded; complete output is retained locally under `data`. Stdout and stderr are captured without blocking the child process. XML provides the structured results and is treated as untrusted input: bounded size, no external entity or network resolution, and control characters neutralized for display. Reports may contain sensitive network information and are excluded from Git.

Closing the results window hides it. **Cancel scan** stops the actual work and preserves output already collected. Scan processes belong to Job Objects that clean up owned processes on closure; the temporary worker does not become a service.

## Privileges and external dependencies

The interface and ping monitor run without administrator privileges. Nmap and Npcap are optional for ping monitoring and required, with suitable permissions, for full scanning. Installation, licensing, and worker restrictions are described in [Dependencies](docs/DEPENDENCIES.md) and [Security](docs/SECURITY.md).

SCAPING installs no drivers, changes no firewall or antivirus settings, and modifies no services or global settings. If Npcap is unavailable or permissions prevent UDP scanning, ping monitoring continues and the missing capability is reported. Elevation applies only to a temporary worker with fixed profiles; declining UAC does not stop the ping monitor.

## Testing and privacy

The automated tests cover IPv4 validation, colors from simulated ICMP results, configuration, the full port range, argument quoting, and hostile or incomplete XML. Real network tests are limited to loopback and controlled listeners. Consult the [verification record](docs/VERIFICATION.md) to distinguish tests actually run from those still outstanding. Recorded version 1.0.0 measurements are historical baseline results, not measurements of version 1.1.0.

`scripts\measure.ps1 -ProcessId <PID> -Seconds 60` measures CPU usage normalized across the whole machine and the resident process's private bytes. Measurement files remain under `data` and exclude Nmap processes.

Source, tests, and documentation use synthetic data. Local `data`, `build`, and `dist` folders, real settings, Nmap output, logs, credentials, and personal metadata are not published. Nmap and Npcap are not redistributed.
