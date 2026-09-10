# Verification record

[English](VERIFICATION.md) · [Italiano](VERIFICATION.it.md) · [README](../README.md)

## Historical baseline: version 1.0.0

All environment details, binary hashes, test counts, desktop observations, and measurements in the sections below were recorded for **version 1.0.0**. They are preserved as a historical baseline and do not certify the version 1.1.0 localization update. No new localization test results are claimed in this baseline; later results must identify the version and checks actually performed.

### Actual test environment

Verification was performed on September 10, 2026, on **Windows 10 x64 build 19045**. The installed toolchain was Visual Studio Build Tools 2022 17.14, MSVC 19.44.35228, CMake 3.31.6-msvc6, and Windows SDK 10.0.26100. The recent SDK version does not introduce a Windows 11 runtime requirement. The declared minimum is Windows 10 1809; that minimum build was not tested separately.

The x64 Release build succeeded. The version 1.0.0 executable was **563,712 bytes**, with SHA-256 `74b2316748251efede96bc5597a8aa4d41806f3333f4e09e2b4e0e98b8c39b49`. PE inspection confirmed **Windows GUI**, ASLR, NX, and Control Flow Guard. Its imports were Windows DLLs; it included no dynamically linked VC runtime, web component, or Nmap/Npcap library. No PDB references, personal profile paths, or token patterns were detected in that binary.

### Automated tests actually passed

`scripts\test.ps1 -SkipBuild`: **2 suites passed, 0 failures**, taking 8.77 seconds in the last centralized version 1.0.0 run.

| Suite | Checks | Coverage |
| --- | ---: | --- |
| Core | 65,731 | Valid/invalid IPv4 and hostile input; simulated ICMP colors and exact threshold; generations; atomic and corrupt configuration, including failed replacement without data loss; Unicode and sanitization; Windows quoting round trips; fixed Nmap profiles; complete, partial, hostile, oversized, and wrong-target XML; all 65,536 port values, including 0 and 65535 |
| Networking | 56 | Real loopback ICMP with stop/resume; controlled TCP listeners, text and binary banners, bounded passive reads; TCP refusal; uncertain timeouts distinguished from local errors; final port 65535 without overflow; cancellation and bounded starts; stdout/stderr; process timeout and cancellation; Job termination of a descendant; rejection of invalid worker requests, nonce, PID, and path; missing Nmap, one scan at a time, and partial reporting |

The initial TCP refusal test with a 500 ms deadline correctly produced an uncertain timeout. On this Windows system, a refusal from the bound but non-listening local socket arrived after approximately 2.1 seconds. The refusal test was updated to allow 4 seconds, and production uses a 3-second TCP minimum shown in reports. Timeout semantics were not changed to make the test pass.

Automated network tests contacted only loopback and controlled listeners. Invalid worker requests were rejected before UAC. The suite performed no external scans, driver installations, or firewall/service changes.

### Actual desktop observations

- The executable was launched from `C:\Windows` and remained resident, without an initial console or main window. Startup selected and checked `D:\scaping` as its working directory.
- A second launch left one resident process and opened **Scaping — Configura IP**. Italian controls and buttons were detected through accessibility.
- **Scaping — Risultati** was observed during the user's manual test, with a partial cancellation summary, text box, scrollbars, and buttons. User-entered configuration and reports remained local and are not reproduced here.
- The final version 1.0.0 build was copied to `D:\scaping\scaping.exe` and launched while preserving existing configuration. No Nmap process or test worker remained running after the suites.

The Windows screenshot tool returned `SetIsBorderRequired failed: Interfaccia non supportata (0x80004002)` (interface not supported). Reading accessible window information worked. Automated input overlapped with the user's interactions and does not constitute a complete interface test. No pixel-by-pixel visual inspection or verification of every tray-menu click is claimed. The test instance was restarted through process management to update the binary; that was not a test of the **Chiudi** command.

### Measurements

The **final version 1.0.0 Release build** was measured after restarting the resident process, with ICMP monitoring configured, windows closed, and no scan running. Duration: **60.895 seconds**, on 4 logical processors. Average CPU usage normalized across the whole machine: **0.0128%**. Average private bytes: **2,774,903** (approximately **2.65 MiB**); peak: **2,859,008** (approximately 2.73 MiB). No scan process was included. Under these conditions, both initial targets were met: CPU below 0.5% and private bytes below 30 MB.

These are measurements from one system, not a performance guarantee for every machine or a measurement of a later release. Detailed measurement files remain under `data` and are excluded from the repository.

### Tests outstanding at the baseline

Nmap and Npcap were not installed in the test environment. Consequently, neither real full 0..65535 TCP/UDP phase was run. The fixed profiles were not checked against an installed Nmap version, and Npcap device access, real UAC consent/denial, and IPC loss during a real elevated scan were not tested. Implementations were present; code review and synthetic tests do not replace that integration testing.

The following desktop tests remained outstanding: an actual Explorer restart, PC suspend/resume, changing the IP while an ICMP request is genuinely pending, startup at the next sign-in, all button interactions, and exiting from the tray during a real scan. Automated generation, cancellation, and cleanup checks cover the underlying logic without claiming to be those manual tests.

The resident process may wait for its one outstanding ICMP timeout before final exit, as explained in [Security](SECURITY.md). Full UDP scanning is not guaranteed to be quick; `open|filtered` results and unidentified services remain possible even with complete coverage.

## Version 1.1.0 verification

Verified on September 10, 2026, using the Windows 10 x64 and MSVC environment described above. The final Release executable is **595,968 bytes**, SHA-256 `b66c18d8ebe72550f337699cbaf86a90e7c4ccbb3ba13cb89326904625d8c172`. PE inspection confirmed Windows GUI, ASLR, NX, Control Flow Guard, and Windows-only DLL imports. No personal profile paths, secret patterns, or PDB references were detected in the binary.

The centralized automated run passed **4 suites, 0 failures**, in **14.32 seconds**: core and networking each ran in Italian and English. Each core run passed **65,762 checks**; each networking run passed **58 checks**. Added coverage verifies version 1 migration without changing settings or rewriting the file on read, version 2 language round trips, invalid/missing/duplicate language rejection, saving the initial language without a target, localized validation and XML diagnostics, thread isolation, and retention of a scan's language while its caller switches language. Existing loopback, process cleanup, cancellation, XML, and full port-boundary checks passed in both languages. Network test traffic remained limited to loopback.

The final UI spacing adjustment was rebuilt successfully. Native GDI text measurements at 100%, 125%, 150%, and 200% scaling verified that the Nmap hint and language label fit their allocated areas. This was a text-layout check, not a screenshot inspection of the full interface.

The application was deployed to `D:\scaping\scaping.exe` and launched from `C:\Windows`. A second launch exited and opened the existing configuration window, leaving one resident process. Accessibility inspection detected the new language selector in Italian and then verified the English **Configure IP** window, field labels, **Browse…**, **Apply**, and **Close** after restart. The local configuration was switched atomically to version 2 with `language=en`; comparison confirmed that every other setting was preserved. No real target or local report is reproduced in this record.

Automated clicking failed with `coordinate input geometry is unavailable`; keyboard input did not produce a verified focus change. The language was therefore selected through the local configuration file while the application was stopped. Live selector interaction is implemented and reviewed, but a successful automated click-and-Apply test is not claimed. The Windows screenshot limitation described above also remains. Windows-owned window controls and common dialogs can follow the operating system's language; original Nmap output and received data retain their original text.

No new performance measurement, full Nmap/Npcap integration run, or UAC test was performed for 1.1.0. The historical measurements and outstanding integration/manual tests above remain explicitly separate from these localization results.
