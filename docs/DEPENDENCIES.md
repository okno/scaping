# Dependencies and references

[English](DEPENDENCIES.md) · [Italiano](DEPENDENCIES.it.md) · [README](../README.md)

The resident application requires only DLLs supplied with Windows 10. Release builds use a statically linked C/C++ runtime. Development requires MSVC 2022, the Windows SDK, and CMake 3.24 or later. Visual Studio is not required on the destination PC.

For full port inventory, install Nmap and Npcap from their official sites under their respective licenses. SCAPING neither installs them nor includes their files in its package. Installing the Npcap driver may require administrator consent, and its administrators-only access option affects raw scans. Do not change global settings solely to accelerate a scan.

- [Nmap on Windows and prerequisites](https://nmap.org/book/inst-windows.html)
- [Download Nmap](https://nmap.org/download.html)
- [Npcap](https://npcap.com/)
- [Scan techniques and privileges](https://nmap.org/book/man-port-scanning-techniques.html)
- [Port selection, including explicit port 0](https://nmap.org/book/man-port-specification.html)
- [Version detection and probe exclusions](https://nmap.org/book/man-version-detection.html)
- [UDP scanning limitations](https://nmap.org/book/scan-methods-udp-scan.html)
- [Nmap legal terms](https://nmap.org/book/man-legal.html)
- [Nmap OEM and redistribution](https://nmap.org/oem/)
- [Asynchronous IcmpSendEcho2](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2)
- [Job Objects](https://learn.microsoft.com/windows/win32/procthread/job-objects)

Launching Nmap as an external process does not grant redistribution rights. Any future package that includes Nmap or Npcap requires a separate review of the terms applicable to the distributed versions.

SCAPING's language setting translates its own interface and explanatory text. It does not translate Nmap's output, received banners, service names, or other external data. Those retain their original content regardless of the selected interface language.
