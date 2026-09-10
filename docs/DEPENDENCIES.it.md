# Dipendenze e fonti

[English](DEPENDENCIES.md) · [Italiano](DEPENDENCIES.it.md) · [README](../README.it.md)

Il residente richiede solo DLL fornite da Windows 10; la Release usa il runtime C/C++ statico. La toolchain di sviluppo è MSVC 2022 con Windows SDK e CMake 3.24 o superiore. Non serve Visual Studio sul PC destinatario.

Per l'inventario completo, installare Nmap e Npcap dai rispettivi siti ufficiali, secondo le loro licenze. SCAPING non li installa e non include loro file nel pacchetto. Il driver Npcap può richiedere consenso amministrativo, e l'opzione di accesso solo agli amministratori influisce sull'esecuzione delle scansioni raw. Non modificare impostazioni globali soltanto per accelerare una scansione.

- [Nmap per Windows e prerequisiti](https://nmap.org/book/inst-windows.html)
- [Download Nmap](https://nmap.org/download.html)
- [Npcap](https://npcap.com/)
- [Tecniche di scansione e privilegi](https://nmap.org/book/man-port-scanning-techniques.html)
- [Porte, inclusione esplicita della porta 0](https://nmap.org/book/man-port-specification.html)
- [Rilevamento versioni ed esclusioni delle sonde](https://nmap.org/book/man-version-detection.html)
- [Limiti della scansione UDP](https://nmap.org/book/scan-methods-udp-scan.html)
- [Nmap: condizioni legali](https://nmap.org/book/man-legal.html)
- [Nmap OEM e redistribuzione](https://nmap.org/oem/)
- [IcmpSendEcho2 asincrono](https://learn.microsoft.com/windows/win32/api/icmpapi/nf-icmpapi-icmpsendecho2)
- [Job Objects](https://learn.microsoft.com/windows/win32/procthread/job-objects)

Il fatto di lanciare Nmap come processo esterno non concede diritti di redistribuzione. Qualsiasi futuro pacchetto che incorpori Nmap/Npcap richiede una verifica separata dei termini applicabili alla versione distribuita.

La lingua di SCAPING riguarda l'interfaccia e i testi esplicativi dell'applicazione. Output di Nmap, banner ricevuti, nomi dei servizi e altri dati esterni conservano il contenuto originale e non vengono tradotti in base alla lingua dell'interfaccia.
