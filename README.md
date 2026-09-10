# SCAPING

Monitor ICMP e inventario delle porte per Windows, scritto in C++20 e API Win32. L'applicazione risiede nella system tray e non apre console o finestre all'avvio. Non contiene telemetria, controlli aggiornamenti, servizi Windows o runtime web.

## Requisiti e avvio

Windows 10 x64 versione 1809 o successiva; eseguibile GUI con runtime C/C++ statico in Release. La compatibilità effettivamente provata e le misure sono in [docs/VERIFICATION.md](docs/VERIFICATION.md).

Cartella obbligatoria e working directory: `D:\scaping`. Eseguibile: `D:\scaping\scaping.exe`. L'app imposta esplicitamente questa directory anche se avviata altrove e mostra un errore se non è disponibile.

```powershell
powershell -NoProfile -File D:\scaping\scripts\build.ps1
powershell -NoProfile -File D:\scaping\scripts\test.ps1 -SkipBuild
powershell -NoProfile -File D:\scaping\scripts\package.ps1 -SkipBuild
powershell -NoProfile -File D:\scaping\scripts\run.ps1
```

I comandi di build, test e packaging si eseguono dal checkout dei sorgenti. Per compilare: Visual Studio 2022 Build Tools, workload **Desktop development with C++**, MSVC x64, Windows SDK e **C++ CMake tools for Windows**. CMake minimo 3.24. Gli script rilevano anche il CMake incluso in Visual Studio. La build Release copia l'eseguibile nella radice del progetto; chiudere SCAPING prima di ricompilare. Debug rimane in `build\Debug`.

Il pacchetto ZIP in `dist` contiene solo eseguibile, istruzioni, esempio neutro e script di deployment/avvio. Non comprende configurazioni locali, report, simboli, Nmap o Npcap. Estrarre il pacchetto e usare `scripts\deploy.ps1` per copiarne l'eseguibile in `D:\scaping`; lo script rifiuta di sovrascrivere un eseguibile già presente.

## Tray e monitoraggio

Al primo avvio il quadrato è grigio, con tooltip **IP non configurato**. Non viene contattato alcun target predefinito. Windows decide se mostrare l'icona direttamente o nell'area delle icone nascoste; SCAPING non cambia questa preferenza.

| Colore | Ultimo tentativo ICMP completato |
| --- | --- |
| Verde | Risposta valida, RTT inferiore alla soglia |
| Arancione | Risposta valida, RTT uguale o superiore alla soglia |
| Rosso | Ping KO: timeout, risposta negativa o errore; non prova che il sistema sia spento |
| Grigio | IP assente, primo risultato in attesa o monitoraggio reinizializzato |

Clic destro: **Chiudi**, **Configura IP**, **Scansiona TUTTE le porte**. Doppio clic sinistro: configurazione. Un secondo avvio richiama l'istanza della stessa sessione utente. La chiusura delle finestre non termina il monitoraggio; **Chiudi** nella tray termina anche le attività possedute. L'icona viene ripristinata dopo il riavvio di Explorer.

Il ping usa `IcmpSendEcho2` asincrono, senza `ping.exe`. Un solo tentativo può essere in corso. Ogni configurazione ha una generazione: una risposta relativa alla generazione precedente non aggiorna il colore. Il cambio IP e la ripresa riavviano il monitoraggio. I risultati ping restano in memoria, senza scritture a ogni tentativo.

## Configurazione

IPv4 numerico singolo obbligatorio, per esempio il loopback `127.0.0.1` per un test sul proprio PC. URL, hostname, CIDR, liste, intervalli e argomenti non sono ammessi. Non è implementato IPv6.

Valori iniziali: intervallo 1000 ms, timeout 800 ms, soglia lenta 150 ms, avvio con Windows disattivato. La soglia deve essere inferiore al timeout. I limiti avanzati consentono di regolare concorrenza TCP e frequenza delle nuove connessioni, inizialmente 64 e 128 al secondo.

Configurazione locale versionata in `D:\scaping\data\config.ini`, salvata atomicamente. Un file non valido viene segnalato e non produce traffico verso valori non validati. L'avvio automatico è per il solo utente corrente, mediante la chiave Run di HKCU; è reversibile dalla stessa finestra e non richiede elevazione. L'esempio in `resources\config.example.ini` non contiene un target.

Lasciare vuoto **Percorso Nmap** per il rilevamento nelle directory di installazione; è disponibile la selezione manuale. L'app non cerca alla cieca un `nmap.exe` nella working directory o nel PATH.

## Scansione completa e limiti

Usare la scansione solo su sistemi che si è autorizzati a verificare. Ogni avvio è manuale e mantiene un'istantanea dell'IP: cambiare l'IP monitorato non reindirizza una scansione in corso. Un solo lavoro può essere attivo; clic successivi riportano in primo piano i risultati.

**TUTTE** significa 65.536 porte TCP e 65.536 UDP, includendo 0 e 65535. Nmap esegue una fase TCP e una UDP, una alla volta, con questi profili fissi, più `-oX` su un percorso assoluto locale e l'IP validato:

```text
TCP: -sT -n -Pn -p0-65535 -sV --version-light -T3 --reason --stats-every 2s
UDP: -sU -n -Pn -p0-65535 -sV --version-light -T3 --reason --stats-every 2s
```

`-Pn` consente la scansione anche quando il ping non risponde. `-sV` abilita il rilevamento di servizi/versioni; non vengono aggiunti script di vulnerabilità, brute force, `-A` o tentativi di autenticazione. La porta TCP 9100 rientra nella scansione porte, ma restano attive le esclusioni delle sonde di versione di Nmap per evitare stampe indesiderate: SCAPING non passa `--allports`.

Gli stati `open`, `closed`, `filtered` e `open|filtered` restano distinti. **Il silenzio UDP non significa porta chiusa**. Il rate limiting ICMP può rendere una scansione UDP completa molto lunga. Non viene garantita una durata e non si riducono di nascosto le porte o le fasi.

Copertura del port scanning e completamento del rilevamento servizi sono riportati separatamente. Una fase non eseguita, un errore o un annullamento producono un risultato **parziale**. Un risultato completo può comunque contenere stati incerti e servizi non identificati.

Servizio, prodotto, versione e informazioni extra provengono dall'XML Nmap; un nome convenzionale da tabella è distinto da un'identificazione basata sulla risposta. Un fingerprint Nmap non viene presentato come banner. Quando un dato non è disponibile, viene indicato come non identificato/non disponibile.

### Nmap assente: fallback TCP

Il ping continua normalmente. La scansione usa **Solo TCP — modalità ridotta**: Winsock non bloccante, concorrenza e velocità limitate, timeout distinti dagli errori locali. Il timeout di connessione TCP è almeno 3000 ms; se il timeout configurato è superiore viene usato quel valore. Questo evita che un rifiuto ritardato dallo stack Windows diventi prematuramente un esito incerto. Il timeout del ping resta quello configurato, inizialmente 800 ms. Il report indica il timeout TCP effettivo. Anche il fallback percorre 0..65535 con un contatore di almeno 32 bit. Non crea un thread per porta.

Sulle porte aperte viene tentata solo una lettura passiva del banner, al massimo 2048 byte e 300 ms; i byte non testuali sono rappresentati con escape. Non vengono inviate sonde applicative e non si simula il database Nmap. Un timeout resta incerto; errori locali non sono presentati come porte chiuse. Non esiste un falso fallback UDP: la copertura complessiva è dichiarata parziale.

### Risultati, annullamento e report

La finestra ridimensionabile contiene una textbox monospaziata multilinea, selezionabile e read-only, con scrollbar, più **Annulla scansione**, **Copia**, **Salva report**, **Chiudi finestra**. Output e fase si aggiornano a blocchi, con indicatore indeterminato quando manca una percentuale attendibile.

Il buffer UI è limitato; l'output completo viene conservato localmente in `data`. Stdout e stderr sono acquisiti senza bloccare il figlio. L'XML costituisce la fonte strutturata dei risultati ed è trattato come input non attendibile: dimensione limitata, parser senza entità esterne/rete, caratteri di controllo neutralizzati. I report possono contenere dati di rete sensibili e sono esclusi da Git.

Chiudere la finestra la nasconde. **Annulla scansione** ferma il lavoro reale e conserva quanto già acquisito. I processi di scansione appartengono a Job Objects con cleanup alla chiusura; il worker temporaneo non diventa un servizio.

## Privilegi e dipendenze esterne

Monitoraggio e UI funzionano senza amministratore. Nmap e Npcap sono opzionali per il ping e necessari, con i relativi permessi, per la scansione completa. Installazione, licenze e vincoli del worker sono descritti in [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md) e [docs/SECURITY.md](docs/SECURITY.md).

SCAPING non installa driver, non cambia firewall/antivirus e non modifica servizi o impostazioni globali. Se Npcap manca o i permessi non consentono UDP, l'app mantiene il ping e indica la capacità mancante. L'elevazione riguarda solo un worker temporaneo a profili fissi; un rifiuto UAC non termina il monitoraggio.

## Test e privacy

Test deterministici per IPv4, colori su risultati simulati, configurazione, intervallo completo delle porte, quoting, XML ostile/incompleto; prove reali limitate al loopback e listener controllati. Consultare il registro di verifica per sapere quali prove sono state effettivamente eseguite.

`scripts\measure.ps1 -ProcessId <PID> -Seconds 60` misura CPU normalizzata sul totale macchina e private bytes del solo residente. Le misure sono salvate in `data` e non includono processi Nmap.

Sorgenti, test e documentazione usano dati sintetici. `data`, `build`, `dist`, configurazioni reali, output Nmap, log, credenziali e metadati personali non vengono pubblicati. Nmap e Npcap non sono ridistribuiti.
