# Verifica della versione 1.0.0

## Ambiente effettivo

Verifica eseguita il 10 settembre 2026 su **Windows 10 x64 build 19045**. Toolchain installata: Visual Studio Build Tools 2022 17.14, MSVC 19.44.35228, CMake 3.31.6-msvc6, Windows SDK 10.0.26100. Il nome del recente SDK non introduce una dipendenza dal runtime Windows 11. La versione minima dichiarata è Windows 10 1809; quella build minima non è stata provata separatamente.

Release x64 compilata con successo. Eseguibile finale di **563.712 byte**, SHA-256 `74b2316748251efede96bc5597a8aa4d41806f3333f4e09e2b4e0e98b8c39b49`. La verifica PE conferma **Windows GUI**, ASLR, NX e Control Flow Guard. Le importazioni sono DLL di Windows; nessuna DLL VC runtime dinamica, componente web o libreria di Nmap/Npcap è incorporata. Non sono stati rilevati riferimenti PDB, percorsi di profili personali o pattern di token nel binario.

## Test automatici effettivamente superati

`scripts\test.ps1 -SkipBuild`: **2 suite passate, 0 fallimenti**, 8,77 secondi nell'ultima esecuzione centralizzata.

| Suite | Controlli | Contenuto |
| --- | ---: | --- |
| Core | 65.731 | IPv4 validi/invalidi e input ostili; colori ICMP simulati e soglia esatta; generazioni; configurazione atomica, corrotta e sostituzione fallita senza perdita; Unicode/sanitizzazione; round-trip del quoting Windows; profili Nmap fissi; XML completo, parziale, ostile, troppo grande e target errato; tutti i 65.536 valori di porta, inclusi 0 e 65535 |
| Networking | 56 | Ping ICMP reale al loopback con stop/ripresa; listener TCP controllati, banner testuali e binari, lettura passiva limitata; rifiuto TCP; timeout incerto ed errori locali distinti; limite finale 65535 senza overflow; cancellazione e avvii limitati; stdout/stderr; timeout e annullamento processi; Job con discendente terminato; rifiuto worker/nonce/PID/percorso non validi; Nmap assente, singola scansione e report parziale |

La prova iniziale di rifiuto TCP a 500 ms ha correttamente prodotto un timeout incerto: su questo Windows il rifiuto del listener locale non in ascolto arrivava dopo circa 2,1 secondi. Il test di rifiuto attende ora 4 secondi, e la produzione usa un minimo TCP di 3 secondi esplicitato nel report. Non è stata cambiata la semantica di timeout per far passare il test.

I test di rete automatici contattano esclusivamente il loopback e listener controllati. Le richieste worker invalide sono rifiutate prima di UAC. Non sono stati eseguiti scansioni esterne, installazioni di driver o cambi a firewall/servizi da parte della suite.

## Prove desktop effettive

- Eseguibile avviato da `C:\Windows` e mantenuto residente; nessuna console o finestra principale iniziale. La startup imposta e verifica `D:\scaping` come working directory.
- Secondo avvio: resta un solo processo residente e viene aperta **Scaping — Configura IP**. Controlli italiani e pulsanti rilevati tramite accessibilità.
- Finestra **Scaping — Risultati** osservata durante la prova manuale dell'utente, con riepilogo di annullamento parziale, textbox, scrollbar e pulsanti. La configurazione e i report inseriti dall'utente sono rimasti locali e non sono riprodotti qui.
- La build finale è stata copiata in `D:\scaping\scaping.exe` e avviata conservando la configurazione esistente. Nessun processo Nmap o worker di test è rimasto in esecuzione dopo le suite.

Lo strumento di screenshot Windows ha restituito `SetIsBorderRequired failed: Interfaccia non supportata (0x80004002)`. La lettura accessibile delle finestre ha funzionato; le azioni automatiche di input si sono sovrapposte a interazioni dell'utente e non costituiscono un collaudo UI completo. Non si dichiara quindi una verifica visiva pixel per pixel o di ogni clic del menu tray. Il riavvio dell'istanza di prova per aggiornare il binario è avvenuto tramite gestione del processo, non è una prova della voce **Chiudi**.

## Misure

Misura della **build finale Release**, dopo riavvio del residente, con monitoraggio ICMP configurato, finestre chiuse e nessuna scansione attiva: **60,895 secondi**, 4 processori logici. CPU media normalizzata sul totale macchina **0,0128%**. Private bytes medi **2.774.903** (circa **2,65 MiB**), massimi **2.859.008** (circa 2,73 MiB). Nessun processo di scansione incluso. In queste condizioni entrambi gli obiettivi iniziali (CPU sotto 0,5%, private bytes entro 30 MB) sono rispettati.

I risultati sono una misura su questo sistema, non una garanzia prestazionale per ogni macchina. I file di misura dettagliati restano in `data` e sono esclusi dal repository.

## Prove ancora da eseguire

Nmap e Npcap non sono installati nell'ambiente: non sono state eseguite le due fasi reali complete 0..65535 TCP/UDP, il confronto dei profili con una versione Nmap installata, apertura dispositivi Npcap, consenso/rifiuto UAC reale o perdita IPC durante una scansione elevata reale. Le implementazioni sono presenti; la loro revisione e i test sintetici non sostituiscono tale collaudo.

Restano da provare sul desktop: riavvio reale di Explorer, sospensione/ripresa del PC, cambio IP con un ICMP realmente pendente, autostart al nuovo accesso, tutte le interazioni dei pulsanti e chiusura dalla tray durante una scansione reale. I controlli automatici di generazione, cancellazione e cleanup coprono la logica sottostante senza presentarsi come queste prove manuali.

Il residente può attendere il timeout dell'unico ICMP pendente prima dell'uscita finale, come spiegato in `SECURITY.md`. Nessuna scansione UDP completa è garantita breve; risultati `open|filtered` e servizi non identificati restano possibili anche con copertura completa.
