# Registro di verifica

[English](VERIFICATION.md) · [Italiano](VERIFICATION.it.md) · [README](../README.it.md)

## Base storica: versione 1.0.0

Ambiente, hash del binario, conteggi dei test, osservazioni desktop e misure delle sezioni seguenti si riferiscono alla **versione 1.0.0**. Sono conservati come base storica e non certificano l'aggiornamento linguistico 1.1.0. Questa base non dichiara nuovi risultati di test sulla localizzazione; eventuali risultati successivi devono indicare versione e controlli effettivamente eseguiti.

### Ambiente effettivo

Verifica eseguita il 10 settembre 2026 su **Windows 10 x64 build 19045**. Toolchain installata: Visual Studio Build Tools 2022 17.14, MSVC 19.44.35228, CMake 3.31.6-msvc6, Windows SDK 10.0.26100. Il nome del recente SDK non introduce una dipendenza dal runtime Windows 11. La versione minima dichiarata è Windows 10 1809; quella build minima non è stata provata separatamente.

Release x64 compilata con successo. Eseguibile finale della versione 1.0.0 di **563.712 byte**, SHA-256 `74b2316748251efede96bc5597a8aa4d41806f3333f4e09e2b4e0e98b8c39b49`. La verifica PE conferma **Windows GUI**, ASLR, NX e Control Flow Guard. Le importazioni sono DLL di Windows; nessuna DLL VC runtime dinamica, componente web o libreria di Nmap/Npcap è incorporata. Non sono stati rilevati riferimenti PDB, percorsi di profili personali o pattern di token nel binario.

### Test automatici effettivamente superati

`scripts\test.ps1 -SkipBuild`: **2 suite passate, 0 fallimenti**, 8,77 secondi nell'ultima esecuzione centralizzata della versione 1.0.0.

| Suite | Controlli | Contenuto |
| --- | ---: | --- |
| Core | 65.731 | IPv4 validi/invalidi e input ostili; colori ICMP simulati e soglia esatta; generazioni; configurazione atomica, corrotta e sostituzione fallita senza perdita; Unicode/sanitizzazione; round-trip del quoting Windows; profili Nmap fissi; XML completo, parziale, ostile, troppo grande e target errato; tutti i 65.536 valori di porta, inclusi 0 e 65535 |
| Networking | 56 | Ping ICMP reale al loopback con stop/ripresa; listener TCP controllati, banner testuali e binari, lettura passiva limitata; rifiuto TCP; timeout incerto ed errori locali distinti; limite finale 65535 senza overflow; cancellazione e avvii limitati; stdout/stderr; timeout e annullamento processi; Job con discendente terminato; rifiuto worker/nonce/PID/percorso non validi; Nmap assente, singola scansione e report parziale |

La prova iniziale di rifiuto TCP a 500 ms ha correttamente prodotto un timeout incerto: su questo Windows il rifiuto del listener locale non in ascolto arrivava dopo circa 2,1 secondi. Il test di rifiuto attende ora 4 secondi, e la produzione usa un minimo TCP di 3 secondi esplicitato nel report. Non è stata cambiata la semantica di timeout per far passare il test.

I test di rete automatici contattano esclusivamente il loopback e listener controllati. Le richieste worker invalide sono rifiutate prima di UAC. Non sono stati eseguiti scansioni esterne, installazioni di driver o cambi a firewall/servizi da parte della suite.

### Prove desktop effettive

- Eseguibile avviato da `C:\Windows` e mantenuto residente; nessuna console o finestra principale iniziale. La startup imposta e verifica `D:\scaping` come working directory.
- Secondo avvio: resta un solo processo residente e viene aperta **Scaping — Configura IP**. Controlli italiani e pulsanti rilevati tramite accessibilità.
- Finestra **Scaping — Risultati** osservata durante la prova manuale dell'utente, con riepilogo di annullamento parziale, textbox, scrollbar e pulsanti. La configurazione e i report inseriti dall'utente sono rimasti locali e non sono riprodotti qui.
- La build finale della versione 1.0.0 è stata copiata in `D:\scaping\scaping.exe` e avviata conservando la configurazione esistente. Nessun processo Nmap o worker di test è rimasto in esecuzione dopo le suite.

Lo strumento di screenshot Windows ha restituito `SetIsBorderRequired failed: Interfaccia non supportata (0x80004002)`. La lettura accessibile delle finestre ha funzionato; le azioni automatiche di input si sono sovrapposte a interazioni dell'utente e non costituiscono un collaudo UI completo. Non si dichiara quindi una verifica visiva pixel per pixel o di ogni clic del menu tray. Il riavvio dell'istanza di prova per aggiornare il binario è avvenuto tramite gestione del processo, non è una prova della voce **Chiudi**.

### Misure

Misura della **build finale Release 1.0.0**, dopo riavvio del residente, con monitoraggio ICMP configurato, finestre chiuse e nessuna scansione attiva: **60,895 secondi**, 4 processori logici. CPU media normalizzata sul totale macchina **0,0128%**. Private bytes medi **2.774.903** (circa **2,65 MiB**), massimi **2.859.008** (circa 2,73 MiB). Nessun processo di scansione incluso. In queste condizioni entrambi gli obiettivi iniziali (CPU sotto 0,5%, private bytes entro 30 MB) sono rispettati.

I risultati sono una misura su questo sistema, non una garanzia prestazionale per ogni macchina né una misura di versioni successive. I file di misura dettagliati restano in `data` e sono esclusi dal repository.

### Prove non eseguite nella verifica storica

Durante la verifica storica Nmap e Npcap non erano installati nell'ambiente: non sono state eseguite le due fasi reali complete 0..65535 TCP/UDP, il confronto dei profili con una versione Nmap installata, apertura dispositivi Npcap, consenso/rifiuto UAC reale o perdita IPC durante una scansione elevata reale. Le implementazioni erano presenti; la loro revisione e i test sintetici non sostituiscono tale collaudo.

Alla verifica storica restavano da provare sul desktop: riavvio reale di Explorer, sospensione/ripresa del PC, cambio IP con un ICMP realmente pendente, autostart al nuovo accesso, tutte le interazioni dei pulsanti e chiusura dalla tray durante una scansione reale. I controlli automatici di generazione, cancellazione e cleanup coprono la logica sottostante senza presentarsi come queste prove manuali.

Il residente può attendere il timeout dell'unico ICMP pendente prima dell'uscita finale, come spiegato in [Sicurezza](SECURITY.it.md). Nessuna scansione UDP completa è garantita breve; risultati `open|filtered` e servizi non identificati restano possibili anche con copertura completa.

## Verifica della versione 1.1.0

Verificata il 10 settembre 2026 nell'ambiente Windows 10 x64 e MSVC descritto sopra. L'eseguibile Release finale misura **595.968 byte**, SHA-256 `b66c18d8ebe72550f337699cbaf86a90e7c4ccbb3ba13cb89326904625d8c172`. L'ispezione PE ha confermato Windows GUI, ASLR, NX, Control Flow Guard e dipendenze esclusivamente da DLL Windows. Nessun percorso personale, pattern di segreti o riferimento PDB rilevato nel binario.

L'esecuzione centralizzata ha superato **4 suite, 0 errori**, in **14,32 secondi**: core e rete eseguiti sia in italiano sia in inglese. Ogni esecuzione core ha superato **65.762 controlli**; ogni esecuzione di rete **58 controlli**. I nuovi casi verificano migrazione dalla versione 1 senza cambiare valori o riscrivere il file alla lettura, salvataggio e lettura della lingua nella versione 2, rifiuto di lingue non valide/mancanti/duplicate, lingua iniziale senza target, diagnostica localizzata di validazione e XML, isolamento dei thread e conservazione della lingua della scansione mentre il chiamante la cambia. Superati in entrambe le lingue anche i controlli esistenti su loopback, processi, annullamento, XML e limiti delle porte. Il traffico dei test di rete è rimasto limitato al loopback.

La correzione finale delle spaziature è stata ricompilata correttamente. Le misure native GDI del testo al 100%, 125%, 150% e 200% hanno verificato che il suggerimento Nmap e l'etichetta della lingua rientrano nelle aree assegnate. Si tratta di una verifica delle dimensioni del testo, non di un'ispezione visiva completa tramite screenshot.

L'applicazione è stata aggiornata in `D:\scaping\scaping.exe` e avviata da `C:\Windows`. Un secondo avvio è terminato aprendo la configurazione dell'istanza esistente, con un solo processo residente. L'accessibilità ha rilevato il selettore nella finestra italiana e poi verificato, dopo il riavvio, la finestra inglese **Configure IP**, le etichette e i pulsanti **Browse…**, **Apply** e **Close**. Il file locale è stato aggiornato atomicamente alla versione 2 con `language=en`; il confronto ha confermato che tutti gli altri valori sono rimasti invariati. Nessun target reale o report locale è riprodotto qui.

Il clic automatico è fallito con `coordinate input geometry is unavailable`; l'input da tastiera non ha prodotto un cambio di focus verificato. La lingua è stata quindi impostata nel file locale a programma fermo. Il selettore è implementato e revisionato, ma non si dichiara riuscita una prova automatica di selezione e pressione di Applica. Resta anche il limite degli screenshot descritto sopra. I controlli e le finestre comuni gestiti da Windows possono seguire la lingua del sistema; output Nmap e dati ricevuti conservano il testo originale.

Per la versione 1.1.0 non sono state ripetute le misure delle prestazioni né eseguite scansioni complete con Nmap/Npcap o prove UAC reali. Le misure storiche e le prove manuali e di integrazione ancora da eseguire restano distinte dai risultati di localizzazione.
