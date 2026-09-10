# Confini di sicurezza e ciclo di vita

## Resident e input

Il manifest richiede `asInvoker`. La UI e il ping non richiedono amministratore. L'IP è un singolo IPv4 numerico validato; non sono ammessi host, subnet, liste o comandi. Il target di ogni scansione è una copia della configurazione al momento dell'avvio.

I figli Nmap usano `CreateProcessW` con eseguibile assoluto e quoting Windows degli argomenti; il worker temporaneo viene avviato con `ShellExecuteExW` e verbo `runas`. Nessun comando passa da shell, `system()`, `cmd.exe` o PowerShell. I profili non accettano opzioni aggiuntive dall'IPC o dalla configurazione.

Il percorso Nmap manuale viene verificato come file PE locale chiamato `nmap.exe`, e interrogato con `--version`. Scegliere un eseguibile significa autorizzarne l'esecuzione con i propri privilegi. Il rilevamento automatico usa solo `Program Files\Nmap`, verificando l'installazione protetta; non cerca nella working directory o nel PATH.

L'XML viene letto entro un limite di 64 MiB da una copia immutabile. Il solo DOCTYPE inerte esatto emesso normalmente da Nmap viene rimosso; tutte le altre dichiarazioni DTD/entità sono rifiutate. XmlLite ha DTD proibiti e resolver nullo. Sono limitati profondità, attributi e risultati; protocolli, porte, conteggi, target e fine positiva sono verificati prima di dichiarare copertura completa.

Stdout/stderr e banner non attendibili sono neutralizzati per la visualizzazione. Un banner passivo non diventa automaticamente un'identificazione di servizio. L'output originale e i report restano in `data`; i buffer UI e IPC sono limitati.

## Worker UAC temporaneo

Il worker esiste solo per una fase che richiede privilegi. Accetta PID/tempo di creazione del padre e nonce; dal canale riceve esclusivamente una richiesta versionata con IPv4 e profilo fisso. Non riceve percorsi eseguibili, percorsi di scrittura o argomenti liberi.

Il canale named pipe usa nonce casuale, ACL del solo utente corrente, rifiuta connessioni remote e verifica i PID dei peer. Il worker controlla che il padre sia vivo, abbia lo stesso SID e lo stesso percorso eseguibile, oltre al tempo di creazione del processo. La connessione usa un livello SQOS che impedisce al server non elevato di impersonare il token elevato.

L'elevazione richiede il token amministrativo dello **stesso utente**. Un consenso fornito con credenziali di un diverso account amministratore è intenzionalmente rifiutato. L'app non cambia l'account o riduce queste verifiche.

Nmap elevato è selezionato nuovamente dal worker solo nella directory predefinita protetta. Proprietario e DACL di directory, eseguibile e file dell'installazione devono essere amministrativi; reparse point e ACL non verificabili sono rifiutati. Una firma presente ma non valida viene rifiutata. Un Nmap non firmato installato da un amministratore può essere accettato sulla base dell'intero albero protetto da ACL; non si presenta tale verifica come una firma digitale.

Il worker costruisce un ambiente ridotto, scrive XML in una directory amministrativa temporanea privata e lo restituisce a frame limitati. È il padre non elevato a salvare il report richiesto, evitando scritture privilegiate verso percorsi forniti dall'utente.

Ogni figlio viene creato sospeso, assegnato a un Job Object con `KILL_ON_JOB_CLOSE` e quindi avviato. La lista degli handle ereditati è esplicita. Il worker controlla la vita del padre e la connessione IPC: annullamento, disconnessione o uscita del padre terminano il Job e i figli. Un consenso UAC lasciato senza risposta non blocca la chiusura della UI: il lancio usa stato condiviso isolato e, se il consenso arriva tardi, il worker deve ancora trovare padre e pipe originali validi prima di procedere.

## Limiti espliciti

- Npcap viene interrogato, non installato o avviato dall'app. La disponibilità del servizio non garantisce il permesso di aprire un dispositivo; l'esito di Nmap resta determinante.
- Rifiuto UAC, dipendenza assente, XML non valido o fase fallita producono stato parziale. Nessun esito UDP viene ricavato dal silenzio di un socket nativo.
- Non esiste una cancellazione ICMP documentata usata da SCAPING: dopo **Chiudi** il processo può attendere il timeout residuo dell'unico ping pendente (800 ms iniziali, fino al limite configurato di 60 s). Tray e finestre sono rimosse e la scansione viene annullata; buffer/handle ICMP restano validi fino al completamento del sistema operativo.
- Il programma non promette anonimato dell'account Git proprietario. La protezione riguarda contenuti, configurazioni, metadati di commit e pacchetti.

## Revisione prima della pubblicazione

Usare `scripts\privacy-check.ps1` dopo lo staging. Con `-GitleaksPath <percorso>` vengono controllati anche diff staged e cronologia mediante Gitleaks. Verificare comunque a mano file tracciati, metadati autore/committer e allow-list del pacchetto. Non aggiungere configurazioni, report, output di test locali o conversazioni al repository.
