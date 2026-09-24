# Conformità e traccia di audit

<!-- CERTMATE-TRANSLATED-FROM 0ddda303c6fe494a -->

Questa pagina mette in relazione la traccia di audit di CertMate con i regimi che gli operatori chiedono più spesso — l'AI Act dell'UE, NIS2 e ISO/IEC 42001 — quando lasciano che un agente IA/MCP gestisca i certificati su un calendario.

> **Da leggere prima.** CertMate è uno strumento MIT self-hosted a istanza singola. **Non** è un sistema di IA, **non** è un sistema di IA ad alto rischio, **non** è un'entità regolamentata e non "si conforma a" né "certifica" nulla. Gli obblighi di conformità ricadono sull'**operatore** che lo utilizza. Ciò che CertMate fornisce sono **artefatti probatori** che un operatore può usare per i *propri* obblighi. Ogni affermazione di seguito significa "consente all'operatore di dimostrare X", con i limiti esplicitamente indicati.

---

## Cosa fornisce la traccia di audit oggi

- **Attribution.** Ogni azione del ciclo di vita dei certificati — creazione, rinnovo, riemissione, deploy, attivazione/disattivazione del rinnovo automatico e rinnovi pianificati non presidiati — viene registrata con un `actor` strutturato (utente umano vs API token vs agente IA, fino all'ID della chiave API) e un `trigger` (manuale, API, agente o job dello scheduler). Le azioni di un agente IA sono distinguibili da quelle di un umano, a condizione che l'agente utilizzi una chiave con flag `is_agent`. Vedere [API: Audit Logging](./api.md#audit-logging) e la [guida MCP](./mcp.md#attribuzione-audit).
- **Prova di integrità.** Le voci vengono scritte in una hash chain SHA-256 in append-only (`data/audit/certificate_audit.chain.jsonl`). Qualsiasi modifica, eliminazione o riordinamento da parte di chi non può ricalcolare la chain è rilevabile e localizzabile.
- **Verifica indipendente.** Un verificatore autonomo (`python -m modules.core.audit_verify`) ricalcola la chain e restituisce PASS/FAIL senza dover eseguire o fidarsi di CertMate; `GET /api/audit/verify` espone lo stesso controllo tramite API e, quando la firma è abilitata, confronta anche la chain con l'ultimo checkpoint firmato — così un troncamento in coda o una riscrittura fino a quel checkpoint compreso fa fallire la verifica (vedi "troncamento in coda" nei Limiti onesti).
- **Export firmato e verificabile da terze parti.** L'istanza firma la testa della chain (checkpoint periodici) e `GET /api/audit/export` produce un bundle firmato con Ed25519. Un revisore lo verifica al di fuori della macchina, fissando la chiave pubblica dell'istanza (`GET /api/audit/public-key`) fuori banda — dimostrando sia che il record è stato scritto e non modificato, sia quale istanza lo ha prodotto. Quell'endpoint restituisce JSON, non un file PEM: salva il suo campo `public_key_pem` come il `.pem` che `--pubkey` del verificatore si aspetta. Risponde 404 quando l'istanza non ha una chiave di firma.
- **Sink di audit per SIEM (push).** Ogni voce di audit può anche essere inviata in tempo reale a un collettore esterno in un formato standard — **syslog** (RFC 5424) o **CEF** su UDP/TCP, oppure **HTTP/JSON generico** — configurato in `audit_sink` nelle impostazioni. Le voci passano dal sanitizzatore di credenziali e segreti prima di lasciare il processo (un token in un campo di dettaglio viene oscurato), e il sink è isolato dai guasti con un timeout breve, come la hash chain: un collettore irraggiungibile non blocca né interrompe mai un'operazione sui certificati. La copertura del ciclo di vita include creazione / rinnovo / deploy / revoca, e il riepilogo periodico (digest): è una voce di audit, quindi passa dal sink come tutte le altre. Registra l'esito, per quanti destinatari era e i conteggi che riportava — **non i destinatari stessi**, che sono dati personali e questa chain non può più toglierli. Un digest saltato perché le notifiche o l'SMTP sono spenti non scrive nulla: a quello rispondono le impostazioni, e una voce settimanale che lo dice farebbe crescere la chain all'infinito per non dire niente.

---

## Corrispondenza con i regimi

### NIS2 (Direttiva (UE) 2022/2555) — la corrispondenza più forte

- **A cosa aiuta.** Le operazioni sui certificati modificano la postura di fiducia dei servizi, quindi sono eventi rilevanti per la sicurezza. CertMate produce un record infalsificabile, attribuito e con timestamp di ogni operazione, oltre a una verifica indipendente — utilizzabile come parte delle pratiche di logging (Art. 21) e di documentazione degli incidenti (Art. 23) dell'operatore.
- **Limite.** NIS2 vincola le **entità** essenziali/importanti, non gli strumenti software. CertMate fornisce log e un verificatore che l'operatore può usare; non valuta, monitora né segnala incidenti, e l'essere un'entità in perimetro (e rispettare NIS2 nella sua totalità) è responsabilità dell'operatore.

### AI Act UE — Articolo 50 trasparenza (solo nello spirito; la corrispondenza più debole)

- **A cosa aiuta.** Quando un agente IA gestisce la PKI in modo autonomo, il record porta un marcatore esplicito `actor.kind="agent"` più la sessione dell'agente, permettendo all'operatore di dimostrare a posteriori quali modifiche sono state effettuate da un agente IA rispetto a un umano, sotto quale identità e con quale trigger — a supporto dello spirito di trasparenza e supervisione umana dell'Atto.
- **Limite.** Gli obblighi dell'Art. 50 ricadono sui **fornitori/deployer di sistemi di IA** e riguardano la divulgazione alle persone fisiche che interagiscono con l'IA. Un agente che rinnova certificati TLS non è un caso tipico dell'Art. 50, e CertMate è uno strumento, non un sistema di IA. Ci allineiamo solo allo spirito di trasparenza; CertMate **non** soddisfa l'Art. 50 per conto di nessuno.

### ISO/IEC 42001 (Sistema di gestione dell'IA) — registrazioni operative

- **A cosa aiuta.** I record attribuiti e infalsificabili costituiscono prove oggettive che un agente IA ha eseguito specifiche azioni sui certificati — utilizzabili per i controlli di registrazione operativa e tracciabilità del proprio AIMS dell'operatore.
- **Limite.** ISO 42001 certifica il sistema di gestione di un'organizzazione, non uno strumento. CertMate non è certificato ISO 42001 e non può certificare l'operatore; produce record che l'operatore può presentare come prova per i propri controlli.

---

## Limiti onesti (non interpretare in modo eccessivo)

- **La chiave di firma non vincola l'operatore.** Un bundle di export firmato (e i checkpoint periodici firmati) consentono a una terza parte di verificare, al di fuori della macchina, quale istanza ha prodotto il record e che non è stato modificato — per chiunque **non** detenga la chiave di firma. Ma l'operatore detiene la chiave e potrebbe ri-firmare una chain riscritta. Vincolare completamente l'operatore richiede l'invio dei checkpoint firmati verso un sink esterno in append-only (**ancoraggio esterno opzionale — una funzionalità pianificata, non ancora rilasciata**). Considerare la garanzia attuale come "autenticità, ordinamento e attribuzione all'istanza delle voci registrate", verificabile in modo indipendente da una terza parte che detiene una copia firmata esportata.
- **Autenticità, non completezza.** Le scritture di audit sono best-effort e non bloccano mai un'operazione sui certificati; la chain prova che le voci registrate sono autentiche e ordinate, e un `seq` mancante all'interno prova un'eliminazione, ma una scrittura che ha fallito prima di essere registrata non lascia alcuna voce da verificare.
- **Il troncamento in coda viene rilevato fino all'ultimo checkpoint firmato.** La rimozione di voci dalla **fine** della chain lascia una chain più corta ma internamente coerente. `GET /api/audit/verify` ora confronta la chain con il checkpoint firmato più recente che verifica con la chiave dell'istanza, quindi qualsiasi troncamento, riavvolgimento o riscrittura **fino a** quel checkpoint compreso fa fallire la verifica — i checkpoint, prima solo scritti, ora vengono riletti. La coda viene **sigillata a uno spegnimento pulito**: quanto è stato scritto dall'ultimo checkpoint viene firmato in uscita, quindi un container che si ferma normalmente non lascia nulla di non attestato. Restano due lacune: (a) un **crash**, un `SIGKILL` o una mancanza di corrente si fermano prima, e in quel caso le voci dall'ultimo checkpoint possono ancora essere eliminate senza che ce ne si accorga finché il successivo non le sigilla — ridotta da «ogni arresto» a «un arresto sporco», non chiusa; e (b) un operatore che detiene la chiave di firma può firmare un nuovo checkpoint su una chain riscritta. Conservare export firmati successivi, oppure attendere l'ancoraggio esterno opzionale, se si ha bisogno di chiuderle.
- **L'header di sessione dell'agente è una dichiarazione del client.** Viene registrato per correlazione ma è fornito dal client; l'identità attendibile è la chiave API autenticata.
- **Le azioni di primo avvio sono attribuite a `setup_user`.** Finché il setup non è completo un'istanza serve ogni richiesta come admin, quindi non c'è un'identità reale da registrare e la catena lo dice apertamente. Una voce come `create` / `user` / `setup_user` significa che quell'utente è stato creato mentre chiunque riuscisse a raggiungere l'istanza era admin. Su una versione attuale solo il primo admin può nascere così — un secondo utente o una chiave API vengono rifiutati — quindi ci si aspetta esattamente una voce di questo tipo. Più di una significa che l'istanza è stata avviata con una versione precedente, e ogni utente oltre il primo va confermato o rimosso. Le chiavi API coniate in quella finestra sono segnalate nella pagina Chiavi API e aspettano l'operatore; gli utenti non lo sono, e per loro la risposta sta nella catena.
- **Limite storico.** La chain inizia quando la funzionalità viene abilitata per la prima volta; la cronologia `.log` precedente non fa parte della chain verificabile.
- **Una chain potata prova meno, e lo dice.** Se hai eseguito `audit_prune` (sotto), la verifica copre le voci dall'anchor in avanti. Il prefisso archiviato è attestato dall'anchor firmato e dal bundle esportato che conservi fuori dalla macchina — non dal file della chain. `verify` riporta `anchored` e il seq dell'anchor proprio per questo; considera un semplice "integra" riferito a un'istanza potata come un'esagerazione.

## Conservazione: archiviare parte della chain

La chain cresce di una riga per ogni operazione registrata — nell'ordine delle centinaia di kilobyte all'anno su un'istanza molto usata — quindi la maggior parte degli operatori non ne ha mai bisogno. Esiste per il caso in cui una policy di conservazione richieda che i record più vecchi lascino la macchina.

Non c'è potatura automatica, e non c'è un endpoint API per farla. Cancellare la cronologia di audit è esattamente ciò che vorrebbe fare chi ha appena compromesso un account amministratore, e un operatore con un obbligo di conservazione legittimo ha comunque accesso alla shell — l'archivio deve pur metterlo da qualche parte. Quindi è un unico comando esplicito, da eseguire con CertMate fermo:

```bash
# 1. Esporta il prefisso che intendi archiviare (token admin).
curl -H "Authorization: Bearer $TOKEN" \
     "https://certmate.example.com/api/audit/export?to_seq=1199" > archive-0-1199.json

# 2. Verificalo FUORI da questa macchina, fissando la chiave dell'istanza.
python -m modules.core.audit_verify --bundle archive-0-1199.json --pubkey instance.pem

# 3. Conservalo dove dice la tua policy. Poi, con CertMate fermo:
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit --yes
```

Il comando senza `--yes` è una prova a secco. Rifiuta, e non rimuove nulla, se il bundle non verifica, non è firmato, è vuoto, non è un prefisso di *questa* chain o non coincide con la chain a un qualsiasi seq, oppure se la potatura lascerebbe la chain senza voci dopo il prefisso archiviato — non cancelli mai record la cui unica copia rimasta non è verificata, e non ti ritrovi mai con una chain in cui non resta nulla da verificare.

Rifiuta anche se `--key-dir` non contiene alcuna chiave di firma, o ne contiene una che appartiene a un'istanza diversa da quella che ha esportato il bundle. Entrambi i controlli avvengono **prima** che venga rimosso qualcosa: un anchor firmato con la chiave sbagliata è un anchor che la verifica dell'istanza stessa rifiuta, e scoprirlo dopo che i record non ci sono più è troppo tardi per servire a qualcosa.

Punta `--key-dir` alla chiave dell'istanza. Il valore predefinito è `data` (relativo alla directory da cui esegui il comando) e deve contenere la `.audit_signing_key` dell'istanza, a meno che `AUDIT_SIGNING_KEY_FILE` non sia impostata come la imposta l'istanza. Lo strumento non crea mai una chiave qui: una chiave nuova sarebbe una nuova identità d'istanza, non quella di questa istanza.

Ciò che fa poi è la parte che conta per la conformità:

- **La cancellazione viene registrata nella chain che le sopravvive.** Viene aggiunta una voce `archive` che indica l'intervallo di seq, il numero di voci, il loro hash di testa e lo SHA-256 del file di archivio. Chi legge la chain potata può vedere che delle voci sono state rimosse, quando, e quale archivio le contiene.
- **Il resto verifica a partire da un anchor firmato.** `certificate_audit.anchor.json` dichiara dove inizia ora la chain e da cosa prosegue, firmato con la chiave dell'istanza, così una chain semplicemente troncata non può essere spacciata per una potata — l'anchor non si può falsificare senza la chiave.
- **Resta onesta anche dopo.** La verifica di una chain potata non riporta mai un semplice "integra": sia l'API sia il verificatore autonomo dicono da quale seq parte la garanzia.

Due limiti da dire. L'anchor descrive l'archivio **più recente**; la cronologia completa è la sequenza dei bundle esportati, ed è per questo che vanno conservati e che il digest di ciascuno è registrato nella chain. E, come ovunque in questa pagina, la chiave dell'istanza non vincola l'operatore: chi la detiene può firmare un anchor su una chain che ha riscritto. Pota solo fin dove arrivano davvero i tuoi archivi.

Gli export firmati che un revisore esterno può fissare a una chiave pubblica sono disponibili oggi. Se i tuoi obblighi richiedono di vincolare l'operatore *stesso* — in modo che nemmeno il detentore della chiave possa riscrivere la cronologia senza essere rilevato — è necessario l'ancoraggio esterno opzionale dei checkpoint firmati verso un sink append-only fuori dalla macchina, che è pianificato ma non ancora rilasciato. Verificarne lo stato prima di farvi affidamento.

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
