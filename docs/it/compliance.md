# Conformità e traccia di audit

Questa pagina mette in relazione la traccia di audit di CertMate con i regimi che gli operatori chiedono più spesso — l'AI Act dell'UE, NIS2 e ISO/IEC 42001 — quando lasciano che un agente IA/MCP gestisca i certificati su un calendario.

> **Da leggere prima.** CertMate è uno strumento MIT self-hosted a istanza singola. **Non** è un sistema di IA, **non** è un sistema di IA ad alto rischio, **non** è un'entità regolamentata e non "si conforma a" né "certifica" nulla. Gli obblighi di conformità ricadono sull'**operatore** che lo utilizza. Ciò che CertMate fornisce sono **artefatti probatori** che un operatore può usare per i *propri* obblighi. Ogni affermazione di seguito significa "consente all'operatore di dimostrare X", con i limiti esplicitamente indicati.

---

## Cosa fornisce la traccia di audit oggi

- **Attribution.** Ogni azione del ciclo di vita dei certificati — creazione, rinnovo, riemissione, deploy, attivazione/disattivazione del rinnovo automatico e rinnovi pianificati non presidiati — viene registrata con un `actor` strutturato (utente umano vs API token vs agente IA, fino all'ID della chiave API) e un `trigger` (manuale, API, agente o job dello scheduler). Le azioni di un agente IA sono distinguibili da quelle di un umano, a condizione che l'agente utilizzi una chiave con flag `is_agent`. Vedere [API: Audit Logging](./api.md#audit-logging) e la [guida MCP](./mcp.md#audit-attribution).
- **Prova di integrità.** Le voci vengono scritte in una hash chain SHA-256 in append-only (`data/audit/certificate_audit.chain.jsonl`). Qualsiasi modifica, eliminazione o riordinamento da parte di chi non può ricalcolare la chain è rilevabile e localizzabile.
- **Verifica indipendente.** Un verificatore autonomo (`python -m modules.core.audit_verify`) ricalcola la chain e restituisce PASS/FAIL senza dover eseguire o fidarsi di CertMate; `GET /api/audit/verify` espone lo stesso controllo tramite API.
- **Export firmato e verificabile da terze parti.** L'istanza firma la testa della chain (checkpoint periodici) e `GET /api/audit/export` produce un bundle firmato con Ed25519. Un revisore lo verifica al di fuori della macchina, fissando la chiave pubblica dell'istanza (`GET /api/audit/public-key`) fuori banda — dimostrando sia che il record non è stato modificato sia quale istanza lo ha prodotto.

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
- **Il troncamento in coda richiede un riferimento esterno.** La rimozione di voci dalla **fine** di una singola chain lascia una chain più corta ma internamente coerente che verifica comunque come integra. I checkpoint firmati e i bundle di export sono gli anchor per rilevare questo: un export firmato successivo con meno voci di uno precedente (o di un checkpoint in possesso di un revisore) rivela il troncamento. Un singolo export non può, da solo, provare che nulla è stato rimosso dalla fine — conservare export firmati successivi, oppure attendere l'ancoraggio esterno opzionale, se si necessita di questa garanzia.
- **L'header di sessione dell'agente è una dichiarazione del client.** Viene registrato per correlazione ma è fornito dal client; l'identità attendibile è la chiave API autenticata.
- **Limite storico.** La chain inizia quando la funzionalità viene abilitata per la prima volta; la cronologia `.log` precedente non fa parte della chain verificabile.

Gli export firmati che un revisore esterno può fissare a una chiave pubblica sono disponibili oggi. Se i tuoi obblighi richiedono di vincolare l'operatore *stesso* — in modo che nemmeno il detentore della chiave possa riscrivere la cronologia senza essere rilevato — è necessario l'ancoraggio esterno opzionale dei checkpoint firmati verso un sink append-only fuori dalla macchina, che è pianificato ma non ancora rilasciato. Verificarne lo stato prima di farvi affidamento.

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
