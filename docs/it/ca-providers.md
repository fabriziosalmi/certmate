# Fornitori di Certificate Authority (CA)

<!-- CERTMATE-TRANSLATED-FROM b5fbaa66b65585c0 -->

CertMate supporta diversi fornitori di Certificate Authority, consentendoti di scegliere la CA più adatta alle tue esigenze.

---

## Fornitori CA supportati

### Let's Encrypt (Predefinito)

- **Tipo**: Certificati SSL gratuiti e automatizzati
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: No
- **Ideale per**: Sviluppo, piccole imprese, progetti personali

**Configurazione:**
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

**Profili:** `classic` (90 giorni, il predefinito), `tlsserver` (45 giorni) e
`shortlived` (160 ore), in produzione e in staging. Un certificato ne richiede
uno con `acme_profile`, e un account CA può indicarne uno predefinito per i
certificati creati su di esso; vedi [Profili ACME](../api.md#acme-profiles).
Nella dashboard: **ACME Profile** nelle opzioni avanzate del modulo di creazione
(Edit & Reissue si apre sul profilo del certificato stesso), e **Default ACME
profile** nel modulo dell'account CA. Il pannello del certificato mostra il suo
profilo e quando si rinnova.

### Let's Encrypt (Staging)

- **Tipo**: Certificati di test dall'ambiente di staging di Let's Encrypt
- **Tipi di certificati**: Domain Validation (DV) — NON riconosciuti dai browser
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: No
- **Ideale per**: Validare la configurazione DNS, il deployment e il rinnovo senza consumare i rate limit di produzione

Lo staging è una voce di Certificate Authority separata (dalla v2.12.0), non un flag per singolo certificato: selezionala come CA durante la creazione di un certificato, oppure impostala come CA predefinita durante i test. L'email utilizza come fallback l'email dell'account Let's Encrypt quando lasciata vuota. La conversione di un certificato di staging in produzione richiede una riemissione con la CA di produzione.

### ZeroSSL

- **Tipo**: Certificati DV gratuiti da 90 giorni
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: Sì

**Requisiti di configurazione:**
- **URL directory ACME**: `https://acme.zerossl.com/v2/DV90` (fisso, preconfigurato)
- **EAB Key ID**: Dalla Developer Dashboard di ZeroSSL
- **EAB HMAC Key**: Dalla Developer Dashboard di ZeroSSL
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

### Google Trust Services

- **Tipo**: Certificati DV gratuiti
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: Sì

**Requisiti di configurazione:**
- **URL directory ACME**: `https://dv.acme-v02.api.pki.goog/directory` (fisso, preconfigurato)
- **EAB Key ID**: Dal tuo progetto Google Cloud
- **EAB HMAC Key**: Dal tuo progetto Google Cloud
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

### DigiCert ACME

- **Tipo**: Certificati SSL di livello enterprise
- **Tipi di certificati**: DV, OV, EV
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: Sì
- **Ideale per**: Ambienti enterprise, applicazioni commerciali

**Requisiti di configurazione:**
- **URL directory ACME**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
  — è il valore predefinito, ed è **regionale**. Un account fuori dalla regione
  predefinita ha un proprio URL di directory, mostrato in CertCentral: inseriscilo
  qui e l'emissione lo usa. Lasciato com'è, viene usato il predefinito. Deve
  essere `https`.
- **EAB Key ID**: Fornito da DigiCert
- **EAB HMAC Key**: Fornita da DigiCert
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

### Actalis

- **Tipo**: Certificati DV gratuiti da 90 giorni di una CA europea (italiana)
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: No (non disponibile tramite ACME)
- **EAB Richiesto**: Sì
- **Ideale per**: Utenti UE che desiderano un'alternativa europea a Let's Encrypt, ambienti dell'ecosistema eIDAS

**Requisiti di configurazione:**
- **URL directory ACME**: `https://acme-api.actalis.com/acme/directory` (fisso, preconfigurato)
- **EAB Key ID**: Dall'area clienti Actalis
- **EAB HMAC Key**: Dall'area clienti Actalis
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

**Limiti del piano gratuito:**
- Solo certificati a dominio singolo — una richiesta con voci SAN viene rifiutata con
  `Your account only grants single-domain 90-days DV certificates`
- Validità di 90 giorni
- Nessun certificato wildcard (i piani SAN a pagamento coprono fino a 5 hostname)

### SSL.com

- **Tipo**: Certificati commerciali
- **Tipi di certificati**: DV, OV, EV
- **Supporto Wildcard**: Sì
- **EAB Richiesto**: Sì

**Requisiti di configurazione:**
- **URL directory ACME**: `https://acme.ssl.com/sslcom-dv-rsa` (fisso, preconfigurato)
- **EAB Key ID**: Fornito da SSL.com
- **EAB HMAC Key**: Fornita da SSL.com
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

### Sectigo

- **Tipo**: CA ACME pubblica/commerciale tramite Sectigo Certificate Manager (SCM)
- **Tipi di certificati**: DV, OV (a seconda dell'account/profilo SCM selezionato)
- **Supporto Wildcard**: Sì, quando consentito dall'account/profilo SCM
- **EAB Richiesto**: Sì
- **URL directory ACME**: Copia l'URL HTTPS dai dettagli dell'account ACME in SCM; è specifico dell'account
- **EAB Key ID / KID e HMAC Key**: Copiali dai dettagli dell'account ACME in SCM
- **Email**: Contatto dell'account ACME (vedi [Email dell'account](#email-dellaccount))

Esempio di configurazione di test (l'URL è **solo un esempio**, non un endpoint universale):

```json
{
  "ca_provider": "sectigo",
  "config": {
    "acme_url": "https://acme.sectigo.com/v2/OV",
    "eab_kid": "your-sectigo-key-id",
    "eab_hmac": "your-sectigo-hmac-key",
    "email": "admin@example.com"
  }
}
```

Per più account, configura `ca_providers.sectigo.accounts` nelle impostazioni,
dove ogni account ha i propri `acme_url`, `eab_kid`, `eab_hmac` ed `email`.
Seleziona un account con `ca_account_id` nell'API di creazione del certificato;
se omesso, CertMate usa `default_ca_accounts.sectigo` o il primo account
configurato. Il rinnovo riutilizza l'account CA registrato. DNS-01 (incluso
Custom Script) e HTTP-01 restano disponibili; SCM potrebbe aver già autorizzato
il dominio richiesto. Per un account SCM che autorizza già **ogni** nome
richiesto, seleziona **Sectigo → Sectigo (already authorized in SCM)** come tipo
di challenge del certificato. In questa modalità CertMate non configura la
validazione DNS o HTTP, e si può richiedere un wildcard se quell'account/profilo
SCM lo autorizza. Certbot usa il suo authenticator manuale con un hook che non
pubblica nulla solo per soddisfare il proprio requisito di esecuzione non
interattiva: quando la CA restituisce autorizzazioni ACME valide, l'hook non
viene mai chiamato. Se SCM restituisce un'autorizzazione in sospeso (pending),
l'hook non pubblica alcun materiale di validazione, quindi CertMate non può
soddisfarla in questa modalità. Usa DNS-01 o HTTP-01 quando i nomi non sono già
autorizzati. Al rinnovo, SCM deve autorizzare ancora i nomi per quell'account.
Questa modalità è disponibile solo quando Sectigo è selezionata esplicitamente come CA.
Le configurazioni Sectigo esistenti sotto CA Privata continuano a funzionare senza modifiche.

### CA Privata

- **Tipo**: Certificate Authority interna/aziendale
- **Tipi di certificati**: Privati/Interni
- **Supporto Wildcard**: Sì (dipende dall'implementazione della CA)
- **EAB Richiesto**: Facoltativo
- **Ideale per**: Reti interne, ambienti aziendali, sistemi isolati (air-gapped)

**Software compatibili:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Altre CA private compatibili con ACME

**Utilizzo di una CA ACME pubblica tramite la voce CA Privata:**

La voce CA Privata è anche la via d'uscita generica per qualsiasi CA ACME priva di una voce dedicata in CertMate: puntala all'URL della directory della CA e, se la CA impone il binding dell'account, compila l'EAB Key ID e la HMAC Key facoltativi. Ad esempio, Actalis funziona sia tramite la sua voce dedicata (consigliato) sia come CA Privata con:

- **URL directory ACME**: `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key**: dall'area clienti Actalis
- **Certificato CA**: lasciare vuoto (root di fiducia pubblici)

---

## Configurazione

### Tramite interfaccia Web

1. Vai su **Impostazioni**
2. Scorri fino a **Fornitori di Certificate Authority (CA)**
3. Clicca su **Add CA Account**, scegli la CA e dai un nome all'account
   (lettere, cifre, punti, trattini e trattini bassi)
4. Configura i campi obbligatori
5. Clicca su **Test CA Connection** per controllare i campi
6. Clicca su **Save Account**

**Test CA Connection** contatta la CA solo per una CA Privata: scarica l'URL
della directory ACME (usando il certificato CA, se indicato). Per tutte le altre
CA controlla che i campi obbligatori siano compilati (e, per DigiCert, che le
credenziali EAB non siano troppo corte per essere plausibili) senza contattare
la CA, quindi un test superato non dimostra che le credenziali funzionino. Lo
dimostra la prima emissione.

### Email dell'account

Per una nuova emissione Certbot usa l'email dell'account CA selezionato, e
ripiega sull'impostazione globale `email` quando l'account non ne ha una.
L'email globale resta obbligatoria per l'emissione. Cambiare l'email di un
account non aggiorna un account ACME già registrato da Certbot: per cambiare
quel contatto usa `certbot update_account`.

### CA predefinita vs. CA per certificato

Impostazioni → Fornitori CA elenca gli account CA (ad esempio, due email Let's
Encrypt o due account Sectigo SCM). **Add CA Account** apre il modulo
dell'account; **Edit** lo riapre. Seleziona **Default for this CA** su un solo
account per fornitore; **Make global default** sceglie anche il fornitore usato
per i nuovi certificati. Le configurazioni esistenti con un solo account vengono
mantenute come account `default` quando se ne aggiunge un altro. Eliminare un
account lascia intatti gli altri account della stessa CA; prima di eliminarlo,
cambia il predefinito o riemetti i certificati che usano quell'account.

Imposta una CA predefinita per tutti i nuovi certificati. Puoi sovrascriverla per singolo certificato durante la creazione:

1. Vai alla pagina **Certificati**
2. Seleziona la CA desiderata dal menu a tendina **Certificate Authority**
3. Procedi con la creazione del certificato

Se la CA scelta non ha una configurazione salvata (o l'account CA richiesto non
esiste), la richiesta viene **rifiutata**. Emettere da una CA diversa non
sostituisce quella che hai chiesto: era possibile chiedere DigiCert e ricevere
un certificato Let's Encrypt con un `201`, e chiedere a una CA privata un nome
interno e vederlo pubblicato in un certificato pubblico. Il rifiuto nomina la
CA che manca.

Let's Encrypt fa eccezione, e solo perché i valori predefiniti di certbot sono
la sua configurazione: una richiesta per Let's Encrypt riesce senza nulla di
salvato, e una richiesta di staging resta su staging.

La colonna **CA** nella pagina Certificati indica con quale autorità è stato
emesso ciascun certificato; lo stesso valore è `ca_provider` nella risposta
dell'API e nei metadati del certificato. I certificati emessi prima che
CertMate registrasse la CA mostrano lì `—` invece di un'ipotesi.

### Tramite API

```bash
# Create certificate with specific CA
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'

# Test CA connection
curl -X POST http://localhost:8000/api/settings/test-ca-provider \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://one.digicert.com/mpki/api/v1/acme/v2/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis e Sectigo richiedono l'External Account Binding per collegare il client ACME al proprio account CA.

### Cos'è l'EAB?

- **Key ID**: Un identificatore univoco per il tuo account
- **HMAC Key**: Una chiave segreta utilizzata per firmare le richieste

### Ottenere le credenziali EAB

**DigiCert:**
1. Accedi al tuo account DigiCert
2. Vai alle impostazioni ACME
3. Genera o recupera il tuo EAB Key ID e la HMAC Key

**ZeroSSL:**
- Genera le credenziali EAB nella Developer Dashboard di ZeroSSL

**Actalis:**
1. Registra un account gratuito su [actalis.com](https://www.actalis.com/)
2. Nell'area clienti, apri **Manage with ACME**
3. Recupera il KID e la chiave HMAC sotto **ACME Credentials**

**CA Privata:**
- **step-ca**: L'EAB può essere abilitato/disabilitato per provisioner
- Consulta la documentazione della tua CA privata per i requisiti specifici

---

## Attendibilità dei certificati SSL

### CA pubbliche (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis, Sectigo)

I certificati sono automaticamente riconosciuti dai browser e dai sistemi operativi (tranne quelli di Let's Encrypt staging).

### CA private

Affinché i certificati di una CA privata siano ritenuti attendibili:
1. Installa il certificato root della CA sui sistemi client
2. Configura le applicazioni per una trust personalizzata
3. Importa il certificato root nei trust store dei browser

Puoi facoltativamente fornire il certificato root della CA in CertMate per la verifica della catena di fiducia durante la creazione del certificato.

---

## Risoluzione dei problemi

### Let's Encrypt
- **Certificato non attendibile dopo l'emissione**: Verifica se il certificato è stato emesso dalla CA di staging — seleziona la voce di produzione "Let's Encrypt" e riemettilo
- **Rate limit raggiunto**: Passa alla voce CA "Let's Encrypt (Staging)" durante i test
- **Email valida**: Assicurati che il formato dell'email sia corretto

### DigiCert
- **Credenziali EAB non valide**: Verifica la Key ID e la HMAC Key
- **Account non autorizzato**: Assicurati che ACME sia abilitato sul tuo account DigiCert
- **URL ACME errato**: Verifica l'URL della directory con il supporto DigiCert

### Actalis
- **`Your account only grants single-domain 90-days DV certificates`**: Il piano gratuito rifiuta le richieste SAN/multi-dominio — emetti un certificato per hostname oppure passa a un piano superiore
- **Credenziali EAB non valide**: Recupera credenziali aggiornate dall'area clienti sotto Manage with ACME
- **Wildcard rifiutato**: I certificati wildcard non sono disponibili tramite ACME su Actalis

### Sectigo
- **Credenziali EAB non valide**: Verifica KID e HMAC confrontandoli con i dettagli dell'account ACME SCM selezionato
- **Identificatore/dominio non autorizzato**: Verifica che il dominio sia autorizzato per l'account ACME SCM e l'organizzazione selezionati
- **Endpoint ACME errato**: Verifica che l'URL della directory configurato corrisponda esattamente all'URL fornito in SCM per quell'account

### CA Privata
- **URL ACME non raggiungibile**: Verifica la connettività di rete
- **Certificato CA non valido**: Verifica il formato PEM e la validità
- **EAB mismatch**: Controlla se l'EAB è richiesto dalla tua CA

### Generale
- Assicurati che il provider DNS sia configurato correttamente
- Verifica la proprietà del dominio e la propagazione DNS
- Controlla le regole del firewall per la porta ACME (di solito 443)

---

## Migrazione tra CA

1. **I nuovi certificati** utilizzano la nuova CA predefinita
2. **I certificati esistenti** restano sulla CA che li ha emessi: il rinnovo esegue
   `certbot renew` verso la CA originale, anche se manuale o forzato
3. **Spostare un certificato su un'altra CA**: riemettilo con la nuova CA
   (`POST /api/certificates/<domain>/reissue` con `ca_provider`; vedi il
   [riferimento API](./api.md))

**Best practice:**
- Testa la nuova configurazione CA prima di impostarla come predefinita
- Pianifica la migrazione durante le finestre di manutenzione
- Conserva backup dei certificati esistenti
- Monitora la validità dopo la migrazione

---

## Considerazioni sulla sicurezza

- Le chiavi HMAC EAB non vengono visualizzate dopo il salvataggio
- Le chiavi private vengono generate localmente e non vengono mai inviate alla CA (un backend di storage remoto o un deploy target che configuri le riceve)
- Utilizza un URL di directory ACME `https://` per una CA Privata
- Valuta l'uso di una VPN per l'accesso alla CA privata

---

## Risorse

### Let's Encrypt
- [Documentazione](https://letsencrypt.org/docs/)
- [Rate Limit](https://letsencrypt.org/docs/rate-limits/)
- [Ambiente di staging](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [Documentazione ACME](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Configurazione account](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)

### Actalis
- [Come abilitare ACME](https://guide.actalis.com/ssl/activation/acme)
- [FAQ ACME](https://guide.actalis.com/faq/SSL/ACME)

### Sectigo
- [Comprendere gli endpoint ACME di SCM](https://docs.sectigo.com/scm/scm-administrator/understanding-acme-endpoints.html)
- [Aggiungere account ACME in SCM](https://docs.sectigo.com/scm/scm-administrator/adding-acme-accounts.html)

### CA Privata
- [Documentazione step-ca](https://smallstep.com/docs/step-ca/)
- [Progetto Boulder](https://github.com/letsencrypt/boulder)
- [Server di test Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Provider DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
