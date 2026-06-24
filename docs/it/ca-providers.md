# Fornitori di Certificate Authority (CA)

CertMate supporta diversi fornitori di Certificate Authority, consentendoti di scegliere la CA più adatta alle tue esigenze.

---

## Fornitori CA supportati

### Let's Encrypt (Predefinito)

- **Tipo**: Certificati SSL gratuiti e automatizzati
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: Si
- **EAB Richiesto**: No
- **Ideale per**: Sviluppo, piccole imprese, progetti personali

**Configurazione:**
- **Email**: Obbligatoria per le notifiche sui certificati

### Let's Encrypt (Staging)

- **Tipo**: Certificati di test dall'ambiente di staging di Let's Encrypt
- **Tipi di certificati**: Domain Validation (DV) — NON riconosciuti dai browser
- **Supporto Wildcard**: Si
- **EAB Richiesto**: No
- **Ideale per**: Validare la configurazione DNS, il deployment e il rinnovo senza consumare i rate limit di produzione

Lo staging e una voce di Certificate Authority separata (dalla v2.12.0), non un flag per singolo certificato: selezionala come CA durante la creazione di un certificato, oppure impostala come CA predefinita durante i test. L'email utilizza come fallback l'account Let's Encrypt quando lasciata vuota. La conversione di un certificato di staging in produzione richiede una riemissione con la CA di produzione.

### DigiCert ACME

- **Tipo**: Certificati SSL di livello enterprise
- **Tipi di certificati**: DV, OV, EV
- **Supporto Wildcard**: Si
- **EAB Richiesto**: Si
- **Ideale per**: Ambienti enterprise, applicazioni commerciali

**Requisiti di configurazione:**
- **URL directory ACME**: `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID**: Fornito da DigiCert
- **EAB HMAC Key**: Fornita da DigiCert
- **Email**: Obbligatoria per le notifiche sui certificati

### Actalis

- **Tipo**: Certificati DV gratuiti da 90 giorni di una CA europea (italiana)
- **Tipi di certificati**: Domain Validation (DV)
- **Supporto Wildcard**: No (non disponibile tramite ACME)
- **EAB Richiesto**: Si
- **Ideale per**: Utenti UE che desiderano un'alternativa europea a Let's Encrypt, ambienti eIDAS

**Requisiti di configurazione:**
- **URL directory ACME**: `https://acme-api.actalis.com/acme/directory` (fisso, preconfigurato)
- **EAB Key ID**: Dall'area clienti Actalis
- **EAB HMAC Key**: Dall'area clienti Actalis
- **Email**: Obbligatoria per le notifiche sui certificati

**Limiti del piano gratuito:**
- Solo certificati a dominio singolo — una richiesta con voci SAN viene rifiutata con
  `Your account only grants single-domain 90-days DV certificates`
- Validita di 90 giorni
- Nessun certificato wildcard (i piani SAN a pagamento coprono fino a 5 hostname)

### CA Privata

- **Tipo**: Certificate Authority interna/aziendale
- **Tipi di certificati**: Privati/Interni
- **Supporto Wildcard**: Si (dipende dall'implementazione della CA)
- **EAB Richiesto**: Facoltativo
- **Ideale per**: Reti interne, ambienti aziendali, sistemi isolati

**Software compatibili:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Altre CA private compatibili con ACME

**Utilizzo di una CA ACME pubblica tramite la voce CA Privata:**

La voce CA Privata e anche la via d'uscita generica per qualsiasi CA ACME priva di una voce dedicata in CertMate: puntala all'URL della directory della CA e, se la CA impone il binding dell'account, compila l'EAB Key ID e la HMAC Key facoltativi. Ad esempio, Actalis funziona sia tramite la sua voce dedicata (consigliato) sia come CA Privata con:

- **URL directory ACME**: `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key**: dall'area clienti Actalis
- **Certificato CA**: lasciare vuoto (root di fiducia pubblici)

---

## Configurazione

### Tramite interfaccia Web

1. Vai su **Impostazioni**
2. Scorri fino a **Fornitori di Certificate Authority (CA)**
3. Seleziona il fornitore CA predefinito
4. Configura i campi obbligatori
5. Clicca su **Testa connessione CA** per verificare
6. Salva le impostazioni

### CA predefinita vs. CA per certificato

Imposta una CA predefinita per tutti i nuovi certificati. Puoi sovrascriverla per singolo certificato durante la creazione:

1. Vai alla pagina **Certificati**
2. Seleziona la CA desiderata dal menu a tendina **Certificate Authority**
3. Procedi con la creazione del certificato

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
      "acme_url": "https://acme.digicert.com/v2/acme/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

Alcuni fornitori CA (come DigiCert e Actalis) richiedono l'External Account Binding per collegare il client ACME al proprio account CA.

### Cos'e l'EAB?

- **Key ID**: Un identificatore univoco per il tuo account
- **HMAC Key**: Una chiave segreta utilizzata per firmare le richieste

### Ottenere le credenziali EAB

**DigiCert:**
1. Accedi al tuo account DigiCert
2. Vai alle impostazioni ACME
3. Genera o recupera il tuo EAB Key ID e la HMAC Key

**Actalis:**
1. Registra un account gratuito su [actalis.com](https://www.actalis.com/)
2. Nell'area clienti, apri **Manage with ACME**
3. Recupera il KID e la chiave HMAC sotto **ACME Credentials**

**CA Privata:**
- **step-ca**: L'EAB puo essere abilitato/disabilitato per provisioner
- **Boulder**: Di norma richiede EAB per la produzione
- Consulta la documentazione della tua CA privata per i requisiti specifici

---

## Attendibilita dei certificati SSL

### CA pubbliche (Let's Encrypt, DigiCert)

I certificati sono automaticamente riconosciuti dai browser e dai sistemi operativi.

### CA private

Affinche i certificati di una CA privata siano ritenuti attendibili:
1. Installa il certificato root della CA sui sistemi client
2. Configura le applicazioni per una trust personalizzata
3. Importa il certificato root nei trust store dei browser

Puoi facoltativamente fornire il certificato root della CA in CertMate per la verifica della catena di fiducia durante la creazione del certificato.

---

## Risoluzione dei problemi

### Let's Encrypt
- **Certificato non attendibile dopo l'emissione**: Verifica se il certificato e stato emesso dalla CA di staging — seleziona la voce di produzione "Let's Encrypt" e riemettilo
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

### CA Privata
- **URL ACME non raggiungibile**: Verifica la connettivita di rete
- **Certificato CA non valido**: Verifica il formato PEM e la validita
- **EAB mismatch**: Controlla se l'EAB e richiesto dalla tua CA

### Generale
- Assicurati che il provider DNS sia configurato correttamente
- Verifica la proprieta del dominio e la propagazione DNS
- Controlla le regole del firewall per la porta ACME (di solito 443)

---

## Migrazione tra CA

1. **I nuovi certificati** utilizzano la nuova CA predefinita
2. **I certificati esistenti** continuano a usare la CA originale fino al rinnovo
3. **Migrazione forzata**: Rinnova manualmente per passare alla nuova CA

**Best practice:**
- Testa la nuova configurazione CA prima di impostarla come predefinita
- Pianifica la migrazione durante le finestre di manutenzione
- Conserva backup dei certificati esistenti
- Monitora la validita dopo la migrazione

---

## Considerazioni sulla sicurezza

- Le chiavi HMAC EAB non vengono visualizzate dopo il salvataggio
- Le chiavi private vengono generate localmente e non vengono mai trasmesse
- Utilizza HTTPS per tutte le comunicazioni con le CA
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

### CA Privata
- [Documentazione step-ca](https://smallstep.com/docs/step-ca/)
- [Progetto Boulder](https://github.com/letsencrypt/boulder)
- [Server di test Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Provider DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
