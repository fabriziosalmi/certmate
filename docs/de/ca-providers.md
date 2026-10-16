# Zertifizierungsstellen (CA) Anbieter

<!-- CERTMATE-TRANSLATED-FROM b5fbaa66b65585c0 -->

CertMate unterstützt mehrere Zertifizierungsstellen-Anbieter, sodass Sie die für Ihre Anforderungen am besten geeignete CA auswählen können.

---

## Unterstützte CA-Anbieter

### Let's Encrypt (Standard)

- **Typ**: Kostenlose, automatisierte SSL-Zertifikate
- **Zertifikattypen**: Domain Validation (DV)
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Nein
- **Am besten geeignet für**: Entwicklung, kleine Unternehmen, private Projekte

**Konfiguration:**
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

**Profile:** `classic` (90 Tage, der Standard), `tlsserver` (45 Tage) und
`shortlived` (160 Stunden), in Produktion und Staging. Ein Zertifikat fordert
eines mit `acme_profile` an, und ein CA-Konto kann einen Standard für die darauf
erstellten Zertifikate festlegen; siehe [ACME-Profile](../api.md#acme-profiles).
Im Dashboard: **ACME Profile** in den erweiterten Optionen des
Erstellungsformulars (Edit & Reissue öffnet sich mit dem eigenen Profil des
Zertifikats) und **Default ACME profile** im Formular des CA-Kontos. Das Panel
des Zertifikats zeigt sein Profil und wann es erneuert wird.

### Let's Encrypt (Staging)

- **Typ**: Testzertifikate aus der Let's Encrypt Staging-Umgebung
- **Zertifikattypen**: Domain Validation (DV) — von Browsern NICHT vertraut
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Nein
- **Am besten geeignet für**: DNS-Konfiguration, Deployment und Erneuerungsablauf validieren, ohne Produktions-Rate-Limits zu verbrauchen

Staging ist ein eigenständiger Zertifizierungsstellen-Eintrag (seit v2.12.0), kein Kennzeichen pro Zertifikat: Wählen Sie ihn beim Erstellen eines Zertifikats als CA aus oder legen Sie ihn während des Testens als Standard-CA fest. Die E-Mail-Adresse fällt auf das Let's Encrypt-Konto zurück, wenn sie leer gelassen wird. Die Umwandlung eines Staging-Zertifikats in ein Produktionszertifikat erfordert eine Neuausstellung mit der Produktions-CA.

### ZeroSSL

- **Typ**: Kostenlose 90-tägige DV-Zertifikate
- **Zertifikattypen**: Domain Validation (DV)
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Ja

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://acme.zerossl.com/v2/DV90` (fest vorkonfiguriert)
- **EAB Key ID**: Aus dem ZeroSSL Developer Dashboard
- **EAB HMAC Key**: Aus dem ZeroSSL Developer Dashboard
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

### Google Trust Services

- **Typ**: Kostenlose DV-Zertifikate
- **Zertifikattypen**: Domain Validation (DV)
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Ja

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://dv.acme-v02.api.pki.goog/directory` (fest vorkonfiguriert)
- **EAB Key ID**: Aus Ihrem Google-Cloud-Projekt
- **EAB HMAC Key**: Aus Ihrem Google-Cloud-Projekt
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

### DigiCert ACME

- **Typ**: SSL-Zertifikate für Unternehmensumgebungen
- **Zertifikattypen**: DV, OV, EV
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Ja
- **Am besten geeignet für**: Unternehmensumgebungen, kommerzielle Anwendungen

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
  — der Standard, und **regional**. Ein Konto außerhalb der Standardregion hat
  eine eigene Directory-URL, die in CertCentral angezeigt wird; tragen Sie sie
  hier ein, und die Ausstellung verwendet sie. Belassen Sie den Standard, wird
  der Standard verwendet. Sie muss `https` sein.
- **EAB Key ID**: Von DigiCert bereitgestellt
- **EAB HMAC Key**: Von DigiCert bereitgestellt
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

### Actalis

- **Typ**: Kostenlose 90-tägige DV-Zertifikate einer europäischen (italienischen) CA
- **Zertifikattypen**: Domain Validation (DV)
- **Wildcard-Unterstützung**: Nein (nicht per ACME angeboten)
- **EAB Erforderlich**: Ja
- **Am besten geeignet für**: EU-Nutzer, die eine europäische Alternative zu Let's Encrypt suchen, eIDAS-Ökosystem-Umgebungen

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://acme-api.actalis.com/acme/directory` (fest vorkonfiguriert)
- **EAB Key ID**: Aus Ihrem Actalis-Kundenbereich
- **EAB HMAC Key**: Aus Ihrem Actalis-Kundenbereich
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

**Limits des kostenlosen Tarifs:**
- Nur Einzeldomain-Zertifikate — eine Anfrage mit SAN-Einträgen wird mit
  `Your account only grants single-domain 90-days DV certificates` abgelehnt
- 90 Tage Gültigkeit
- Keine Wildcard-Zertifikate (kostenpflichtige SAN-Tarife decken bis zu 5 Hostnamen ab)

### SSL.com

- **Typ**: Kommerzielle Zertifikate
- **Zertifikattypen**: DV, OV, EV
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Ja

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://acme.ssl.com/sslcom-dv-rsa` (fest vorkonfiguriert)
- **EAB Key ID**: Von SSL.com bereitgestellt
- **EAB HMAC Key**: Von SSL.com bereitgestellt
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

### Sectigo

- **Typ**: Öffentliche/kommerzielle ACME-CA über Sectigo Certificate Manager (SCM)
- **Zertifikattypen**: DV, OV (abhängig vom ausgewählten SCM-Konto/-Profil)
- **Wildcard-Unterstützung**: Ja, sofern das SCM-Konto/-Profil es erlaubt
- **EAB Erforderlich**: Ja
- **ACME Directory URL**: Kopieren Sie die HTTPS-URL aus den Details des SCM-ACME-Kontos; sie ist kontospezifisch
- **EAB Key ID / KID und HMAC Key**: Aus den Details des SCM-ACME-Kontos kopieren
- **E-Mail**: Kontakt des ACME-Kontos (siehe [Konto-E-Mail](#konto-e-mail))

Beispiel einer Testkonfiguration (die URL ist **nur ein Beispiel**, kein universeller Endpoint):

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

Für mehrere Konten konfigurieren Sie `ca_providers.sectigo.accounts` in den
Einstellungen, wobei jedes Konto seine eigenen Werte für `acme_url`, `eab_kid`,
`eab_hmac` und `email` enthält. Wählen Sie ein Konto über `ca_account_id` in der
API zur Zertifikatserstellung aus; fehlt es, verwendet CertMate
`default_ca_accounts.sectigo` oder das erste konfigurierte Konto. Die Erneuerung
verwendet das aufgezeichnete CA-Konto erneut. DNS-01 (einschließlich Custom
Script) und HTTP-01 bleiben verfügbar; SCM hat die angeforderte Domain
möglicherweise bereits autorisiert. Für ein SCM-Konto, das bereits **jeden**
angeforderten Namen autorisiert, wählen Sie **Sectigo → Sectigo (already
authorized in SCM)** als Challenge-Typ des Zertifikats. CertMate konfiguriert in
diesem Modus weder DNS- noch HTTP-Validierung, und ein Wildcard-Zertifikat kann
angefordert werden, wenn dieses SCM-Konto/-Profil es autorisiert. Certbot
verwendet seinen manuellen Authenticator mit einem Hook, der nichts
veröffentlicht, nur um seine Anforderung an den nicht-interaktiven Betrieb zu
erfüllen: Wenn die CA gültige ACME-Autorisierungen zurückgibt, wird der Hook nie
aufgerufen. Gibt SCM eine ausstehende Autorisierung zurück, veröffentlicht der
Hook kein Validierungsmaterial, sodass CertMate sie in diesem Modus nicht
erfüllen kann. Verwenden Sie DNS-01 oder HTTP-01, wenn die Namen nicht bereits
autorisiert sind. Bei der Erneuerung muss SCM die Namen für dieses Konto weiterhin
autorisieren. Dieser Modus ist nur verfügbar, wenn Sectigo ausdrücklich als
CA ausgewählt ist. Bestehende Sectigo-Konfigurationen unter Private CA
funktionieren unverändert weiter.

### Private CA

- **Typ**: Interne/Unternehmenseigene Zertifizierungsstelle
- **Zertifikattypen**: Privat/Intern
- **Wildcard-Unterstützung**: Ja (abhängig von der CA-Implementierung)
- **EAB Erforderlich**: Optional
- **Am besten geeignet für**: Interne Netzwerke, Unternehmensumgebungen, abgeschottete Systeme

**Kompatible Software:**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Andere ACME-kompatible private CAs

**Öffentliche ACME-CA über Private CA nutzen:**

Der Private-CA-Eintrag ist auch der generische Ausweg für jede ACME-CA ohne dedizierten CertMate-Eintrag: Richten Sie ihn auf die Directory-URL der CA aus und füllen Sie, falls die CA eine Kontobindung erzwingt, die optionale EAB Key ID und den HMAC Key aus. Actalis funktioniert beispielsweise sowohl über seinen dedizierten Eintrag (empfohlen) als auch als Private CA mit:

- **ACME Directory URL**: `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key**: aus dem Actalis-Kundenbereich
- **CA-Zertifikat**: leer lassen (öffentlich vertrauenswürdige Stammzertifikate)

---

## Konfiguration

### Über die Weboberfläche

1. Navigieren Sie zu **Einstellungen**
2. Scrollen Sie zu **Zertifizierungsstellen (CA) Anbieter**
3. Klicken Sie auf **Add CA Account**, wählen Sie die CA und benennen Sie das
   Konto (Buchstaben, Ziffern, Punkte, Binde- und Unterstriche)
4. Konfigurieren Sie die erforderlichen Felder
5. Klicken Sie auf **Test CA Connection**, um die Felder zu prüfen
6. Klicken Sie auf **Save Account**

**Test CA Connection** kontaktiert die CA nur bei einer Private CA: Es ruft die
ACME Directory URL ab (mit dem CA-Zertifikat, falls eines angegeben ist). Bei
jeder anderen CA prüft es, ohne die CA zu kontaktieren, dass die erforderlichen
Felder ausgefüllt sind (und bei DigiCert, dass die EAB-Zugangsdaten nicht
unplausibel kurz sind); ein bestandener Test beweist also nicht, dass die
Zugangsdaten funktionieren. Das beweist erst die erste Ausstellung.

### Konto-E-Mail

Certbot verwendet für neue Ausstellungen die E-Mail-Adresse des ausgewählten
CA-Kontos und greift auf die globale Einstellung `email` zurück, wenn dieses
Konto keine hat. Die globale E-Mail-Adresse bleibt für die Ausstellung
erforderlich. Das Ändern der E-Mail-Adresse eines Kontos aktualisiert kein
ACME-Konto, das Certbot bereits registriert hat; verwenden Sie für diese
Kontaktänderung `certbot update_account`.

### Standard-CA vs. CA pro Zertifikat

Einstellungen → CA Providers listet die CA-Konten auf (zum Beispiel zwei
Let's-Encrypt-E-Mail-Adressen oder zwei Sectigo-SCM-Konten). **Add CA Account**
öffnet das Kontoformular; **Edit** öffnet es erneut. Wählen Sie **Default for
this CA** für jeweils ein Konto pro Anbieter; **Make global default** bestimmt
außerdem den Anbieter, der für neue Zertifikate verwendet wird. Bestehende
Konfigurationen mit einem einzigen Konto bleiben als Konto `default` erhalten,
wenn ein weiteres Konto hinzugefügt wird. Das Löschen eines Kontos lässt die
übrigen Konten dieser CA unberührt; wechseln Sie den Standard oder stellen Sie
die Zertifikate, die dieses Konto verwenden, neu aus, bevor Sie es löschen.

Legen Sie eine Standard-CA für alle neuen Zertifikate fest. Überschreiben Sie diese pro Zertifikat während der Erstellung:

1. Gehen Sie zur Seite **Zertifikate**
2. Wählen Sie die gewünschte CA aus dem Dropdown-Menü **Zertifizierungsstelle**
3. Fahren Sie mit der Zertifikatserstellung fort

Hat die gewählte CA keine gespeicherte Konfiguration (oder existiert das
angeforderte CA-Konto nicht), wird die Anfrage **abgelehnt**. Die Ausstellung
durch eine andere CA ist kein Ersatz für die angeforderte: Es war möglich,
DigiCert anzufordern und mit einem `201` ein Let's-Encrypt-Zertifikat zu
erhalten, und bei einer privaten CA einen internen Namen anzufordern und diesen
Namen dann in einem öffentlichen Zertifikat veröffentlicht zu finden. Die
Ablehnung nennt die CA, die fehlt.

Let's Encrypt ist die Ausnahme, und zwar nur, weil die Standardwerte von certbot
seine Konfiguration sind: Eine Anfrage dafür gelingt auch ohne gespeicherte
Konfiguration, und eine Staging-Anfrage bleibt bei Staging.

Die Spalte **CA** auf der Seite Zertifikate nennt die Zertifizierungsstelle, mit
der jedes Zertifikat ausgestellt wurde; derselbe Wert steht als `ca_provider` in
der API-Antwort und in den Metadaten des Zertifikats. Zertifikate, die
ausgestellt wurden, bevor CertMate die CA aufzeichnete, zeigen dort `—` statt
einer Vermutung.

### Über die API

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

ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis und Sectigo erfordern External Account Binding, um Ihren ACME-Client mit Ihrem CA-Konto zu verknüpfen.

### Was ist EAB?

- **Key ID**: Ein eindeutiger Bezeichner für Ihr Konto
- **HMAC Key**: Ein geheimer Schlüssel zum Signieren von Anfragen

### EAB-Zugangsdaten beziehen

**DigiCert:**
1. Melden Sie sich in Ihrem DigiCert-Konto an
2. Navigieren Sie zu den ACME-Einstellungen
3. Generieren oder rufen Sie Ihre EAB Key ID und den HMAC Key ab

**ZeroSSL:**
- Erzeugen Sie die EAB-Zugangsdaten im ZeroSSL Developer Dashboard

**Actalis:**
1. Registrieren Sie ein kostenloses Konto auf [actalis.com](https://www.actalis.com/)
2. Öffnen Sie im Kundenbereich **Manage with ACME**
3. Rufen Sie die KID und den HMAC Key unter **ACME Credentials** ab

**Private CA:**
- **step-ca**: EAB kann pro Provisioner aktiviert/deaktiviert werden
- Entnehmen Sie die spezifischen Anforderungen der Dokumentation Ihrer privaten CA

---

## SSL-Zertifikatsvertrauen

### Öffentliche CAs (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis, Sectigo)

Zertifikate werden von Browsern und Betriebssystemen automatisch als vertrauenswürdig eingestuft (ausgenommen die aus Let's Encrypt Staging).

### Private CAs

Damit Zertifikate einer privaten CA als vertrauenswürdig gelten:
1. Installieren Sie das Stamm-CA-Zertifikat auf den Client-Systemen
2. Konfigurieren Sie Anwendungen für benutzerdefiniertes Vertrauen
3. Importieren Sie das Stammzertifikat in die Vertrauensspeicher der Browser

Sie können in CertMate optional das Stamm-CA-Zertifikat angeben, um bei der Zertifikatserstellung die Vertrauenskette zu prüfen.

---

## Fehlerbehebung

### Let's Encrypt
- **Zertifikat nach Ausstellung nicht vertrauenswürdig**: Prüfen Sie, ob das Zertifikat von der Staging-CA ausgestellt wurde — wählen Sie den Produktionseintrag "Let's Encrypt" und stellen Sie es neu aus
- **Rate-Limit erreicht**: Wechseln Sie während des Testens zum CA-Eintrag "Let's Encrypt (Staging)"
- **Gültige E-Mail**: Stellen Sie sicher, dass das E-Mail-Format korrekt ist

### DigiCert
- **Ungültige EAB-Zugangsdaten**: Überprüfen Sie Key ID und HMAC Key
- **Konto nicht autorisiert**: Stellen Sie sicher, dass ACME in Ihrem DigiCert-Konto aktiviert ist
- **Falsche ACME-URL**: Überprüfen Sie die Directory-URL beim DigiCert-Support

### Actalis
- **`Your account only grants single-domain 90-days DV certificates`**: Der kostenlose Tarif lehnt SAN/Multi-Domain-Anfragen ab — stellen Sie je ein Zertifikat pro Hostname aus oder upgraden Sie den Tarif
- **Ungültige EAB-Zugangsdaten**: Rufen Sie neue Zugangsdaten aus dem Kundenbereich unter Manage with ACME ab
- **Wildcard abgelehnt**: Wildcard-Zertifikate sind bei Actalis über ACME nicht verfügbar

### Sectigo
- **Ungültige EAB-Zugangsdaten**: Gleichen Sie KID und HMAC mit den Details des ausgewählten SCM-ACME-Kontos ab
- **Nicht autorisierter Identifier/nicht autorisierte Domain**: Prüfen Sie, ob die Domain für das ausgewählte SCM-ACME-Konto und die Organisation autorisiert ist
- **Falscher ACME-Endpoint**: Prüfen Sie, ob die konfigurierte Directory-URL exakt mit der URL übereinstimmt, die SCM für dieses Konto angibt

### Private CA
- **ACME-URL nicht erreichbar**: Überprüfen Sie die Netzwerkkonnektivität
- **CA-Zertifikat ungültig**: Überprüfen Sie das PEM-Format und die Gültigkeit
- **EAB mismatch**: Prüfen Sie, ob EAB von Ihrer CA verlangt wird

### Allgemein
- Stellen Sie sicher, dass der DNS-Anbieter korrekt konfiguriert ist
- Überprüfen Sie die Domain-Inhaberschaft und die DNS-Propagation
- Prüfen Sie die Firewall-Regeln für den ACME-Port (in der Regel 443)

---

## Migration zwischen CAs

1. **Neue Zertifikate** verwenden die neue Standard-CA
2. **Bestehende Zertifikate** bleiben bei der CA, von der sie ausgestellt wurden: Die
   Erneuerung führt `certbot renew` gegen die ursprüngliche CA aus, auch bei einer
   manuellen oder erzwungenen Erneuerung
3. **Ein Zertifikat zu einer anderen CA verschieben**: Stellen Sie es mit der neuen CA neu aus
   (`POST /api/certificates/<domain>/reissue` mit `ca_provider`; siehe die
   [API-Referenz](./api.md))

**Best Practices:**
- Testen Sie die neue CA-Konfiguration, bevor Sie sie als Standard festlegen
- Planen Sie die Migration in Wartungsfenstern
- Sichern Sie vorhandene Zertifikate
- Überwachen Sie die Gültigkeit nach der Migration

---

## Sicherheitshinweise

- EAB-HMAC-Schlüssel werden nach dem Speichern nicht mehr angezeigt
- Private Schlüssel werden lokal generiert und niemals an die CA gesendet (ein von Ihnen konfiguriertes entferntes Storage-Backend oder Deploy-Ziel erhält sie jedoch)
- Verwenden Sie für eine Private CA eine ACME Directory URL mit `https://`
- Erwägen Sie ein VPN für den Zugriff auf private CAs

---

## Ressourcen

### Let's Encrypt
- [Dokumentation](https://letsencrypt.org/docs/)
- [Rate Limits](https://letsencrypt.org/docs/rate-limits/)
- [Staging-Umgebung](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [ACME-Dokumentation](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Konto-Einrichtung](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)

### Actalis
- [ACME aktivieren](https://guide.actalis.com/ssl/activation/acme)
- [ACME FAQ](https://guide.actalis.com/faq/SSL/ACME)

### Sectigo
- [SCM-ACME-Endpoints verstehen](https://docs.sectigo.com/scm/scm-administrator/understanding-acme-endpoints.html)
- [SCM-ACME-Konten hinzufügen](https://docs.sectigo.com/scm/scm-administrator/adding-acme-accounts.html)

### Private CA
- [step-ca Dokumentation](https://smallstep.com/docs/step-ca/)
- [Boulder-Projekt](https://github.com/letsencrypt/boulder)
- [Pebble-Testserver](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [DNS-Anbieter →](./dns-providers.md) • [Docker →](./docker.md)

</div>
