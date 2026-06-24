# Zertifizierungsstellen (CA) Anbieter

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
- **E-Mail**: Erforderlich für Zertifikatsbenachrichtigungen

### Let's Encrypt (Staging)

- **Typ**: Testzertifikate aus der Let's Encrypt Staging-Umgebung
- **Zertifikattypen**: Domain Validation (DV) — von Browsern NICHT vertraut
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Nein
- **Am besten geeignet für**: DNS-Konfiguration, Deployment und Erneuerungsablauf validieren, ohne Produktions-Rate-Limits zu verbrauchen

Staging ist ein eigenständiger Zertifizierungsstellen-Eintrag (seit v2.12.0), kein Kennzeichen pro Zertifikat: Wählen Sie ihn beim Erstellen eines Zertifikats als CA aus oder legen Sie ihn während des Testens als Standard-CA fest. Die E-Mail-Adresse fällt auf das Let's Encrypt-Konto zurück, wenn sie leer gelassen wird. Die Umwandlung eines Staging-Zertifikats in ein Produktionszertifikat erfordert eine Neuausstellung mit der Produktions-CA.

### DigiCert ACME

- **Typ**: SSL-Zertifikate für Unternehmensumgebungen
- **Zertifikattypen**: DV, OV, EV
- **Wildcard-Unterstützung**: Ja
- **EAB Erforderlich**: Ja
- **Am besten geeignet für**: Unternehmensumgebungen, kommerzielle Anwendungen

**Konfigurationsanforderungen:**
- **ACME Directory URL**: `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID**: Von DigiCert bereitgestellt
- **EAB HMAC Key**: Von DigiCert bereitgestellt
- **E-Mail**: Erforderlich für Zertifikatsbenachrichtigungen

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
- **E-Mail**: Erforderlich für Zertifikatsbenachrichtigungen

**Limits des kostenlosen Tarifs:**
- Nur Einzeldomain-Zertifikate — eine Anfrage mit SAN-Einträgen wird mit
  `Your account only grants single-domain 90-days DV certificates` abgelehnt
- 90 Tage Gültigkeit
- Keine Wildcard-Zertifikate (kostenpflichtige SAN-Tarife decken bis zu 5 Hostnamen ab)

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
3. Wählen Sie Ihren Standard-CA-Anbieter aus
4. Konfigurieren Sie die erforderlichen Felder
5. Klicken Sie auf **CA-Verbindung testen**, um die Verbindung zu prüfen
6. Einstellungen speichern

### Standard-CA vs. CA pro Zertifikat

Legen Sie eine Standard-CA für alle neuen Zertifikate fest. Überschreiben Sie diese pro Zertifikat während der Erstellung:

1. Gehen Sie zur Seite **Zertifikate**
2. Wählen Sie die gewünschte CA aus dem Dropdown-Menü **Zertifizierungsstelle**
3. Fahren Sie mit der Zertifikatserstellung fort

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
      "acme_url": "https://acme.digicert.com/v2/acme/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

Einige CA-Anbieter (wie DigiCert und Actalis) erfordern External Account Binding, um Ihren ACME-Client mit Ihrem CA-Konto zu verknüpfen.

### Was ist EAB?

- **Key ID**: Ein eindeutiger Bezeichner für Ihr Konto
- **HMAC Key**: Ein geheimer Schlüssel zum Signieren von Anfragen

### EAB-Zugangsdaten beziehen

**DigiCert:**
1. Melden Sie sich in Ihrem DigiCert-Konto an
2. Navigieren Sie zu den ACME-Einstellungen
3. Generieren oder rufen Sie Ihre EAB Key ID und den HMAC Key ab

**Actalis:**
1. Registrieren Sie ein kostenloses Konto auf [actalis.com](https://www.actalis.com/)
2. Öffnen Sie im Kundenbereich **Manage with ACME**
3. Rufen Sie die KID und den HMAC Key unter **ACME Credentials** ab

**Private CA:**
- **step-ca**: EAB kann pro Provisioner aktiviert/deaktiviert werden
- **Boulder**: Erfordert in der Regel EAB für den Produktionsbetrieb
- Entnehmen Sie die spezifischen Anforderungen der Dokumentation Ihrer privaten CA

---

## SSL-Zertifikatsvertrauen

### Öffentliche CAs (Let's Encrypt, DigiCert)

Zertifikate werden von Browsern und Betriebssystemen automatisch als vertrauenswürdig eingestuft.

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
2. **Bestehende Zertifikate** nutzen weiterhin ihre ursprüngliche CA bis zur Erneuerung
3. **Erzwungene Migration**: Manuell erneuern, um zur neuen CA zu wechseln

**Best Practices:**
- Testen Sie die neue CA-Konfiguration, bevor Sie sie als Standard festlegen
- Planen Sie die Migration in Wartungsfenstern
- Sichern Sie vorhandene Zertifikate
- Überwachen Sie die Gültigkeit nach der Migration

---

## Sicherheitshinweise

- EAB-HMAC-Schlüssel werden nach dem Speichern nicht mehr angezeigt
- Private Schlüssel werden lokal generiert und niemals übertragen
- Verwenden Sie HTTPS für alle CA-Kommunikationen
- Erwägen Sie einen VPN für den Zugriff auf private CAs

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

### Private CA
- [step-ca Dokumentation](https://smallstep.com/docs/step-ca/)
- [Boulder-Projekt](https://github.com/letsencrypt/boulder)
- [Pebble-Testserver](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [DNS-Anbieter →](./dns-providers.md) • [Docker →](./docker.md)

</div>
