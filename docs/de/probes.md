# Deployment Probes

Probes prüfen, ob Ihre Zertifikate im Netzwerk erreichbar sind, indem sie einen Live-TLS-Handshake mit dem deployten Server durchführen.

## Konfiguration

Konfigurieren Sie Probes pro Domain unter **Einstellungen → Deployment Probes**.

| Feld | Beschreibung |
|---|---|
| Domain | Die zu prüfende Zertifikatsdomain |
| Port | TCP-Port (Standard: 443 für HTTPS/TLS, 587 für SMTP STARTTLS) |
| Protokoll | `HTTPS/TLS` — Standard-HTTPS-Handshake, `TLS` — reines TLS ohne HTTP, `SMTP STARTTLS` — SMTP mit TLS-Upgrade |

Protokoll und Port werden in der `metadata.json` des Zertifikats unter den Schlüsseln `deployment_protocol` und `deployment_port` gespeichert.

## Funktionsweise

### Backend-Probe

1. Das Backend liest den konfigurierten Port und das Protokoll aus den Zertifikatsmetadaten.
2. Eine Socket-Verbindung wird geöffnet und ein TLS-Handshake durchgeführt.
3. Der Fingerabdruck des gelieferten Zertifikats wird mit dem lokal gespeicherten Zertifikat verglichen.
4. Das Ergebnis (erreichbar, deployed, Zertifikatsübereinstimmung) wird für 5 Minuten zwischengespeichert (konfigurierbar).

### Browser-Fallback

Wenn die Backend-Probe den Server als nicht erreichbar meldet **und** das Protokoll `HTTPS/TLS` ist, wird ein browserseitiger Fallback über `fetch(..., { mode: 'no-cors' })` ausgelöst. Dadurch kann die Erreichbarkeit auch dann geprüft werden, wenn das Backend keine Verbindung herstellen kann (z. B. bei Netzwerksegmentierung).

Für die Protokolle `TLS` und `SMTP STARTTLS` wird der Browser-Fallback **übersprungen**, da Browser keine reinen TLS- oder SMTP-Verbindungen aufbauen können. Der Browser-Status zeigt „Nicht geprüft".

### Cache

| Schicht | TTL | Umgehung |
|---|---|---|
| Backend (Speicher) | 300 s (Standard) | Query-Parameter `?refresh=1` |
| Frontend (Speicher) | 300 s | `forceRefresh=true` (Schaltfläche „Probe prüfen") |

## API

### Deployment-Status prüfen

```
GET /api/certificates/<domain>/deployment-status
GET /api/certificates/<domain>/deployment-status?refresh=1
```

Gibt zurück:

| Feld | Typ | Beschreibung |
|---|---|---|
| domain | string | Die geprüfte Domain |
| deployed | boolean | Ob ein Zertifikat ausgeliefert wurde |
| reachable | boolean | Ob der Server geantwortet hat |
| certificate_match | boolean/null | Ob das gelieferte Zertifikat mit dem gespeicherten übereinstimmt |
| method | string | Verwendetes Protokoll (`https-tls`, `tls`, `smtp-starttls`) |
| port | integer | Geprüfter TCP-Port |
| protocol | string | Identisch mit method |
| error | string | Fehlermeldung, wenn die Probe fehlgeschlagen ist |
| browser | object | Ergebnis des Browser-Fallbacks (nur HTTPS) |

### Probe konfigurieren

```
PATCH /api/certificates/<domain>
```

```json
{ "deployment_port": 444, "deployment_protocol": "https-tls" }
```

Auf `null` setzen, um die Probe-Konfiguration zu entfernen:

```json
{ "deployment_port": null, "deployment_protocol": null }
```
