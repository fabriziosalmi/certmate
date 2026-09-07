# Deployment Probes

Probes prüfen, ob Ihre Zertifikate im Netzwerk erreichbar sind, indem sie einen Live-TLS-Handshake mit dem deployten Server durchführen.

## Konfiguration

Konfigurieren Sie Probes pro Domain unter **Einstellungen → Deployment Probes**.

| Feld | Beschreibung |
|---|---|
| Domain | Die zu prüfende Zertifikatsdomain |
| Host | Hostname für die Verbindung und als SNI. Optional — standardmäßig die Domain. **Bei Wildcards erforderlich** (siehe unten) |
| Port | TCP-Port (Standard: 443 für HTTPS/TLS, 587 für SMTP STARTTLS) |
| Protokoll | `HTTPS/TLS` — Standard-HTTPS-Handshake, `TLS` — reines TLS ohne HTTP, `SMTP STARTTLS` — SMTP mit TLS-Upgrade |

Host, Port und Protokoll werden in der `metadata.json` des Zertifikats unter
`deployment_host`, `deployment_port` und `deployment_protocol` gespeichert.

### Wildcard-Zertifikate

Ein Wildcard-Zertifikat **kann ohne Host nicht geprüft werden**, denn ein
Wildcard deckt seinen eigenen Apex nicht ab: `*.example.com` gilt nicht für
`example.com`, eine Verbindung zum Apex würde also gegen den falschen Namen
vergleichen. Statt für jedes Wildcard ein rotes „Falsches Zertifikat" zu melden,
zeigt CertMate den neutralen Status **Nicht überprüfbar**, bis ein Host gesetzt
ist.

Setzen Sie **Host** auf einen Namen, den das Zertifikat tatsächlich abdeckt —
`www.example.com` für `*.example.com` — und die Prüfung läuft normal. Das Feld
schlägt einen vor.

Wird das Host-Feld geleert, wird der Host entfernt; ein versehentlich gesetzter
Host lässt sich so korrigieren, ohne die Probe zu löschen und neu anzulegen.

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
