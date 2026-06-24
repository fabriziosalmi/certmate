# Kubernetes-Produktionshinweise

Dieser Leitfaden enthält die Basiswerte für die Produktionsdimensionierung von CertMate, wenn es hinter einem Kubernetes Ingress/HTTPRoute betrieben wird und ein entferntes Zertifikat-Backend wie Azure Key Vault verwendet.

## Empfohlene Ressourcen

CertMate führt gunicorn zusammen mit certbot-Subprozessen im selben Container aus. Während der Erstellung oder Erneuerung von Zertifikaten können certbot und DNS-Plugins vorübergehend zu einem erheblichen Speicher-Spike führen. Mit Azure Key Vault im Modus `both` werden beim Auflisten von Zertifikaten ebenfalls entfernte Aufrufe durchgeführt, sodass sehr enge Limits Routineoperationen in OOM-Neustarts verwandeln können.

Verwenden Sie diese Basiskonfiguration für Produktions-Pods, die Dutzende von Zertifikaten verwalten:

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
env:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
  - name: GUNICORN_TIMEOUT
    value: "300"
```

Für den spezifischen Fehlerfall, bei dem ein Pod mit `memory: 512Mi` während der Zertifikatserstellung neu startet, erhöhen Sie zuerst das Speicherlimit. Der Code-Pfad vermeidet nun die früheren `openssl`-Subprozesse der Listenansicht, verwendet leichtgewichtige Azure Key Vault-Zertifikatsinformationslesungen und schließt certbot-Scratch-/Verlaufsverzeichnisse von Routine-Backups aus — certbot benötigt jedoch beim Ausstellen von Zertifikaten weiterhin Puffer.

## Beispiel für einen Deployment-Patch

```bash
kubectl -n certificate-management patch deployment certmate --type='strategic' -p '
spec:
  template:
    spec:
      containers:
        - name: certmate
          resources:
            requests:
              cpu: 250m
              memory: 512Mi
            limits:
              cpu: "1"
              memory: 1536Mi
          env:
            - name: CERTMATE_CERT_INFO_CACHE_TTL
              value: "60"
            - name: GUNICORN_TIMEOUT
              value: "300"
'
```

Überprüfen Sie nach der Anwendung den nächsten Neustart-Grund:

```bash
kubectl -n certificate-management describe pod -l app=certmate | grep -A6 "Last State"
kubectl -n certificate-management top pod -l app=certmate
```

## Anzahl der Replikas

Führen Sie `replicas: 1` aus, es sei denn, alle veränderbaren Pfade (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) werden durch einen Speicher unterstützt, der für gleichzeitige Schreibzugriffe geeignet ist, und Sie haben das Planer-/Erneuerungsverhalten für mehrere Pods validiert. Azure Key Vault kann Zertifikate remote speichern, aber CertMate bewahrt Einstellungen, Metadaten, Backups und den Laufzeitstatus weiterhin lokal auf.

## Das Deployment-Status-Badge zeigt "Backend: Unreachable"

*Aktualisiert am 2026-05-25 (siehe [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Das Deployment-Status-Badge auf dem Dashboard ist ein optionaler Gesundheitsindikator und **beeinträchtigt nicht** die Ausstellung, Erneuerung oder den Download. Der CertMate-Prozess selbst öffnet eine einfache TLS-Verbindung zu `<domain>:443` und vergleicht den Fingerabdruck des bereitgestellten Zertifikats mit dem gespeicherten:

- **Deployed** — der Handshake war erfolgreich und der Fingerabdruck stimmt überein.
- **Wrong Cert** — der Handshake war erfolgreich, aber ein anderes Zertifikat wird bereitgestellt.
- **Unreachable** — der Pod konnte keine TLS-Verbindung zur Domain aufbauen.

Auf Kubernetes ist **Unreachable für jedes Zertifikat zu erwarten**, wenn der CertMate-Pod keine direkte Verbindung zu Ihrer öffentlichen/Ingress-IP aufbauen kann. Häufige Ursachen:

- Die Domain löst sich in eine öffentliche/Ingress-IP auf, die vom Pod aus nicht routbar ist (Hairpin/NAT oder Split-Horizon-DNS).
- Eine ausgehende `NetworkPolicy` blockiert den ausgehenden Port 443.
- TLS wird von Ihrem Ingress-Controller oder einem externen Load Balancer terminiert, sodass kein Endpoint vorhanden ist, den CertMate direkt erreichen kann.
- Die Probe ist schlicht zu langsam und überschreitet das Standard-Budget von 3 Sekunden.

Wenn das Ziel erreichbar, aber langsam ist, erhöhen Sie das Probe-Budget:

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

Andernfalls kann das Badge in einer Ingress/Kubernetes-Topologie bedenkenlos ignoriert werden — die Zertifikate werden korrekt ausgestellt und bereitgestellt, auch wenn CertMate sie selbst nicht prüfen kann.

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Docker-Leitfaden →](./docker.md)

</div>
