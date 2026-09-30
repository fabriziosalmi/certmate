# CertMate auf Kubernetes

<!-- CERTMATE-TRANSLATED-FROM c0ef74162bfa4e87 -->

Installieren Sie CertMate mit seinem Helm-Chart, direkt oder über Argo CD bzw. Flux, und dimensionieren Sie es anschließend für die Produktion. Die README des Charts beschreibt jeden Wert: [charts/certmate/README.md](../../charts/certmate/README.md).

## Installation mit Helm

Das Chart wird bei jedem Release als OCI-Artefakt auf GHCR veröffentlicht, daher entfällt der Schritt `helm repo add` (Helm 3.8+). Seine Version entspricht der CertMate-Version: Ohne `--version` nimmt Helm die neueste, mit `--version X.Y.Z` wird eine bestimmte festgelegt.

Legen Sie zuerst das Secret an, damit die Instanz über Neustarts hinweg denselben Token und denselben Sitzungsschlüssel behält:

```bash
kubectl create namespace certmate
kubectl -n certmate create secret generic certmate-secrets \
  --from-literal=API_BEARER_TOKEN="$(openssl rand -hex 32)" \
  --from-literal=SECRET_KEY="$(openssl rand -hex 32)" \
  --from-literal=CERTMATE_BACKUP_PASSPHRASE="$(openssl rand -hex 32)"

helm install certmate oci://ghcr.io/fabriziosalmi/charts/certmate \
  --namespace certmate \
  --set secrets.existingSecret=certmate-secrets

kubectl -n certmate port-forward svc/certmate 8000:8000
```

Öffnen Sie `http://127.0.0.1:8000`. Die erste Seite legt das Administratorkonto an und fragt nach dem im Secret gespeicherten `API_BEARER_TOKEN` (`kubectl -n certmate get secret certmate-secrets -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d`). Fügen Sie demselben Secret `CLOUDFLARE_TOKEN` hinzu, um ein Cloudflare-DNS-Konto vorzukonfigurieren; andere DNS-Anbieter werden in der Weboberfläche eingerichtet.

Aktualisieren Sie mit `helm upgrade certmate oci://ghcr.io/fabriziosalmi/charts/certmate --namespace certmate --reuse-values`. Zu Ingress, Persistenz und Backups siehe die README des Charts.

## GitOps mit Argo CD

Das obige Secret wird einmalig außerhalb von Git angelegt. Danach:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: certmate
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ghcr.io/fabriziosalmi/charts
    chart: certmate
    targetRevision: "2.*"
    helm:
      valuesObject:
        secrets:
          existingSecret: certmate-secrets
  destination:
    server: https://kubernetes.default.svc
    namespace: certmate
  syncPolicy:
    automated: {}
```

`repoURL` hat kein Präfix `oci://`: Argo CD erwartet den Registry-Pfad und den Chart-Namen getrennt. `2.*` folgt neuen 2.x-Releases; setzen Sie eine exakte Version, um eine bestimmte festzulegen.

## GitOps mit Flux

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: OCIRepository
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  url: oci://ghcr.io/fabriziosalmi/charts/certmate
  ref:
    semver: "2.x"
  layerSelector:
    mediaType: application/vnd.cncf.helm.chart.content.v1.tar+gzip
    operation: copy
---
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: certmate
  namespace: certmate
spec:
  interval: 1h
  chartRef:
    kind: OCIRepository
    name: certmate
  values:
    secrets:
      existingSecret: certmate-secrets
```

`semver: "2.x"` folgt neuen 2.x-Releases; verwenden Sie `tag: X.Y.Z`, um eine bestimmte Version festzulegen.

Alle drei Wege wurden auf einem k3s-1.31-Cluster mit Helm 4.1, Argo CD 3.5 und Flux (source-controller 1.9) geprüft: Jeder installiert das Chart, und die Instanz meldet sich als gesund.

---

# Produktionshinweise

Dieser Teil enthält die Basiswerte für die Produktionsdimensionierung von CertMate,
wenn es hinter einem Kubernetes Ingress/HTTPRoute betrieben wird und ein entferntes
Zertifikat-Backend wie Azure Key Vault verwendet.

## Empfohlene Ressourcen

CertMate führt gunicorn zusammen mit certbot-Subprozessen im selben Container aus. Während
der Erstellung oder Erneuerung von Zertifikaten können certbot und DNS-Plugins vorübergehend
zu einem erheblichen Speicher-Spike führen. Mit Azure Key Vault im Modus `both` werden beim
Auflisten von Zertifikaten ebenfalls entfernte Aufrufe durchgeführt, sodass sehr enge Limits
Routineoperationen in OOM-Neustarts verwandeln können.

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

Mit dem Helm-Chart setzen Sie dasselbe in Ihrer Values-Datei. Das Standard-Speicherlimit des Charts beträgt 512Mi, was – wie der nächste Absatz erklärt – für die Ausstellung unter Last zu klein ist:

```yaml
resources:
  requests:
    cpu: 250m
    memory: 512Mi
  limits:
    cpu: "1"
    memory: 1536Mi
extraEnv:
  - name: CERTMATE_CERT_INFO_CACHE_TTL
    value: "60"
```

Für den spezifischen Fehlerfall, bei dem ein Pod mit `memory: 512Mi` während der
Zertifikatserstellung neu startet, erhöhen Sie zuerst das Speicherlimit. Der Code-Pfad
vermeidet nun die früheren `openssl`-Subprozesse der Listenansicht, verwendet leichtgewichtige
Azure Key Vault-Zertifikatsinformationslesungen und schließt certbot-Scratch-/Verlaufsverzeichnisse
von Routine-Backups aus — certbot benötigt jedoch beim Ausstellen von Zertifikaten weiterhin Puffer.

## Beispiel für einen Deployment-Patch

Für ein Deployment, das nicht vom Helm-Chart verwaltet wird (das Chart kennzeichnet seine Pods mit `app.kubernetes.io/name=certmate`, nicht mit `app=certmate`). Mit dem Chart verwenden Sie stattdessen die obigen Values.

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

Betreiben Sie `replicas: 1`. CertMate führt seinen Planer für die Zertifikatserneuerung
**im Prozess** aus, sodass jeder Pod (und jeder gunicorn-Worker) die Erneuerungsprüfung
unabhängig auslöst. Bei mehr als einem Schreiber bedeutet das doppelte ACME-Bestellungen und
das Rate-Limit der CA für doppelte Zertifikate — dazu Wettläufe bei den lokalen Einstellungen,
Metadaten, Backups und dem Laufzeitstatus, die CertMate auch dann lokal aufbewahrt, wenn die
Zertifikate in einem entfernten Backend liegen (Azure Key Vault, Vault, S3).

Ein host-lokales `flock` (`/app/data/.renewal.lock`) verhindert doppelte Erneuerungen, wenn
mehrere Worker/Container **dasselbe** Datenvolume auf einem Host teilen, koordiniert aber
**keine** Pods auf getrennten Volumes/Nodes. Erhöhen Sie die Anzahl der Replikas daher nur,
wenn jeder veränderbare Pfad (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`)
ein einziges, von allen Pods geteiltes Volume ist UND Sie das Erneuerungsverhalten validiert
haben — andernfalls behalten Sie einen einzigen Schreiber bei und stellen für die Verfügbarkeit
eine einzelne aktive Instanz bereit, statt dieses Deployment zu skalieren.

## Das Deployment-Status-Badge zeigt "Backend: Unreachable"

*Aktualisiert am 2026-05-25 (siehe [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Das Deployment-Status-Badge auf dem Dashboard ist ein optionaler Gesundheitsindikator und
**beeinträchtigt nicht** die Ausstellung, Erneuerung oder den Download. Der CertMate-Prozess
selbst öffnet eine einfache TLS-Verbindung zu `<domain>:443` und vergleicht den Fingerabdruck
des bereitgestellten Zertifikats mit dem gespeicherten:

- **Deployed** — der Handshake war erfolgreich und der Fingerabdruck stimmt überein.
- **Wrong Cert** — der Handshake war erfolgreich, aber ein anderes Zertifikat wird bereitgestellt.
- **Unreachable** — der Pod konnte überhaupt keine TLS-Verbindung zur Domain aufbauen.

Auf Kubernetes ist **Unreachable für jedes Zertifikat zu erwarten**, wenn der
CertMate-Pod keine direkte Verbindung zu Ihrer öffentlichen/Ingress-IP aufbauen kann. Häufige Ursachen:

- Die Domain löst sich in eine öffentliche/Ingress-IP auf, die vom Pod aus nicht
  routbar ist (Hairpin/NAT oder Split-Horizon-DNS).
- Eine ausgehende `NetworkPolicy` blockiert den ausgehenden Port 443.
- TLS wird von Ihrem Ingress-Controller oder einem externen Load Balancer terminiert, sodass
  kein Endpoint vorhanden ist, den CertMate direkt erreichen kann.
- Die Probe ist schlicht zu langsam und überschreitet das Standard-Budget von 3 Sekunden.

Wenn das Ziel erreichbar, aber langsam ist, erhöhen Sie das Probe-Budget:

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

Andernfalls kann das Badge in einer Ingress/Kubernetes-Topologie bedenkenlos ignoriert werden — die
Zertifikate werden korrekt ausgestellt und bereitgestellt, auch wenn CertMate sie selbst nicht
prüfen kann.
