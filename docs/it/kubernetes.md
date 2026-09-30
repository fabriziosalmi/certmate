# CertMate su Kubernetes

<!-- CERTMATE-TRANSLATED-FROM c0ef74162bfa4e87 -->

Installa CertMate con il suo chart Helm, direttamente o tramite Argo CD o Flux, poi dimensionalo per la produzione. Il README del chart descrive ogni valore: [charts/certmate/README.md](../../charts/certmate/README.md).

## Installazione con Helm

Il chart viene pubblicato su GHCR come artefatto OCI a ogni rilascio, quindi non serve il passaggio `helm repo add` (Helm 3.8+). La sua versione coincide con quella di CertMate: senza `--version` Helm prende la più recente, mentre `--version X.Y.Z` ne fissa una.

Crea prima il Secret, così l'istanza mantiene lo stesso token e la stessa chiave di sessione tra un riavvio e l'altro:

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

Apri `http://127.0.0.1:8000`. La prima pagina crea l'account amministratore e chiede l'`API_BEARER_TOKEN` salvato nel Secret (`kubectl -n certmate get secret certmate-secrets -o jsonpath='{.data.API_BEARER_TOKEN}' | base64 -d`). Aggiungi `CLOUDFLARE_TOKEN` allo stesso Secret per creare all'avvio un account DNS Cloudflare; gli altri provider DNS si configurano dall'interfaccia web.

Per aggiornare usa `helm upgrade certmate oci://ghcr.io/fabriziosalmi/charts/certmate --namespace certmate --reuse-values`. Per Ingress, persistenza e backup, vedi il README del chart.

## GitOps con Argo CD

Il Secret visto sopra si crea una sola volta, fuori da Git. Poi:

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

`repoURL` non ha il prefisso `oci://`: Argo CD riceve separatamente il percorso del registry e il nome del chart. `2.*` segue i nuovi rilasci 2.x; indica una versione esatta per fissarne una.

## GitOps con Flux

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

`semver: "2.x"` segue i nuovi rilasci 2.x; usa `tag: X.Y.Z` per fissarne uno.

Questi tre metodi sono stati verificati su un cluster k3s 1.31, con Helm 4.1, Argo CD 3.5 e Flux (source-controller 1.9): ciascuno installa il chart e l'istanza risulta in salute.

---

# Note di produzione

Questa parte raccoglie la configurazione di dimensionamento di base per CertMate quando viene eseguito dietro un Ingress/HTTPRoute Kubernetes e utilizza un backend di certificati remoto come Azure Key Vault.

## Risorse consigliate

CertMate esegue gunicorn insieme ai sottoprocessi certbot nello stesso container. Durante la creazione o il rinnovo dei certificati, certbot e i plugin DNS possono generare temporaneamente un picco di memoria elevato. Con Azure Key Vault in modalità `both`, elencare i certificati comporta anche chiamate remote, quindi limiti molto ridotti possono trasformare operazioni di routine in riavvii OOM.

Utilizza questa configurazione di base per i pod di produzione che gestiscono decine di certificati:

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

Con il chart Helm, imposta gli stessi valori nel tuo file di values. Il limite di memoria predefinito del chart è 512Mi, che, come spiega il paragrafo successivo, è troppo poco per l'emissione sotto carico:

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

Per il caso di errore specifico in cui un pod con `memory: 512Mi` si riavvia durante la creazione di un certificato, aumenta prima il limite di memoria. Il percorso del codice evita ora i sottoprocessi `openssl` della precedente vista elenco, utilizza letture leggere delle informazioni sui certificati tramite Azure Key Vault, ed esclude le directory temporanee/storiche di certbot dai backup di routine, ma certbot ha comunque bisogno di margine durante l'emissione dei certificati.

## Esempio di patch del Deployment

Per un Deployment non gestito dal chart Helm (il chart etichetta i suoi pod con `app.kubernetes.io/name=certmate`, non con `app=certmate`). Con il chart, usa invece i values visti sopra.

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

Verifica il motivo del successivo riavvio dopo l'applicazione:

```bash
kubectl -n certificate-management describe pod -l app=certmate | grep -A6 "Last State"
kubectl -n certificate-management top pod -l app=certmate
```

## Numero di repliche

Esegui `replicas: 1`. CertMate esegue lo scheduler di rinnovo dei certificati **all'interno del processo**, quindi ogni pod (e ogni worker gunicorn) avvia il controllo dei rinnovi in modo indipendente. Con più di uno scrittore questo significa ordini ACME duplicati e il rate limit della CA sui certificati duplicati, oltre a race condition sulle impostazioni locali, sui metadati, sui backup e sullo stato di esecuzione che CertMate mantiene anche quando i certificati risiedono in un backend remoto (Azure Key Vault, Vault, S3).

Un `flock` locale all'host (`/app/data/.renewal.lock`) impedisce i rinnovi duplicati quando più worker/container condividono lo **stesso** volume di dati su un unico host, ma **non** coordina pod su volumi/nodi separati. Aumenta quindi il numero di repliche solo se ogni percorso mutabile (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) è un unico volume condiviso da tutti i pod E hai validato il comportamento dei rinnovi; altrimenti mantieni un solo scrittore e, per la disponibilità, metti davanti una singola istanza attiva invece di scalare questo Deployment.

## Il badge di stato del deployment mostra "Backend: Unreachable"

*Aggiornato il 2026-05-25 (vedi [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Il badge di stato del deployment nella dashboard è un indicatore di salute facoltativo e **non influisce** sull'emissione, il rinnovo o il download. Il processo di CertMate apre una connessione TLS diretta verso `<domain>:443` e confronta l'impronta digitale del certificato servito con quella memorizzata:

- **Deployed** — l'handshake ha avuto successo e l'impronta digitale corrisponde.
- **Wrong Cert** — l'handshake ha avuto successo ma viene servito un certificato diverso.
- **Unreachable** — il pod non ha potuto aprire alcuna connessione TLS verso il dominio.

Su Kubernetes, **Unreachable per ogni certificato è previsto** ogni volta che il pod CertMate non riesce a raggiungere direttamente il tuo IP pubblico/Ingress. Cause comuni:

- Il dominio risolve un IP pubblico/Ingress non raggiungibile dall'interno del pod (hairpin/NAT o DNS split-horizon).
- Una `NetworkPolicy` di uscita blocca il traffico in uscita sulla porta 443.
- TLS viene terminato dal controller Ingress o da un load balancer esterno, quindi non esiste un endpoint che CertMate possa raggiungere direttamente.
- La probe è semplicemente lenta e supera il budget predefinito di 3 secondi.

Se la destinazione è raggiungibile ma lenta, aumenta il budget della probe:

```yaml
env:
  - name: CERTMATE_TLS_PROBE_TIMEOUT_SECONDS
    value: "10"   # accepts 1–30 seconds; default is 3
```

In caso contrario, il badge può essere ignorato in tutta sicurezza in una topologia Ingress/Kubernetes: i certificati vengono emessi e serviti correttamente anche quando CertMate non riesce a verificarli autonomamente.
