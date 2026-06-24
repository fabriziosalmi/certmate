# Note di produzione Kubernetes

Questa guida raccoglie la configurazione di dimensionamento di base per CertMate quando viene eseguito dietro un Ingress/HTTPRoute Kubernetes e utilizza un backend di certificati remoto come Azure Key Vault.

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

Per il caso di errore specifico in cui un pod con `memory: 512Mi` si riavvia durante la creazione di un certificato, aumenta prima il limite di memoria. Il percorso del codice evita ora i sottoprocessi `openssl` della precedente vista elenco, utilizza letture leggere delle informazioni sui certificati tramite Azure Key Vault, ed esclude le directory temporanee/storiche di certbot dai backup di routine, ma certbot ha comunque bisogno di margine durante l'emissione dei certificati.

## Esempio di applicazione del patch

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

Esegui `replicas: 1` a meno che tutti i percorsi mutabili (`/app/data`, `/app/certificates`, `/app/backups`, `/app/logs`) non siano supportati da uno storage sicuro per scritture concorrenti e tu abbia validato il comportamento dello scheduler e del rinnovo per pod multipli. Azure Key Vault può archiviare i certificati in remoto, ma CertMate mantiene comunque localmente le impostazioni, i metadati, i backup e lo stato di esecuzione.

## Il badge di stato del deployment mostra "Backend: Unreachable"

*Aggiornato il 2026-05-25 (vedi [#263](https://github.com/fabriziosalmi/certmate/issues/263)).*

Il badge di stato del deployment nella dashboard è un indicatore di salute facoltativo e **non influisce** sull'emissione, il rinnovo o il download. Il processo di CertMate apre una connessione TLS diretta verso `<domain>:443` e confronta l'impronta digitale del certificato servito con quella memorizzata:

- **Deployed** — l'handshake ha avuto successo e l'impronta digitale corrisponde.
- **Wrong Cert** — l'handshake ha avuto successo ma viene servito un certificato diverso.
- **Unreachable** — il pod non ha potuto aprire una connessione TLS verso il dominio.

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

In caso contrario, il badge può essere ignorato in tutta sicurezza in una topologia Ingress/Kubernetes — i certificati vengono emessi e serviti correttamente anche quando CertMate non riesce a verificarli autonomamente.

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Guida Docker →](./docker.md)

</div>
