# Sondes de Déploiement (Probes)

Les sondes vérifient que vos certificats sont accessibles sur le réseau en effectuant une poignée de main TLS en direct avec le serveur déployé.

## Configuration

Configurez les sondes par domaine dans **Paramètres → Sondes de déploiement**.

| Champ | Description |
|---|---|
| Domaine | Le domaine du certificat à sonder |
| Port | Port TCP (défaut : 443 pour HTTPS/TLS, 587 pour SMTP STARTTLS) |
| Protocole | `HTTPS/TLS` — handshake HTTPS standard, `TLS` — TLS brut sans HTTP, `SMTP STARTTLS` — SMTP puis mise à niveau TLS |

Le protocole et le port sont stockés dans le `metadata.json` du certificat sous les clés `deployment_protocol` et `deployment_port`.

## Fonctionnement

### Sonde backend

1. Le backend lit le port et le protocole configurés dans les métadonnées du certificat.
2. Une connexion socket est ouverte et une poignée de main TLS est effectuée.
3. L'empreinte du certificat servi est comparée à celle du certificat local.
4. Le résultat (accessible, déployé, correspondance certificat) est mis en cache pendant 5 minutes (configurable).

### Sonde navigateur (fallback)

Quand la sonde backend indique que le serveur est injoignable **et** que le protocole est `HTTPS/TLS`, une sonde de secours côté navigateur est déclenchée via `fetch(..., { mode: 'no-cors' })`. Cela permet de vérifier l'accessibilité même lorsque le backend ne peut pas se connecter (ex. segmentation réseau).

Pour les protocoles `TLS` et `SMTP STARTTLS`, la sonde navigateur est **ignorée** car les navigateurs ne peuvent pas effectuer de connexions TLS brutes ou SMTP. Le statut navigateur affiche « Non vérifié ».

### Cache

| Couche | Durée | Contournement |
|---|---|---|
| Backend (mémoire) | 300 s (défaut) | Paramètre `?refresh=1` |
| Frontend (mémoire) | 300 s | `forceRefresh=true` (bouton Vérifier la sonde) |

## API

### Vérifier le statut de déploiement

```
GET /api/certificates/<domain>/deployment-status
GET /api/certificates/<domain>/deployment-status?refresh=1
```

Retourne :

| Champ | Type | Description |
|---|---|---|
| domain | string | Le domaine sondé |
| deployed | boolean | Un certificat a-t-il été servi |
| reachable | boolean | Le serveur a-t-il répondu |
| certificate_match | boolean/null | Le certificat servi correspond-il au certificat local |
| method | string | Protocole utilisé (`https-tls`, `tls`, `smtp-starttls`) |
| port | integer | Port TCP sondé |
| protocol | string | Identique à method |
| error | string | Message d'erreur si la sonde a échoué |
| browser | object | Résultat de la sonde navigateur (HTTPS uniquement) |

### Configurer une sonde

```
PATCH /api/certificates/<domain>
```

```json
{ "deployment_port": 444, "deployment_protocol": "https-tls" }
```

Mettre à `null` pour supprimer la configuration :

```json
{ "deployment_port": null, "deployment_protocol": null }
```
