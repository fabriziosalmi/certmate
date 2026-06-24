# CertMate Certificats Clients - Référence API

## Vue d'ensemble

L'API CertMate de gestion des certificats clients fournit des endpoints REST pour une gestion complète des certificats avec authentification, limitation de débit et journalisation d'audit.

**URL de base** : `http://localhost:5000/api`
**Authentification** : Bearer Token (requis sur tous les endpoints)
**Type de contenu** : `application/json`

---

## Authentification

Tous les endpoints API nécessitent une authentification par Bearer token.

### Format de l'en-tête

```
Authorization: Bearer VOTRE_TOKEN
```

### Exemple de requête

```bash
curl -X GET http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer VOTRE_TOKEN" \
 -H "Content-Type: application/json"
```

---

## Limitation de débit (Rate Limiting)

Les endpoints API ont des limites de débit pour prévenir les abus :

| Endpoint           | Limite | Par     |
| ------------------ | ------ | ------- |
| Général            | 100    | minute  |
| Créer un certificat| 30     | minute  |
| Opérations par lots| 10     | minute  |
| Statut OCSP        | 200    | minute  |
| Téléchargement CRL | 60     | minute  |

### Réponse en cas de limite atteinte

Lorsque la limite est dépassée, vous recevez :

```
HTTP 429 Too Many Requests

{
  "error": "Rate limit exceeded",
  "message": "Too many requests. Please try again later.",
  "retry_after": 60
}
```

---

## Endpoints

### Gestion des certificats

#### 1. Créer un certificat

**Endpoint** : `POST /client-certs/create`

Crée un nouveau certificat client.

**Requête** :
```json
{
  "common_name": "user@example.com",
  "email": "user@example.com",
  "organization": "ACME Corp",
  "organizational_unit": "Engineering",
  "cert_usage": "api-mtls",
  "days_valid": 365,
  "generate_key": true,
  "notes": "Production certificate"
}
```

**Paramètres** :
- `common_name` (obligatoire) — Sujet du certificat
- `email` (optionnel) — Adresse e-mail
- `organization` (optionnel) — Nom de l'organisation
- `organizational_unit` (optionnel) — Nom du service
- `cert_usage` (optionnel) — Type d'usage : `api-mtls`, `vpn`, ou personnalisé
- `days_valid` (optionnel) — Durée de validité en jours (défaut : 365)
- `generate_key` (optionnel) — Générer une clé privée (défaut : true)
- `notes` (optionnel) — Notes supplémentaires

**Réponse** (201 Created) :
```json
{
  "identifier": "cert-abc123",
  "common_name": "user@example.com",
  "serial_number": "12345678901234567890",
  "created_at": "2024-10-30T18:00:00Z",
  "expires_at": "2025-10-30T18:00:00Z",
  "cert_usage": "api-mtls",
  "status": "active"
}
```

**Exemple** :
```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "common_name": "user@example.com",
   "email": "user@example.com",
   "organization": "ACME Corp",
   "cert_usage": "api-mtls",
   "days_valid": 365
 }'
```

---

#### 2. Lister les certificats

**Endpoint** : `GET /client-certs`

Liste tous les certificats clients avec filtrage optionnel.

**Paramètres de requête** :
- `usage` (optionnel) — Filtrer par type d'usage (ex : `api-mtls`)
- `revoked` (optionnel) — Filtrer par statut (`true` ou `false`)
- `search` (optionnel) — Rechercher dans le nom commun

**Réponse** (200 OK) :
```json
{
  "certificates": [{
    "identifier": "cert-001",
    "common_name": "user1@example.com",
    "organization": "ACME Corp",
    "cert_usage": "api-mtls",
    "created_at": "2024-10-30T18:00:00Z",
    "expires_at": "2025-10-30T18:00:00Z",
    "revoked": false,
    "status": "active"
  },
  {
    "identifier": "cert-002",
    "common_name": "user2@example.com",
    "organization": "ACME Corp",
    "cert_usage": "vpn",
    "created_at": "2024-10-29T18:00:00Z",
    "expires_at": "2025-10-29T18:00:00Z",
    "revoked": true,
    "status": "revoked"
  }
  ],
  "total": 2
}
```

**Exemples** :
```bash
# Lister tous les certificats
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrer par type d'usage
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Lister uniquement les révoqués
curl "http://localhost:5000/api/client-certs?revoked=true" \
 -H "Authorization: Bearer TOKEN"

# Rechercher par nom commun
curl "http://localhost:5000/api/client-certs?search=user1" \
 -H "Authorization: Bearer TOKEN"
```

---

#### 3. Obtenir les détails d'un certificat

**Endpoint** : `GET /client-certs/<identifier>`

Récupère les métadonnées complètes d'un certificat.

**Réponse** (200 OK) :
```json
{
  "type": "client_certificate",
  "identifier": "cert-001",
  "common_name": "user@example.com",
  "email": "user@example.com",
  "organization": "ACME Corp",
  "organizational_unit": "Engineering",
  "serial_number": "12345678901234567890",
  "created_at": "2024-10-30T18:00:00Z",
  "expires_at": "2025-10-30T18:00:00Z",
  "cert_usage": "api-mtls",
  "notes": "Production certificate",
  "revocation": {
    "revoked": false,
    "revoked_at": null,
    "reason_revoked": null
  },
  "renewal": {
    "renewal_enabled": true,
    "renewal_threshold_days": 30
  }
}
```

**Exemple** :
```bash
curl http://localhost:5000/api/client-certs/cert-001 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 4. Télécharger les fichiers d'un certificat

**Endpoint** : `GET /client-certs/<identifier>/download/<type>`

Télécharge le certificat, la clé privée ou le CSR.

**Paramètres** :
- `identifier` — ID du certificat
- `type` — Type de fichier : `crt`, `key`, ou `csr`

**Réponse** (200 OK) :
- Content-Type : `application/octet-stream`
- Pièce jointe avec nom approprié

**Exemples** :
```bash
# Télécharger le certificat
curl http://localhost:5000/api/client-certs/cert-001/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o certificate.crt

# Télécharger la clé privée
curl http://localhost:5000/api/client-certs/cert-001/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o private.key

# Télécharger le CSR
curl http://localhost:5000/api/client-certs/cert-001/download/csr \
 -H "Authorization: Bearer TOKEN" \
 -o request.csr
```

---

#### 5. Révoquer un certificat

**Endpoint** : `POST /client-certs/<identifier>/revoke`

Révoque un certificat avec une raison optionnelle.

**Requête** (optionnelle) :
```json
{
  "reason": "compromised"
}
```

**Réponse** (200 OK) :
```json
{
  "message": "Certificate revoked: cert-001",
  "revoked_at": "2024-10-30T18:15:00Z",
  "reason": "compromised"
}
```

**Exemple** :
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "reason": "compromised"
 }'
```

---

#### 6. Renouveler un certificat

**Endpoint** : `POST /client-certs/<identifier>/renew`

Renouvelle un certificat (même CN, nouveau numéro de série).

**Réponse** (201 Created) :
```json
{
  "identifier": "cert-001-renewed",
  "common_name": "user@example.com",
  "serial_number": "98765432109876543210",
  "created_at": "2024-10-30T18:20:00Z",
  "expires_at": "2025-10-30T18:20:00Z",
  "status": "active"
}
```

**Exemple** :
```bash
curl -X POST http://localhost:5000/api/client-certs/cert-001/renew \
 -H "Authorization: Bearer TOKEN"
```

---

#### 7. Obtenir les statistiques

**Endpoint** : `GET /client-certs/stats`

Récupère les statistiques d'utilisation des certificats.

**Réponse** (200 OK) :
```json
{
  "total": 100,
  "active": 85,
  "revoked": 15,
  "expiring_soon": 8,
  "by_usage": {
    "api-mtls": 60,
    "vpn": 35,
    "other": 5
  },
  "created_count": 100,
  "renewal_enabled": 92
}
```

**Exemple** :
```bash
curl http://localhost:5000/api/client-certs/stats \
 -H "Authorization: Bearer TOKEN"
```

---

#### 8. Import par lots de certificats

**Endpoint** : `POST /client-certs/batch`

Crée plusieurs certificats à partir de données CSV en une seule requête.

**Requête** :
```json
{
  "headers": ["common_name", "email", "organization", "cert_usage", "days_valid"],
  "rows": [["user1@example.com", "user1@example.com", "ACME Corp", "api-mtls", "365"],
           ["user2@example.com", "user2@example.com", "ACME Corp", "vpn", "365"],
           ["user3@example.com", "user3@example.com", "ACME Corp", "api-mtls", "365"]
          ]
}
```

**Réponse** (201 Created) :
```json
{
  "total": 3,
  "successful": 3,
  "failed": 0,
  "errors": [],
  "certificates": [{
    "identifier": "cert-batch-001",
    "common_name": "user1@example.com"
  },
  {
    "identifier": "cert-batch-002",
    "common_name": "user2@example.com"
  },
  {
    "identifier": "cert-batch-003",
    "common_name": "user3@example.com"
  }
  ]
}
```

**Exemple** :
```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "headers": ["common_name", "email", "organization"],
   "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
            ["user2@example.com", "user2@example.com", "ACME Corp"]
           ]
 }'
```

---

### OCSP & CRL

#### 9. Requête de statut OCSP

**Endpoint** : `GET /ocsp/status/<serial_number>`

Interroge le statut d'un certificat via OCSP.

**Réponse** (200 OK) :
```json
{
  "response_status": "successful",
  "certificate_status": "good|revoked|unknown",
  "certificate_serial": 12345678,
  "this_update": "2024-10-30T18:00:00Z",
  "next_update": null,
  "responder_name": "CertMate OCSP Responder"
}
```

**Exemple** :
```bash
curl http://localhost:5000/api/ocsp/status/12345678 \
 -H "Authorization: Bearer TOKEN"
```

---

#### 10. Distribution de la CRL

**Endpoint** : `GET /crl/download/<format_type>`

Télécharge la liste de révocation des certificats (CRL).

**Paramètres** :
- `format_type` — `pem`, `der`, ou `info`

**Réponse** :
- Pour `pem` et `der` : Pièce jointe
- Pour `info` : JSON avec métadonnées CRL

**Exemples** :
```bash
# Télécharger la CRL en format PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Télécharger la CRL en format DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Obtenir les infos CRL
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

**Réponse des infos CRL** :
```json
{
  "status": "available",
  "issuer": "CN=CertMate CA, O=CertMate",
  "last_update": "2024-10-30T18:00:00Z",
  "next_update": "2024-10-31T18:00:00Z",
  "revoked_count": 5,
  "revoked_serials": [12345678,
   87654321
  ]
}
```

---

#### 11. Télécharger les fichiers de certificat de domaine

**Endpoint** : `GET /certificates/<domain>/download`

Télécharge les fichiers de certificat pour un domaine spécifique. Par défaut, cet endpoint renvoie une archive ZIP contenant tous les composants du certificat. Un fichier spécifique peut être demandé via le paramètre de requête `file`. Un mode JSON est également disponible pour l'automatisation qui souhaite obtenir tous les PEM en une seule réponse.

**Paramètres** :
- `domain` (Path) — Le nom de domaine associé au certificat.
- `file` (Query, optionnel) — Spécifie un fichier unique à télécharger.
  - Valeurs supportées : `fullchain.pem`, `privkey.pem`, `combined.pem`
- `format` (Query, optionnel) — Mettre à `json` pour renvoyer tous les fichiers du certificat dans un objet JSON.

**Réponse** (200 OK) :
- **Par défaut** : `application/zip` (un fichier ZIP contenant tous les fichiers PEM)
- **Avec paramètre `file`** : `application/x-pem-file` (le contenu brut du fichier demandé)
- **Avec `format=json`** : `application/json` avec `domain`, `cert_pem`, `chain_pem`, `fullchain_pem` et `private_key_pem`

La forme JSON est le format d'automatisation préféré pour Ansible, Salt ou tout autre client souhaitant écrire directement les fichiers PEM.

**Exemples** :

```bash
# Télécharger tous les fichiers sous forme d'archive ZIP
curl http://localhost:5000/api/certificates/example.com/download \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.zip

# Télécharger uniquement le fichier fullchain.pem
curl "http://localhost:5000/api/certificates/example.com/download?file=fullchain.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o fullchain.pem

# Télécharger uniquement la clé privée
curl "http://localhost:5000/api/certificates/example.com/download?file=privkey.pem" \
 -H "Authorization: Bearer TOKEN" \
 -o privkey.pem

# Télécharger le bundle complet en JSON
curl "http://localhost:5000/api/certificates/example.com/download?format=json" \
 -H "Authorization: Bearer TOKEN" \
 -o example_com_bundle.json

```

---

#### 12. Réémettre un certificat de domaine (modifier la configuration)

**Endpoint** : `POST /certificates/<domain>/reissue`

Modifie la configuration d'un certificat et le réémet sur place — permet d'étendre ou de supprimer des entrées SAN sans supprimer + recréer. Les champs omis conservent les valeurs avec lesquelles le certificat a été émis (lues depuis ses métadonnées), évitant ainsi de ressaisir la configuration DNS/alias/CA. Le certificat actuel continue d'être servi jusqu'à ce que la réémission réussisse. La forme de la clé est préservée sauf modification explicite (aucun indicateur de clé n'est envoyé et certbot conserve la clé de la lignée).

**Corps de la requête** (tous les champs sont optionnels) :
```json
{
  "san_domains": ["www.example.com", "api.example.com"],
  "domain_alias": "",
  "async": true
}
```

- `san_domains` : ensemble de remplacement des SAN — omettre pour conserver, `[]` pour supprimer tous les SAN
- `domain_alias` : omettre pour conserver, `""` pour effacer
- `dns_provider`, `account_id`, `ca_provider`, `challenge_type` : omettre pour conserver
- `key_type`/`key_size`/`elliptic_curve` : omettre pour conserver la forme de clé existante
- `async` : différer l'émission vers un job d'arrière-plan (202 + ID du job, interroger `GET /certificates/jobs/<job_id>`)

**Réponse** (200 OK, ou 202 Accepted avec `async`) : message, domain, dns_provider, ca_provider, duration.

**Erreurs** : 404 quand aucun certificat n'existe pour le domaine (utiliser create), 403 scope, 400 validation, 409 opération en cours, 422 échec certbot (le certificat précédent est toujours en place).

**Exemple** :
```bash
curl -X POST http://localhost:5000/api/certificates/example.com/reissue \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{"san_domains": ["www.example.com", "api.example.com"]}'
```

---

## Gestion des erreurs

### Format de la réponse d'erreur

```json
{
  "error": "Error message",
  "code": "ERROR_CODE",
  "status": 400
}
```

### Codes de statut HTTP courants

| Code | Signification      | Exemple                         |
| ---- | ------------------ | ------------------------------- |
| 200  | Succès             | Certificat listé                |
| 201  | Créé               | Certificat créé                 |
| 400  | Mauvaise requête   | Champ obligatoire manquant      |
| 401  | Non autorisé       | Token invalide/manquant         |
| 404  | Non trouvé         | Le certificat n'existe pas      |
| 429  | Trop de requêtes   | Limite de débit dépassée        |
| 500  | Erreur serveur     | Erreur interne                  |
| 503  | Service indisponible| OCSP/CRL non disponible        |

### Exemple d'erreur

```bash
curl http://localhost:5000/api/client-certs/invalid-id \
 -H "Authorization: Bearer TOKEN"

# Réponse
{
  "error": "Certificate not found: invalid-id",
  "code": 404,
  "status": 404
}
```

---

## Journalisation d'audit

Les opérations du cycle de vie des certificats ainsi que les modifications de configuration et de contrôle d'accès sont enregistrées dans un journal d'audit. Cela inclut les chemins critiques du cycle de vie — créations, renouvellements, réémissions, déploiements et activations/désactivations d'auto-renouvellement réussis et échoués, ainsi que les **renouvellements non supervisés (planifiés)** — chacun attribué à l'acteur qui l'a effectué et au déclencheur qui en est la cause.

### Format du journal

Le journal d'audit est écrit dans `logs/audit/certificate_audit.log`. Chaque ligne est une ligne de log Python standard dont le message est l'entrée d'audit JSON :

```
2026-06-15 18:00:00 - certmate.audit - INFO - {"timestamp": "...", ...}
```

Pour récupérer le JSON, divisez chaque ligne sur le littéral ` - INFO - ` et analysez le reste. Notez les deux bases de temps : le préfixe temporel de la ligne est l'heure **locale** du serveur, tandis que le champ `timestamp` du JSON est en **UTC** (ISO-8601). Lisez-le en direct avec :

```bash
tail -f logs/audit/certificate_audit.log
```

### Structure de l'entrée

```json
{
  "timestamp": "2026-06-15T18:00:00.000000+00:00",
  "operation": "renew",
  "resource_type": "certificate",
  "resource_id": "api.example.com",
  "status": "success",
  "user": "api_key:renew-bot",
  "ip_address": "10.0.0.9",
  "details": {"force": false},
  "error": null,
  "actor": {
    "kind": "agent",
    "id": "9f2c…",
    "label": "api_key:renew-bot",
    "token_prefix": "cm_1a2b",
    "agent_session": "sess-9f2"
  },
  "trigger": {"cause": "agent"}
}
```

- **`actor.kind`** — `user` (une session humaine / connexion OIDC), `api_token` (une clé API ou le token Bearer global hérité), `agent` (une clé API explicitement marquée comme agent IA/MCP — voir ci-dessous), `scheduler` (un job de renouvellement non supervisé), ou `system`. Il est dérivé **uniquement de l'identité authentifiée**.
- **`actor.id` / `token_prefix`** — l'ID de clé API stable et le préfixe du token derrière l'action (absent pour le token Bearer global hérité, qui ne peut pas être distingué par appelant — préférez les clés scoped).
- **`actor.agent_session` / `agent_id`** — les valeurs des en-têtes `X-CertMate-Agent-Session` / `X-CertMate-Agent-Id` fournis par le client (le serveur MCP les envoie). Ce sont des **informations déclaratives uniquement** : elles sont enregistrées pour corrélation mais ne changent jamais `actor.kind`, donc un appelant non-agent ne peut pas usurper une attribution `agent`.
- **`trigger.cause`** — `manual`, `api`, `agent`, `scheduled_renewal`, ou `event` ; pour les renouvellements planifiés, `trigger.job_id` nomme le job.

Pour que les actions d'un agent soient enregistrées comme `actor.kind="agent"`, créez une clé API scoped avec `is_agent: true` (une case à cocher dans Paramètres → Clés API, ou `is_agent` dans `POST /api/keys`) et pointez le serveur MCP vers celle-ci. Voir le [guide MCP](./mcp.md).

### Lecture du journal d'audit via l'API

`GET /api/activity?limit=N` renvoie les entrées les plus récentes (admin/lecteur, limité à 500).

### Preuve d'intégrité (chaîne de hachage)

Parallèlement au journal lisible par l'homme, chaque entrée est ajoutée à une **chaîne de hachage** SHA-256 infalsifiable dans `data/audit/certificate_audit.chain.jsonl`. Chaque enregistrement est `{seq, entry, prev_hash, hash}` où `hash` s'engage sur l'entrée et le hachage de l'enregistrement précédent, et `seq` est un compteur sans trou — donc toute modification, suppression ou réordonnancement par quiconque ne peut pas recalculer toute la chaîne est détectable et localisable. Activé par défaut ; désactiver avec `CERTMATE_AUDIT_CHAIN=0`.

**Vérification depuis l'API** : `GET /api/audit/verify` (admin) renvoie le résultat du vérificateur et HTTP `200` quand elle est intacte ou `409` quand elle est cassée :

```json
{"ok": true, "count": 128, "first_seq": 0, "last_seq": 127, "head_hash": "5ee1…", "reason": "intact"}
```

**Vérification hors ligne** : le vérificateur autonome ne dépend que de la bibliothèque standard Python, donc un auditeur peut l'exécuter sans installer ni faire confiance à CertMate :

```bash
python -m modules.core.audit_verify data/audit/certificate_audit.chain.jsonl
# OK: audit chain intact (128 entries, seq 0..127)
# or: FAIL: audit chain broken at seq 42: hash mismatch at seq 42: entry was modified
```

Code de sortie `0` intact, `1` cassé (avec le `seq` et la raison incriminés), `2` fichier manquant/illisible.

### Bundle d'export signé (vérifiable par un tiers)

L'instance détient une clé de signature Ed25519, persistée dans `data/.audit_signing_key` (générée au premier lancement, `0600` ; surchargez avec `AUDIT_SIGNING_KEY_FILE` pour la conserver hors de la machine). Son identité publique est exposée via `GET /api/audit/public-key` (admin) : `{algorithm, public_key_pem, fingerprint}`. Le sommet de la chaîne est signé dans des points de contrôle périodiques (`certificate_audit.checkpoints.jsonl`).

`GET /api/audit/export` (admin, optionnel `?from_seq`/`?to_seq`) renvoie un bundle signé et auto-vérifiable — `{manifest, entries, bundle_signature}`. Le manifeste épingle l'empreinte de l'instance, la clé publique, la plage de `seq` et le `head_hash` ; la signature porte sur le manifeste canonique, qui (via `head_hash`) s'engage transativement sur chaque entrée. Un auditeur le vérifie **hors de la machine** sans exécuter ni faire confiance à CertMate, en épinglant éventuellement la clé de manière externe :

```bash
python -m modules.core.audit_verify --bundle bundle.json --pubkey instance.pem
# OK: audit bundle intact and signed (128 entries, seq 0..127; signed by 0m2V5lDmnkPWOUHX)
```

Le vérificateur contrôle la structure de la chaîne, que le manifeste correspond aux entrées, la signature Ed25519, et que l'empreinte correspond à la clé publique (optionnellement épinglée).

> **Honnêteté du modèle de menace.** La chaîne + la signature détectent toute modification intérieure, suppression ou réordonnancement, et lient une exportation à la clé publique de cette instance — pour quiconque ne détient pas la clé de signature. Elles ne **lient pas** l'opérateur, qui détient la clé et pourrait resigner une chaîne réécrite, et la troncature de la queue n'est détectée qu'en comparant les exportations dans le temps (une exportation ultérieure avec moins d'entrées) ou contre un point de contrôle externe. Contraindre complètement l'opérateur nécessite d'envoyer les points de contrôle signés vers un puits externe en append-only — un ancrage externe optionnel, une fonctionnalité prévue mais pas encore livrée. Voir [compliance.md](./compliance.md).

---

## Types de certificats

### API mTLS

Pour l'authentification des clients API via TLS mutuel.

```
cert_usage: "api-mtls"
```

### VPN

Pour l'authentification des clients VPN.

```
cert_usage: "vpn"
```

### Types d'usage personnalisés

Vous pouvez utiliser n'importe quelle chaîne de type d'usage personnalisé :

```
cert_usage: "custom-application"
```

---

## Bonnes pratiques

### Sécurité

1. **Protégez votre token**
   - Gardez les tokens secrets
   - Rotation régulière des tokens
   - Utilisez HTTPS en production

2. **Gestion des certificats**
   - Activez le renouvellement automatique
   - Surveillez les dates d'expiration
   - Examinez régulièrement les journaux d'audit
   - Révoquez immédiatement les certificats compromis

3. **Limitation de débit**
   - Respectez les limites de débit
   - Implémentez un backoff exponentiel
   - Utilisez les opérations par lots quand c'est possible

### Performance

1. **Utilisez les opérations par lots**
   - Importez plusieurs certificats à la fois
   - Réduit les appels API
   - Meilleure gestion des erreurs

2. **Filtrez les résultats**
   - Utilisez les paramètres de requête
   - Filtrez par usage ou statut
   - Réduit le transfert de données

3. **Mettez en cache quand c'est approprié**
   - Mettez en cache les métadonnées des certificats
   - Rafraîchissez périodiquement
   - Vérifiez l'expiration localement

---

---

<div align="center">

[← Retour à la documentation](./README.md) • [Démarrage rapide →](./guide.md) • [Architecture →](./architecture.md)

</div>
