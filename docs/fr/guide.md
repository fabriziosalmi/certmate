# CertMate Certificats Clients - Guide d'utilisation

## Pour commencer

### Installation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer CertMate
python app.py

# 3. Ouvrir le tableau de bord
# Accédez à : http://localhost:5000/client-certificates
```

### Premiers pas

1. **Générer la CA** — Créée automatiquement au premier démarrage
2. **Accéder au tableau de bord** — Allez dans `/client-certificates`
3. **Créer un certificat** — Utilisez le formulaire Web ou l'API
4. **Télécharger les fichiers** — Obtenez le cert, la clé et le CSR

---

## Tableau de bord Web

### Fonctionnalités du tableau de bord

**URL** : `http://localhost:5000/client-certificates`

#### Panneau de statistiques
- Total des certificats
- Nombre actifs
- Nombre révoqués
- Répartition par type d'utilisation

#### Tableau des certificats
- Liste tous les certificats
- Recherche par nom commun
- Filtre par type d'utilisation
- Filtre par statut
- Tri par date de création

#### Formulaire de création de certificat

**Champs du formulaire** :
- Nom commun (obligatoire)
- Adresse email
- Organisation
- Unité organisationnelle
- Type d'utilisation (VPN, API-mTLS, etc.)
- Jours de validité (défaut : 365)
- Générer la clé (case à cocher)
- Notes

**Exemple** :
```
Nom commun : user@example.com
Email : user@example.com
Organisation : ACME Corp
Type d'utilisation : api-mtls
Jours de validité : 365
```

#### Import CSV par lots

1. Cliquez sur l'onglet "Import en vrac"
2. Préparez un fichier CSV avec les en-têtes :
 ```
 common_name,email,organization,cert_usage,days_valid
 user1@example.com,user1@example.com,ACME Corp,api-mtls,365
 user2@example.com,user2@example.com,ACME Corp,vpn,365
 ```
3. Glissez-déposez ou cliquez pour importer
4. Visionnez l'aperçu
5. Cliquez sur "Importer"

---

## Tâches courantes

### Créer un certificat unique

#### Via le tableau de bord Web

1. Allez dans `/client-certificates`
2. Remplissez le formulaire "Créer un certificat"
3. Cliquez sur "Créer"
4. Le certificat apparaît dans le tableau

#### Via l'API

```bash
curl -X POST http://localhost:5000/api/client-certs/create \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "common_name": "user@example.com",
   "email": "user@example.com",
   "organization": "ACME Corp",
   "cert_usage": "api-mtls",
   "days_valid": 365,
   "generate_key": true
 }'
```

---

### Télécharger les fichiers d'un certificat

#### Via le tableau de bord Web

1. Trouvez le certificat dans le tableau
2. Cliquez sur l'icône de téléchargement
3. Sélectionnez le type de fichier :
   - **CRT** — Certificat (public)
   - **KEY** — Clé privée (à garder secrète)
   - **CSR** — Demande de signature de certificat

#### Via l'API

```bash
# Télécharger le certificat
curl http://localhost:5000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o mon-cert.crt

# Télécharger la clé
curl http://localhost:5000/api/client-certs/CERT_ID/download/key \
 -H "Authorization: Bearer TOKEN" \
 -o ma-cle.key
```

---

### Révoquer un certificat

#### Via le tableau de bord Web

1. Trouvez le certificat dans le tableau
2. Cliquez sur le bouton "Révoquer"
3. Saisissez la raison de la révocation (optionnelle)
4. Confirmez

#### Via l'API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/revoke \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "reason": "compromised"
 }'
```

**Raisons de révocation** :
- `compromised` — La clé a été compromise
- `superseded` — Remplacé par un nouveau certificat
- `unspecified` — Révocation générale
- Toute raison personnalisée

---

### Renouveler un certificat

#### Via le tableau de bord Web

1. Trouvez le certificat dans le tableau
2. Cliquez sur le bouton "Renouveler"
3. Confirmez le renouvellement

#### Via l'API

```bash
curl -X POST http://localhost:5000/api/client-certs/CERT_ID/renew \
 -H "Authorization: Bearer TOKEN"
```

**Note** : Le renouvellement crée un nouveau certificat avec :
- Le même nom commun
- Un nouveau numéro de série
- Une nouvelle date d'expiration
- L'ID d'origine mis à jour

---

### Lister et filtrer les certificats

#### Via le tableau de bord Web

1. Allez dans le tableau des certificats
2. Utilisez la zone de recherche pour le nom commun
3. Utilisez le menu déroulant "Type d'usage" pour filtrer
4. Utilisez le menu déroulant "Statut" (Actif/Révoqué)
5. Cliquez sur "Appliquer les filtres"

#### Via l'API

```bash
# Lister tout
curl http://localhost:5000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrer par usage
curl "http://localhost:5000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtrer par statut
curl "http://localhost:5000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Rechercher
curl "http://localhost:5000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Vérifier le statut d'un certificat (OCSP)

#### Via l'API

```bash
curl http://localhost:5000/api/ocsp/status/NUMERO_SERIE \
 -H "Authorization: Bearer TOKEN"
```

**Réponse** :
```json
{
  "certificate_status": "good",
  "certificate_serial": 12345678,
  "this_update": "2024-10-30T18:00:00Z"
}
```

---

### Obtenir la liste de révocation (CRL)

#### Télécharger la CRL

```bash
# Format PEM
curl http://localhost:5000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Format DER
curl http://localhost:5000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Obtenir les informations CRL

```bash
curl http://localhost:5000/api/crl/download/info \
 -H "Authorization: Bearer TOKEN"
```

---

## Opérations par lots

### Format CSV

```csv
common_name,email,organization,cert_usage,days_valid
user1@example.com,user1@example.com,ACME Corp,api-mtls,365
user2@example.com,user2@example.com,ACME Corp,vpn,365
user3@example.com,user3@example.com,ACME Corp,api-mtls,730
```

### Colonnes obligatoires

- `common_name` — Sujet du certificat (obligatoire)

### Colonnes optionnelles

- `email` — Adresse e-mail
- `organization` — Nom de l'organisation
- `organizational_unit` — Nom du service
- `cert_usage` — Type d'usage
- `days_valid` — Durée de validité en jours

### Via le tableau de bord Web

1. Allez dans l'onglet "Import en vrac"
2. Importez le fichier CSV
3. Visionnez l'aperçu
4. Cliquez sur "Tout importer"

### Via l'API

```bash
curl -X POST http://localhost:5000/api/client-certs/batch \
 -H "Authorization: Bearer TOKEN" \
 -H "Content-Type: application/json" \
 -d '{
   "headers": ["common_name", "email", "organization"],
   "rows": [["user1@example.com", "user1@example.com", "ACME Corp"],
            ["user2@example.com", "user2@example.com", "ACME Corp"],
            ["user3@example.com", "user3@example.com", "ACME Corp"]
           ]
 }'
```

### Résultats de l'import

Retourne les compteurs de succès/échec :
```json
{
  "total": 3,
  "successful": 3,
  "failed": 0,
  "errors": [],
  "certificates": [{"identifier": "cert-batch-001", "common_name": "user1@example.com"},
                   {"identifier": "cert-batch-002", "common_name": "user2@example.com"},
                   {"identifier": "cert-batch-003", "common_name": "user3@example.com"}
                  ]
}
```

---

## Types d'usage des certificats

### API mTLS

Pour l'authentification mutuelle TLS des clients API.

```
Type d'usage : api-mtls
Validité typique : 1 an (365 jours)
```

### VPN

Pour l'authentification des clients VPN.

```
Type d'usage : vpn
Validité typique : 1-2 ans (365-730 jours)
```

### Types personnalisés

Vous pouvez créer des certificats pour tout usage personnalisé :

```
Type d'usage : custom-application
Type d'usage : internal-service
Type d'usage : mobile-app
```

---

## Renouvellement automatique

### Configuration

- **Vérification** : Tous les jours à 3h du matin
- **Seuil** : 30 jours avant l'expiration
- **Action** : Renouvellement automatique si activé

### Activation du renouvellement automatique

Le renouvellement automatique est activé par défaut. Pour vérifier le statut :

```bash
curl http://localhost:5000/api/client-certs/CERT_ID \
 -H "Authorization: Bearer TOKEN"
```

Recherchez :
```json
{
  "renewal": {
    "renewal_enabled": true,
    "renewal_threshold_days": 30
  }
}
```

### Comportement du renouvellement

En cas de renouvellement automatique :
- Nouveau certificat créé
- Même CN (nom commun)
- Nouveau numéro de série
- Nouvelle date d'expiration
- L'ID d'origine reste le même
- L'ancien certificat est remplacé

---

## Dépannage

### Problèmes courants

#### Échec de création du certificat

**Erreur** : `Failed to create certificate`

**Solutions** :
1. Vérifiez que le nom commun est valide
2. Vérifiez que tous les champs obligatoires sont remplis
3. Vérifiez que la CA est initialisée
4. Consultez les logs pour plus de détails

#### Échec de téléchargement du fichier

**Erreur** : `File not found`

**Solutions** :
1. Vérifiez que l'ID du certificat existe
2. Vérifiez le type de fichier (crt, key, csr)
3. Assurez-vous que le certificat n'a pas été supprimé
4. Vérifiez l'espace disque

#### Limite de débit dépassée

**Erreur** : `HTTP 429 Too Many Requests`

**Solutions** :
1. Attendez avant de réessayer
2. Utilisez les opérations par lots
3. Implémentez un backoff exponentiel
4. Vérifiez la limite de votre endpoint

### Consultation des logs

Afficher les logs de l'application :
```bash
tail -f logs/certmate.log
```

Afficher les logs d'audit :
```bash
tail -f logs/audit/certificate_audit.log
```

---

## Bonnes pratiques de sécurité

### Clés privées

- **NE JAMAIS** partager vos clés privées
- **NE JAMAIS** commiter les clés dans git
- Stockez les clés de manière sécurisée
- Utilisez les permissions 0600

### Certificats

- Surveillez les dates d'expiration
- Renouvelez avant l'expiration
- Révoquez immédiatement les certificats compromis
- Conservez les logs d'audit pour la conformité

### Jetons API

- Effectuez une rotation régulière des jetons
- Utilisez HTTPS en production
- Ne codez pas en dur les jetons
- Utilisez les variables d'environnement

### Révocation

Révoquez toujours quand :
- La clé est compromise
- Le certificat est remplacé
- Un utilisateur quitte l'organisation
- Le service est désaffecté

---

## Conseils de performance

### Pour les gros lots

Utilisez les opérations par lots au lieu de créations individuelles :
```bash
# Bien : Une requête pour 1000 certificats
POST /api/client-certs/batch

# Mal : 1000 requêtes pour 1000 certificats
POST /api/client-certs/create × 1000
```

### Pour le filtrage

Filtrez côté serveur :
```bash
# Bien : Le serveur filtre
GET /api/client-certs?usage=api-mtls

# Mal : Le client filtre tout
GET /api/client-certs
```

### Pour la surveillance

Utilisez l'endpoint de statistiques :
```bash
GET /api/client-certs/stats
```

---

## Support

### Documentation

- [Référence API](./api.md) — Tous les endpoints
- [Architecture](./architecture.md) — Conception du système
- [Notes de version](../RELEASE_NOTES.md) — Historique des versions

### Tests

Voir `test_e2e_complete.py` pour des exemples d'utilisation.

---

<div align="center">

[← Retour à la documentation](./README.md) • [Référence API →](./api.md) • [Architecture →](./architecture.md)

</div>
