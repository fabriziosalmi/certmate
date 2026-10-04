# CertMate Certificats Clients - Guide d'utilisation

<!-- CERTMATE-TRANSLATED-FROM 88bb16eb976577c4 -->

## Vue d'ensemble

CertMate Certificats Clients est une solution complète et prête pour la production pour la gestion de certificats clients avec :

- **CA auto-signée** — Générez et gérez votre propre Autorité de Certification
- **Gestion complète du cycle de vie** — Créez, renouvelez, révoquez et surveillez les certificats clients
- **OCSP & CRL** — Statut des certificats en temps réel et listes de révocation
- **Tableau de bord Web** — Interface intuitive pour la gestion des certificats
- **API REST** — API complète pour l'automatisation
- **Opérations par lots** — Importez des certificats clients par CSV (100 lignes maximum par requête)
- **Journal d'audit** — Suivez toutes les opérations pour la conformité
- **Limitation de débit** — Protection intégrée contre les abus

---


## Pour commencer

### Installation

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Lancer CertMate
python app.py

# 3. Ouvrir le tableau de bord
# Accédez à : http://localhost:8000/client-certificates
```

### Premiers pas

1. **Générer la CA** — Créée automatiquement au premier démarrage
2. **Accéder au tableau de bord** — Allez dans `/client-certificates`
3. **Créer un certificat** — Utilisez le formulaire Web ou l'API
4. **Télécharger les fichiers** — Obtenez le cert, la clé et le CSR

---

## Tableau de bord Web

### Fonctionnalités du tableau de bord

**URL** : `http://localhost:8000/client-certificates`

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
curl -X POST http://localhost:8000/api/client-certs/create \
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
curl http://localhost:8000/api/client-certs/CERT_ID/download/crt \
 -H "Authorization: Bearer TOKEN" \
 -o mon-cert.crt

# Télécharger la clé
curl http://localhost:8000/api/client-certs/CERT_ID/download/key \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/revoke \
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
curl -X POST http://localhost:8000/api/client-certs/CERT_ID/renew \
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
curl http://localhost:8000/api/client-certs \
 -H "Authorization: Bearer TOKEN"

# Filtrer par usage
curl "http://localhost:8000/api/client-certs?usage=api-mtls" \
 -H "Authorization: Bearer TOKEN"

# Filtrer par statut
curl "http://localhost:8000/api/client-certs?revoked=false" \
 -H "Authorization: Bearer TOKEN"

# Rechercher
curl "http://localhost:8000/api/client-certs?search=user@" \
 -H "Authorization: Bearer TOKEN"
```

---

### Vérifier le statut d'un certificat (OCSP)

#### Via l'API

```bash
curl http://localhost:8000/api/ocsp/status/NUMERO_SERIE \
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
curl http://localhost:8000/api/crl/download/pem \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl

# Format DER
curl http://localhost:8000/api/crl/download/der \
 -H "Authorization: Bearer TOKEN" \
 -o ca.crl
```

#### Obtenir les informations CRL

```bash
curl http://localhost:8000/api/crl/download/info \
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
curl -X POST http://localhost:8000/api/client-certs/batch \
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

- **Vérification** : Tous les jours. Les certificats clients entre 02h00 et
  04h00 ; les certificats serveur, dont le reste de cette section décrit la
  règle, entre 01h00 et 03h00 (chaque passage à son heure, avec jusqu'à une
  heure de décalage aléatoire dans un sens ou dans l'autre)
- **Seuil** : 30 jours avant l'expiration (`renewal_threshold_days`), lorsque
  cela ne dépasse pas la moitié de la durée de vie du certificat ; voir plus bas
- **Action** : Renouvellement automatique si activé

### Quand un certificat est renouvele

Une seule regle decide, et la reponse du certificat la porte :
`needs_renewal` devient vrai a `renews_at`, l'instant ou le balayage le
renouvelle (`GET /api/certificates/<domain>`, depuis le contrat d'API 2.40).
CertMate prend la decision et demande a certbot de renouveler ; le verrou
propre de certbot n'intervient plus, donc une mise a jour de certbot ne peut
pas changer le moment ou CertMate renouvelle.

- **Le seuil**, lorsqu'il ne depasse pas la moitie de la duree de vie : 30
  jours d'un certificat de 90, comme toujours, ou 45 si vous reglez 45.
- **Sinon la duree de vie** : un tiers, ou la moitie pour un certificat qui
  vit moins de 10 jours. 30 jours ne veulent rien dire pour un certificat de
  45, qui est donc renouvele quand il lui en reste 15 ; un certificat de 160
  heures quand il lui reste environ 3 jours.
- **La fenetre de la CA**, quand elle en a publie une pour ce certificat (plus
  bas) : avant ou apres le seuil.

Pour un certificat de 90 jours avec les 30 jours par defaut, les
renouvellements ont lieu quand ils ont toujours eu lieu.

### Quand la CA n'est pas d'accord avec le seuil (ARI)

Le seuil est l'avis de CertMate, et c'est le meme avis pour chaque
certificat et chaque CA. Depuis la [RFC 9773](https://www.rfc-editor.org/rfc/rfc9773.html)
une CA peut publier le sien, par certificat : un endpoint `renewalInfo` qui
repond par une fenetre pendant laquelle elle souhaite voir ce certificat
remplace. Let's Encrypt en expose un, en production et en staging. step-ca pas
encore (0.30.2, mesure ; voir smallstep/certificates#2162) : sur une step-ca
privee seul le seuil decide, et le panneau du certificat indique que la CA ne
publie pas de fenetre.

Le balayage de renouvellement TLS pose la question, pour chaque certificat, et
la fenetre decide dans les deux sens. Elle **avance** un renouvellement : c'est
ainsi qu'une instance apprend un remplacement en masse — une emission erronee,
un intermediaire compromis, une decision du CA/Browser Forum — des jours avant
l'arrivee de la revocation, au lieu de le decouvrir quand le certificat cesse
de fonctionner. Et elle **reporte** un renouvellement que le seuil aurait
fait, jusqu'au point de la fenetre demande par la CA.

**Un report a un plancher.** Une fenetre ne retient jamais un certificat
lorsqu'il ne lui reste qu'un sixieme de sa duree de vie (15 jours sur 90, 7,5
sur 45, environ un sur 160 heures), ni au-dela de la fin de la fenetre
elle-meme : une CA qui se trompe, ou une fenetre perimee, ne peut donc pas
pousser un certificat vers l'expiration. Chaque absence — une CA qui ne publie
pas `renewalInfo`, un endpoint injoignable, une reponse malformee, un
certificat auto-signe sans Authority Key Identifier par lequel le nommer — ne
laisse aucune fenetre, et le seuil decide. La fenetre est conservee sur disque,
donc un report dure d'un balayage au suivant.

Dans la fenetre, CertMate choisit un point, derive de l'identifiant propre du
certificat, de sorte que le choix est le meme a chaque balayage et que deux
certificats ne tombent pas sur le meme instant. C'est a cela que sert la
fenetre : une CA ne veut pas que tous ses clients renouvellent en meme temps.

Le resume du balayage les compte comme `ari_advanced` et `ari_postponed`, afin
qu'un renouvellement que votre configuration n'explique pas, ou qu'elle ne
fait pas, reste attribuable.

Le panneau de detail du certificat montre ce que la CA a dit au dernier
balayage, sous **CA renewal window** : la fenetre, l'instant a l'interieur
duquel CertMate renouvelle, et le lien d'explication de la CA quand elle en a
donne un. Sans fenetre, il dit de quelle absence il s'agit : la CA n'en publie
pas, la CA n'a pas repondu au dernier controle, ou le certificat ne peut pas
etre nomme dans ARI. Le meme enregistrement est renvoye comme `renewal_info`
par `GET /api/certificates/<domain>`. Il est lu dans ce que le balayage a
conserve, donc ouvrir le tableau de bord n'envoie jamais de requete a la CA.
Juste apres un renouvellement il affiche "Not checked yet" jusqu'a ce que le
balayage suivant interroge sur le nouveau certificat.

Mettez `"ari_enabled": false` dans `settings.json` pour le desactiver ; il est
actif par defaut et coute un GET non authentifie par certificat et par
balayage, plus un par CA et par heure pour le repertoire.

### Un seuil au-dela de 30 jours

Avant la version 2.40.0, CertMate demandait a certbot de renouveler sans le
forcer, et le verrou propre de certbot ne renouvelait que dans les 30 derniers
jours avant l'expiration : un `renewal_threshold_days` de 45 se comportait
donc comme 30. La version 2.40.0 a force les renouvellements qu'un seuil
au-dela de 30 jours declarait dus, et depuis le contrat d'API 2.40 tout
renouvellement decide par CertMate est force : un seuil de 45 renouvelle un
certificat de 90 jours 45 jours avant son expiration. Un renouvellement que le
seuil avance par rapport a la regle de la duree de vie s'accompagne de deux
protections :

- **Au plus `early_renewals_per_sweep` par balayage** (10 par defaut, entre 1
  et 50). Relever le seuil sur un grand parc etale les renouvellements anticipes
  sur plusieurs nuits au lieu d'envoyer toutes les commandes a la CA en une
  seule. Le resume les compte comme `early_forced`, et ceux laisses au balayage
  suivant comme `early_deferred`.
- **Un certificat plus jeune qu'une semaine, ou qu'un tiers de sa duree de
  vie, n'est jamais renouvele en avance.** Un seuil au-dela de la moitie de la
  duree de vie ne compte plus (la duree de vie decide) : cette protection est
  la derniere defense contre un certificat dont les dates ne concordent pas.

Un certificat qui demande de l'attention pour une autre raison, une cle servie
absente ou qui ne correspond pas, n'est pas force : il est repare depuis sa
lignee, sans nouvelle cle.

### Activation du renouvellement automatique

Le renouvellement automatique est activé par défaut. Pour vérifier le statut :

```bash
curl http://localhost:8000/api/client-certs/CERT_ID \
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

Le corps indique quelle limite a été atteinte. `"code": "ISSUANCE_QUEUE_FULL"`
signifie que trop de tâches de certificat sont en file ou en cours : réessayez
quand certaines se terminent, ou augmentez `CERTMATE_ISSUANCE_QUEUE_LIMIT` /
`CERTMATE_ISSUANCE_WORKERS`. La limite de l'API et celle des tentatives de
connexion renvoient toutes deux `retry_after` en secondes.

### Consultation des logs

Afficher les logs de l'application (CertMate journalise sur stdout) :
```bash
docker logs -f certmate
```

Un fichier de log n'existe que si vous définissez `CERTMATE_LOG_FILE` (par ex.
`CERTMATE_LOG_FILE=/app/logs/certmate.log`) ; faites alors `tail -f` sur ce chemin.

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
- [Notes de version](../../RELEASE_NOTES.md) — Historique des versions

### Tests

Voir `test_e2e_complete.py` pour des exemples d'utilisation.

---

<div align="center">

[← Retour à la documentation](./README.md) • [Référence API →](./api.md) • [Architecture →](./architecture.md)

</div>
