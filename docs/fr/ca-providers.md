# Fournisseurs d'autorité de certification (CA)

<!-- CERTMATE-TRANSLATED-FROM b5fbaa66b65585c0 -->

CertMate supporte plusieurs fournisseurs d'autorité de certification, vous permettant de choisir la CA la plus adaptée à vos besoins.

---

## Fournisseurs CA supportés

### Let's Encrypt (par défaut)

- **Type** : Certificats SSL gratuits et automatisés
- **Types de certificats** : Domain Validation (DV)
- **Support Wildcard** : Oui
- **EAB Requis** : Non
- **Meilleur pour** : Développement, petites entreprises, projets personnels

**Configuration :**
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

**Profils :** `classic` (90 jours, le défaut), `tlsserver` (45 jours) et
`shortlived` (160 heures), en production comme en staging. Un certificat en demande un
avec `acme_profile`, et un compte CA peut désigner un profil par défaut pour les certificats
créés avec lui ; voir [Profils ACME](../api.md#acme-profiles). Dans le tableau de bord : **ACME
Profile** dans les options avancées du formulaire de création (Edit & Reissue s'ouvre sur le
profil propre au certificat), et **Default ACME profile** dans le formulaire du compte CA. Le
panneau du certificat affiche son profil et la date de son renouvellement.

### Let's Encrypt (Staging)

- **Type** : Certificats de test depuis l'environnement de staging Let's Encrypt
- **Types de certificats** : Domain Validation (DV) — PAS reconnus par les navigateurs
- **Support Wildcard** : Oui
- **EAB Requis** : Non
- **Meilleur pour** : Valider la configuration DNS, le déploiement et le renouvellement sans consommer les limites de débit de production

Le staging est une entrée d'autorité de certification distincte (depuis v2.12.0), pas un indicateur
par certificat : sélectionnez-la comme CA lors de la création d'un certificat, ou définissez-la comme CA par défaut
pendant les tests. L'email utilise celui du compte Let's Encrypt comme repli quand il est laissé vide.
La conversion d'un certificat de staging en production nécessite une réémission avec la CA de production.

### ZeroSSL

- **Type** : Certificats DV gratuits de 90 jours
- **Types de certificats** : Domain Validation (DV)
- **Support Wildcard** : Oui
- **EAB Requis** : Oui

**Configuration requise :**
- **URL du répertoire ACME** : `https://acme.zerossl.com/v2/DV90` (fixe, préconfigurée)
- **EAB Key ID** : Depuis le ZeroSSL Developer Dashboard
- **EAB HMAC Key** : Depuis le ZeroSSL Developer Dashboard
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

### Google Trust Services

- **Type** : Certificats DV gratuits
- **Types de certificats** : Domain Validation (DV)
- **Support Wildcard** : Oui
- **EAB Requis** : Oui

**Configuration requise :**
- **URL du répertoire ACME** : `https://dv.acme-v02.api.pki.goog/directory` (fixe, préconfigurée)
- **EAB Key ID** : Depuis votre projet Google Cloud
- **EAB HMAC Key** : Depuis votre projet Google Cloud
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

### DigiCert ACME

- **Type** : Certificats SSL de qualité entreprise
- **Types de certificats** : DV, OV, EV
- **Support Wildcard** : Oui
- **EAB Requis** : Oui
- **Meilleur pour** : Environnements d'entreprise, applications commerciales

**Configuration requise :**
- **URL du répertoire ACME** : `https://one.digicert.com/mpki/api/v1/acme/v2/directory`
  — la valeur par défaut, et **régionale**. Un compte situé hors de la région par défaut a
  sa propre URL de répertoire, affichée dans CertCentral ; saisissez-la ici et l'émission
  l'utilise. Laissez la valeur par défaut et c'est elle qui est utilisée. Elle doit être en `https`.
- **EAB Key ID** : Fourni par DigiCert
- **EAB HMAC Key** : Fournie par DigiCert
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

### Actalis

- **Type** : Certificats DV gratuits de 90 jours d'une CA européenne (Italie)
- **Types de certificats** : Domain Validation (DV)
- **Support Wildcard** : Non (non proposé via ACME)
- **EAB Requis** : Oui
- **Meilleur pour** : Utilisateurs UE qui souhaitent une alternative européenne à Let's Encrypt, environnements de l'écosystème eIDAS

**Configuration requise :**
- **URL du répertoire ACME** : `https://acme-api.actalis.com/acme/directory` (fixe, préconfigurée)
- **EAB Key ID** : Depuis votre espace client Actalis
- **EAB HMAC Key** : Depuis votre espace client Actalis
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

**Limites du plan gratuit :**
- Certificats mono-domaine uniquement — une requête avec des entrées SAN est rejetée avec
  `Your account only grants single-domain 90-days DV certificates`
- Validité de 90 jours
- Pas de certificats wildcard (les plans SAN payants couvrent jusqu'à 5 noms d'hôte)

### SSL.com

- **Type** : Certificats commerciaux
- **Types de certificats** : DV, OV, EV
- **Support Wildcard** : Oui
- **EAB Requis** : Oui

**Configuration requise :**
- **URL du répertoire ACME** : `https://acme.ssl.com/sslcom-dv-rsa` (fixe, préconfigurée)
- **EAB Key ID** : Fourni par SSL.com
- **EAB HMAC Key** : Fournie par SSL.com
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

### Sectigo

- **Type** : CA ACME publique/commerciale via Sectigo Certificate Manager (SCM)
- **Types de certificats** : DV, OV (selon le compte/profil SCM sélectionné)
- **Support Wildcard** : Oui, lorsque le compte/profil SCM le permet
- **EAB Requis** : Oui
- **URL du répertoire ACME** : Copiez l'URL HTTPS depuis les détails du compte ACME dans SCM ; elle est propre à chaque compte
- **EAB Key ID / KID et HMAC Key** : À copier depuis les détails du compte ACME dans SCM
- **Email** : Contact du compte ACME (voir [Email du compte](#email-du-compte))

Exemple de configuration de test (l'URL n'est **qu'un exemple**, pas un endpoint universel) :

```json
{
  "ca_provider": "sectigo",
  "config": {
    "acme_url": "https://acme.sectigo.com/v2/OV",
    "eab_kid": "your-sectigo-key-id",
    "eab_hmac": "your-sectigo-hmac-key",
    "email": "admin@example.com"
  }
}
```

Pour plusieurs comptes, configurez `ca_providers.sectigo.accounts` dans les paramètres,
chaque compte ayant ses propres `acme_url`, `eab_kid`, `eab_hmac` et `email`.
Sélectionnez un compte avec `ca_account_id` dans l'API de création de certificat ; s'il est
omis, CertMate utilise `default_ca_accounts.sectigo` ou le premier compte configuré.
Le renouvellement réutilise le compte CA enregistré. DNS-01 (y compris Custom Script) et
HTTP-01 restent disponibles ; SCM a peut-être déjà autorisé le domaine demandé.
Pour un compte SCM qui autorise déjà **chacun** des noms demandés, sélectionnez
**Sectigo → Sectigo (already authorized in SCM)** comme type de challenge
du certificat. CertMate ne configure aucune validation DNS ou HTTP dans ce mode, et un
wildcard peut être demandé si ce compte/profil SCM l'autorise. Certbot
utilise son authenticator manuel avec un hook qui ne publie rien, uniquement pour satisfaire son
exigence de fonctionnement non interactif : lorsque la CA retourne des autorisations ACME valides,
le hook n'est jamais appelé. Si SCM retourne une autorisation en attente, le hook
ne publie aucun matériel de validation, donc CertMate ne peut pas la satisfaire dans ce mode.
Utilisez DNS-01 ou HTTP-01 lorsque les noms ne sont pas déjà autorisés. Au
renouvellement, SCM doit toujours autoriser les noms pour ce compte.
Ce mode n'est disponible que lorsque Sectigo est sélectionné explicitement comme CA.
Les configurations Sectigo existantes sous CA privée continuent de fonctionner sans changement.

### CA privée

- **Type** : Autorité de certification interne/entreprise
- **Types de certificats** : Privés/Internes
- **Support Wildcard** : Oui (dépend de l'implémentation CA)
- **EAB Requis** : Optionnel
- **Meilleur pour** : Réseaux internes, environnements d'entreprise, systèmes isolés

**Logiciels compatibles :**
- [step-ca](https://smallstep.com/docs/step-ca/)
- [Boulder](https://github.com/letsencrypt/boulder)
- [Pebble](https://github.com/letsencrypt/pebble)
- Autres CA privées compatibles ACME

**Utilisation d'une CA publique ACME via l'entrée CA privée :**

L'entrée CA privée est aussi la porte de sortie générique pour toute CA ACME sans entrée dédiée dans CertMate : pointez-la vers l'URL du répertoire de la CA et, si la CA impose une liaison de compte, remplissez l'EAB Key ID et HMAC Key optionnels. Par exemple, Actalis fonctionne à la fois via son entrée dédiée (recommandé) et comme CA privée avec :

- **URL du répertoire ACME** : `https://acme-api.actalis.com/acme/directory`
- **EAB Key ID / HMAC Key** : depuis l'espace client Actalis
- **Certificat CA** : laisser vide (racines de confiance publique)

---

## Configuration

### Via l'interface Web

1. Allez dans **Paramètres**
2. Descendez jusqu'à **Fournisseurs d'autorité de certification (CA)**
3. Cliquez sur **Add CA Account**, choisissez la CA et nommez le compte (lettres,
   chiffres, points, tirets et tirets bas)
4. Configurez les champs requis
5. Cliquez sur **Test CA Connection** pour vérifier les champs
6. Cliquez sur **Save Account**

**Test CA Connection** ne contacte la CA que pour une CA privée : il récupère
l'URL du répertoire ACME (en utilisant le certificat CA, s'il est fourni). Pour toutes les autres
CA, il vérifie que les champs requis sont remplis (et, pour DigiCert, que
les identifiants EAB ne sont pas d'une brièveté invraisemblable) sans contacter la CA ; un
test réussi ne prouve donc pas que les identifiants fonctionnent. C'est la première émission qui le prouve.

### Email du compte

Certbot utilise l'email du compte CA sélectionné pour les nouvelles émissions, avec repli
sur le paramètre global `email` lorsque ce compte n'en a pas. L'email global
reste requis pour l'émission. Modifier l'email d'un compte ne met pas à jour un
compte ACME déjà enregistré par Certbot ; utilisez `certbot update_account` pour
ce changement de contact.

### CA par défaut vs par certificat

Paramètres → Fournisseurs CA liste les comptes CA (par exemple, deux emails Let's Encrypt
ou deux comptes Sectigo SCM). **Add CA Account** ouvre le formulaire du compte ;
**Edit** le rouvre. Sélectionnez **Default for this CA** sur un compte par fournisseur ;
**Make global default** choisit aussi le fournisseur utilisé pour les nouveaux certificats.
Les configurations existantes à compte unique sont conservées comme compte `default`
lorsqu'un autre compte est ajouté. Supprimer un compte laisse intacts les autres comptes de
cette CA ; changez le compte par défaut ou réémettez les certificats qui utilisent ce compte avant
de le supprimer.

Définissez une CA par défaut pour tous les nouveaux certificats. Remplacez-la par certificat lors de la création :

1. Allez dans la page **Certificats**
2. Sélectionnez la CA souhaitée dans le menu déroulant **Autorité de certification**
3. Procédez à la création du certificat

Si la CA choisie n'a aucune configuration enregistrée (ou si le compte CA demandé
n'existe pas), la requête est **refusée**. Émettre depuis une autre CA ne remplace pas
celle que vous avez demandée : il était possible de demander DigiCert et
de recevoir un certificat Let's Encrypt avec un `201`, et de demander à une CA privée un
nom interne et de voir ce nom publié dans un certificat public. Le
refus nomme la CA manquante.

Let's Encrypt est l'exception, et uniquement parce que les valeurs par défaut de certbot constituent sa
configuration : une requête pour elle réussit sans rien d'enregistré, et une requête
de staging reste en staging.

La colonne **CA** de la page Certificats indique l'autorité avec laquelle chaque certificat
a été émis ; la même valeur figure dans `ca_provider` dans la réponse de l'API et dans les
métadonnées du certificat. Les certificats émis avant que CertMate n'enregistre la CA
affichent `—` à cet endroit plutôt qu'une supposition.

### Via l'API

```bash
# Créer un certificat avec une CA spécifique
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'

# Tester la connexion CA
curl -X POST http://localhost:8000/api/settings/test-ca-provider \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://one.digicert.com/mpki/api/v1/acme/v2/directory",
      "eab_kid": "your_key_id",
      "eab_hmac": "your_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis et Sectigo nécessitent External Account Binding pour lier votre client ACME à votre compte CA.

### Qu'est-ce que l'EAB ?

- **Key ID** : Un identifiant unique pour votre compte
- **HMAC Key** : Une clé secrète utilisée pour signer les requêtes

### Obtenir des identifiants EAB

**DigiCert :**
1. Connectez-vous à votre compte DigiCert
2. Allez dans les paramètres ACME
3. Générez ou récupérez votre EAB Key ID et HMAC Key

**ZeroSSL :**
- Générez les identifiants EAB dans le ZeroSSL Developer Dashboard

**Actalis :**
1. Enregistrez un compte gratuit sur [actalis.com](https://www.actalis.com/)
2. Dans l'espace client, ouvrez **Manage with ACME**
3. Récupérez le KID et la clé HMAC sous **ACME Credentials**

**CA privée :**
- **step-ca** : L'EAB peut être activé/désactivé par provisioner
- Consultez la documentation de votre CA privée pour les exigences spécifiques

---

## Confiance du certificat SSL

### CA publiques (Let's Encrypt, ZeroSSL, Google Trust Services, DigiCert, SSL.com, Actalis, Sectigo)

Les certificats sont automatiquement reconnus par les navigateurs et les systèmes d'exploitation (sauf ceux du staging Let's Encrypt).

### CA privées

Pour que les certificats de CA privée soient reconnus :
1. Installez le certificat racine CA sur les systèmes clients
2. Configurez les applications pour une confiance personnalisée
3. Importez le certificat racine dans les magasins de confiance des navigateurs

Vous pouvez optionnellement fournir le certificat racine CA dans CertMate pour la vérification de la chaîne de confiance lors de la création du certificat.

---

## Dépannage

### Let's Encrypt
- **Certificat non fiable après émission** : Vérifiez si le certificat a été émis par la CA de staging — sélectionnez l'entrée de production "Let's Encrypt" et réémettez
- **Limite de débit atteinte** : Passez à l'entrée CA "Let's Encrypt (Staging)" pendant les tests
- **Email valide** : Assurez-vous que le format de l'email est correct

### DigiCert
- **Identifiants EAB invalides** : Vérifiez la Key ID et la HMAC Key
- **Compte non autorisé** : Assurez-vous qu'ACME est activé sur votre compte DigiCert
- **Mauvaise URL ACME** : Vérifiez l'URL du répertoire auprès du support DigiCert

### Actalis
- **`Your account only grants single-domain 90-days DV certificates`** : Le plan gratuit rejette les requêtes SAN/multi-domaines — émettez un certificat par nom d'hôte ou passez à un plan supérieur
- **Identifiants EAB invalides** : Récupérez des identifiants frais depuis l'espace client sous Manage with ACME
- **Wildcard rejeté** : Les certificats wildcard ne sont pas disponibles via ACME chez Actalis

### Sectigo
- **Identifiants EAB invalides** : Vérifiez le KID et le HMAC par rapport aux détails du compte ACME SCM sélectionné
- **Identifiant/domaine non autorisé** : Vérifiez que le domaine est autorisé pour le compte ACME SCM et l'organisation sélectionnés
- **Mauvais endpoint ACME** : Vérifiez que l'URL de répertoire configurée correspond exactement à l'URL fournie dans SCM pour ce compte

### CA privée
- **URL ACME injoignable** : Vérifiez la connectivité réseau
- **Certificat CA invalide** : Vérifiez le format PEM et la validité
- **EAB mismatch** : Vérifiez si EAB est requis par votre CA

### Général
- Assurez-vous que le fournisseur DNS est correctement configuré
- Vérifiez la propriété du domaine et la propagation DNS
- Vérifiez les règles de pare-feu pour le port ACME (généralement 443)

---

## Migration entre CA

1. **Les nouveaux certificats** utilisent la nouvelle CA par défaut
2. **Les certificats existants** restent sur la CA qui les a émis : le renouvellement exécute
   `certbot renew` auprès de la CA d'origine, y compris pour un renouvellement manuel ou forcé
3. **Déplacer un certificat vers une autre CA** : réémettez-le avec la nouvelle CA
   (`POST /api/certificates/<domain>/reissue` avec `ca_provider` ; voir la
   [référence API](./api.md))

**Bonnes pratiques :**
- Testez la nouvelle configuration CA avant de la rendre par défaut
- Planifiez la migration pendant des fenêtres de maintenance
- Conservez des sauvegardes des certificats existants
- Surveillez la validité après la migration

---

## Considérations de sécurité

- Les clés HMAC EAB ne sont pas affichées après la sauvegarde
- Les clés privées sont générées localement et ne sont jamais envoyées à la CA (un backend de stockage distant ou une cible de déploiement que vous configurez les reçoit, en revanche)
- Utilisez une URL de répertoire ACME en `https://` pour une CA privée
- Envisagez un VPN pour l'accès à la CA privée

---

## Ressources

### Let's Encrypt
- [Documentation](https://letsencrypt.org/docs/)
- [Limites de débit](https://letsencrypt.org/docs/rate-limits/)
- [Environnement de staging](https://letsencrypt.org/docs/staging-environment/)

### DigiCert
- [Documentation ACME](https://docs.digicert.com/certificate-tools/acme-user-guide/)
- [Configuration du compte](https://docs.digicert.com/certificate-tools/acme-user-guide/acme-account-setup/)

### Actalis
- [Comment activer ACME](https://guide.actalis.com/ssl/activation/acme)
- [FAQ ACME](https://guide.actalis.com/faq/SSL/ACME)

### Sectigo
- [Comprendre les endpoints ACME de SCM](https://docs.sectigo.com/scm/scm-administrator/understanding-acme-endpoints.html)
- [Ajouter des comptes ACME dans SCM](https://docs.sectigo.com/scm/scm-administrator/adding-acme-accounts.html)

### CA privée
- [Documentation step-ca](https://smallstep.com/docs/step-ca/)
- [Projet Boulder](https://github.com/letsencrypt/boulder)
- [Serveur de test Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Retour à la documentation](./README.md) • [Fournisseurs DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
