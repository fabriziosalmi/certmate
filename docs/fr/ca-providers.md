# Fournisseurs d'autorité de certification (CA)

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
- **Email** : Requis pour les notifications de certificat

### Let's Encrypt (Staging)

- **Type** : Certificats de test depuis l'environnement de staging Let's Encrypt
- **Types de certificats** : Domain Validation (DV) — PAS reconnus par les navigateurs
- **Support Wildcard** : Oui
- **EAB Requis** : Non
- **Meilleur pour** : Valider la configuration DNS, le déploiement et le renouvellement sans consommer les limites de débit de production

Le staging est une entrée d'autorité de certification distincte (depuis v2.12.0), pas un indicateur par certificat : sélectionnez-la comme CA lors de la création d'un certificat, ou définissez-la comme CA par défaut pendant les tests. L'email utilise le compte Let's Encrypt comme repli quand il est laissé vide. La conversion d'un certificat de staging en production nécessite une réémission avec la CA de production.

### DigiCert ACME

- **Type** : Certificats SSL de qualité entreprise
- **Types de certificats** : DV, OV, EV
- **Support Wildcard** : Oui
- **EAB Requis** : Oui
- **Meilleur pour** : Environnements d'entreprise, applications commerciales

**Configuration requise :**
- **URL du répertoire ACME** : `https://acme.digicert.com/v2/acme/directory`
- **EAB Key ID** : Fourni par DigiCert
- **EAB HMAC Key** : Fournie par DigiCert
- **Email** : Requis pour les notifications de certificat

### Actalis

- **Type** : Certificats DV gratuits de 90 jours d'une CA européenne (Italie)
- **Types de certificats** : Domain Validation (DV)
- **Support Wildcard** : Non (non proposé via ACME)
- **EAB Requis** : Oui
- **Meilleur pour** : Utilisateurs UE qui souhaitent une alternative européenne à Let's Encrypt, environnements eIDAS

**Configuration requise :**
- **URL du répertoire ACME** : `https://acme-api.actalis.com/acme/directory` (fixe, préconfiguré)
- **EAB Key ID** : Depuis votre espace client Actalis
- **EAB HMAC Key** : Depuis votre espace client Actalis
- **Email** : Requis pour les notifications de certificat

**Limites du plan gratuit :**
- Certificats mono-domaine uniquement — une requête avec des entrées SAN est rejetée avec `Your account only grants single-domain 90-days DV certificates`
- Validité de 90 jours
- Pas de certificats wildcard (les plans SAN payants couvrent jusqu'à 5 noms d'hôte)

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
3. Sélectionnez votre fournisseur CA par défaut
4. Configurez les champs requis
5. Cliquez sur **Tester la connexion CA** pour vérifier
6. Sauvegardez les paramètres

### CA par défaut vs par certificat

Définissez une CA par défaut pour tous les nouveaux certificats. Remplacez-la par certificat lors de la création :

1. Allez dans la page **Certificats**
2. Sélectionnez la CA souhaitée dans le menu déroulant **Autorité de certification**
3. Procédez à la création du certificat

### Via l'API

```bash
# Créer un certificat avec une CA spécifique
curl -X POST http://localhost:8000/api/certificates/create \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "ca_provider": "digicert"
  }'

# Tester la connexion CA
curl -X POST http://localhost:8000/api/settings/test-ca-provider \
  -H "Authorization: Bearer VOTRE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ca_provider": "digicert",
    "config": {
      "acme_url": "https://acme.digicert.com/v2/acme/directory",
      "eab_kid": "votre_key_id",
      "eab_hmac": "votre_hmac_key",
      "email": "admin@example.com"
    }
  }'
```

---

## External Account Binding (EAB)

Certains fournisseurs CA (comme DigiCert et Actalis) nécessitent External Account Binding pour lier votre client ACME à votre compte CA.

### Qu'est-ce que l'EAB ?

- **Key ID** : Un identifiant unique pour votre compte
- **HMAC Key** : Une clé secrète utilisée pour signer les requêtes

### Obtenir des identifiants EAB

**DigiCert :**
1. Connectez-vous à votre compte DigiCert
2. Allez dans les paramètres ACME
3. Générez ou récupérez votre EAB Key ID et HMAC Key

**Actalis :**
1. Enregistrez un compte gratuit sur [actalis.com](https://www.actalis.com/)
2. Dans l'espace client, ouvrez **Manage with ACME**
3. Récupérez le KID et la clé HMAC sous **ACME Credentials**

**CA privée :**
- **step-ca** : L'EAB peut être activé/désactivé par provisioneur
- **Boulder** : Nécessite généralement EAB pour la production
- Consultez la documentation de votre CA privée pour les exigences spécifiques

---

## Confiance du certificat SSL

### CA publiques (Let's Encrypt, DigiCert)

Les certificats sont automatiquement reconnus par les navigateurs et systèmes d'exploitation.

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
2. **Les certificats existants** continuent d'utiliser leur CA d'origine jusqu'au renouvellement
3. **Migration forcée** : Renouvelez manuellement pour basculer vers la nouvelle CA

**Bonnes pratiques :**
- Testez la nouvelle configuration CA avant de la rendre par défaut
- Planifiez la migration pendant des fenêtres de maintenance
- Conservez des sauvegardes des certificats existants
- Surveillez la validité après la migration

---

## Considérations de sécurité

- Les clés HMAC EAB ne sont pas affichées après la sauvegarde
- Les clés privées sont générées localement et jamais transmises
- Utilisez HTTPS pour toutes les communications CA
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

### CA privée
- [Documentation step-ca](https://smallstep.com/docs/step-ca/)
- [Projet Boulder](https://github.com/letsencrypt/boulder)
- [Serveur de test Pebble](https://github.com/letsencrypt/pebble)

---

<div align="center">

[← Retour à la documentation](./README.md) • [Fournisseurs DNS →](./dns-providers.md) • [Docker →](./docker.md)

</div>
