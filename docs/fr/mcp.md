# Serveur MCP (Model Context Protocol) CertMate

<!-- CERTMATE-TRANSLATED-FROM 8ff9ffe2c5fe3b5b -->

CertMate inclut un serveur MCP (Model Context Protocol) intégré écrit en Node.js. Cela permet aux assistants IA agentiques (tels que Claude ou Gemini) d'inspecter les statuts des certificats, de déclencher des renouvellements, de demander des diagnostics et d'interagir directement avec l'API CertMate.

## Fonctionnalités et outils

Le serveur MCP CertMate expose les outils suivants aux assistants IA :

**Inventaire et statut**
1. **`certmate_list_certificates`** — Liste tous les certificats gérés par l'instance CertMate active (avec expiration, statut, domaines).
2. **`certmate_get_certificate`** — Détail complet pour un domaine : statut, jours avant expiration, SANs, fournisseur DNS/CA, indicateur de renouvellement automatique. Utilisez-le pour décider si un certificat doit être renouvelé.
3. **`certmate_get_activity`** — Activité récente/journal d'audit, pour diagnostiquer ce qui a changé ou échoué.
4. **`certmate_diagnostics`** — Instantané de diagnostic complet et nettoyé.
5. **`certmate_get_settings`** — Paramètres globaux et configuration, avec les valeurs secrètes masquées.

**Opérations sur le cycle de vie**
6. **`certmate_create_certificate`** — Demande un nouveau certificat TLS pour un domaine (DNS provider, account, CA optionnels). Le serveur demande toujours une émission asynchrone, donc cet outil retourne un `job_id` (HTTP 202) à interroger.
7. **`certmate_renew_certificate`** — Renouvelle un certificat existant si CertMate le considère comme dû selon sa politique de renouvellement ; un certificat pas encore dû reste tel quel, et le job indique `renewed: false`. Également asynchrone : retourne un `job_id`.
8. **`certmate_get_job`** — Interroge un job asynchrone de création/renouvellement/mise à jour par `job_id` jusqu'à ce que son statut soit `succeeded` ou `failed` (`queued` et `running` ne sont pas des statuts finaux).
9. **`certmate_set_auto_renew`** — Active ou désactive le renouvellement automatique pour un seul domaine.
10. **`certmate_deploy_certificate`** — Exécute manuellement tous les hooks de déploiement configurés pour un domaine.
11. **`certmate_download_certificate`** — Retourne le matériel du certificat d'un domaine en JSON (fullchain, key, chain) pour qu'un agent puisse le déployer ailleurs.

**Fournisseurs**
12. **`certmate_list_dns_providers`** — Fournisseurs DNS supportés et configurés sur cette instance.
13. **`certmate_list_dns_accounts`** — Comptes fournisseurs DNS configurés (identifiants masqués) ; utilisez un ID de compte retourné comme `account_id` lors de la création d'un certificat. **Nécessite `admin`.**

**Modification et suppression**
14. **`certmate_update_certificate`** — Modifie sur place la couverture d'un certificat existant en le réémettant : remplace l'ensemble des SAN et/ou l'alias DNS-01. Le domaine principal est l'identité du certificat et ne peut pas être modifié ici. Retourne un `job_id`.
15. **`certmate_delete_certificate`** — **Destructif et irréversible.** Supprime les fichiers du certificat du disque et le domaine des paramètres. **Nécessite `admin`.**
16. **`certmate_get_certificate_file`** — Retourne un fichier de certificat en PEM brut, prêt à coller, plutôt qu'enveloppé dans du JSON. `cert.pem`, `chain.pem` et `fullchain.pem` sont lisibles par un `viewer` ; `privkey.pem`, `combined.pem` et `cert.pfx` contiennent du matériel de clé et nécessitent `operator`.

## Rôles

Donnez à l'agent le token le plus restreint qui lui permet de faire son travail, et notez que quelques outils
exigent plus que les autres :

| Outil | Rôle minimum |
|---|---|
| tout ce qui figure sous Inventaire et statut sauf les diagnostics (`certmate_get_settings` retourne les secrets masqués), `certmate_list_dns_providers`, `certmate_get_certificate_file` pour `cert.pem` / `chain.pem` / `fullchain.pem` | `viewer` |
| `certmate_create_certificate`, `certmate_renew_certificate`, `certmate_get_job`, `certmate_set_auto_renew`, `certmate_update_certificate`, `certmate_download_certificate`, `certmate_get_certificate_file` pour `privkey.pem` / `combined.pem` / `cert.pfx` | `operator` |
| `certmate_diagnostics` | `admin` |
| **`certmate_deploy_certificate`** | **`admin`** |
| **`certmate_list_dns_accounts`** | **`admin`** |
| **`certmate_delete_certificate`** | **`admin`** |

Le déploiement et la liste des comptes sont les cas surprenants : tous deux lisent des identifiants stockés ou agissent
sur eux, donc tous deux exigent `admin` côté serveur, même si un agent qui
ne fait que renouveler se contenterait sinon de `operator`. Un agent limité à operator
à qui l'on demande de « choisir un compte et émettre » recevra un 403 sur la recherche du compte — passez
plutôt l'`account_id` dans le prompt, ou donnez-lui délibérément un token admin.

## Configuration

### Prérequis
- Node.js (>= 20 — `mcp/package.json` déclare `engines.node: ">=20.0.0"`)
- npm

### Installation
Naviguez vers le répertoire `mcp/` dans le dépôt CertMate et installez les dépendances :
```bash
cd mcp
npm install
```

### Variables d'environnement
Le serveur MCP communique avec l'API REST CertMate et nécessite deux variables d'environnement :
- `CERTMATE_URL` — L'URL de votre instance CertMate (défaut : `http://localhost:8000`).
- `CERTMATE_TOKEN` — Un token Bearer API valide avec les permissions de rôle appropriées (généralement `operator` ou `admin`). Pour un agent auditable, utilisez une clé marquée comme clé d'agent (voir [Attribution d'audit](#attribution-daudit)).

Optionnel :
- `CERTMATE_AGENT_SESSION` — Surcharge l'ID de session par processus que le serveur envoie à chaque appel (`X-CertMate-Agent-Session`), pour qu'une exécution puisse être corrélée avec l'ID d'un orchestrateur externe. Un nouvel UUID est généré par processus s'il n'est pas défini.
- `CERTMATE_AGENT_ID` — Un libellé pour ce déploiement d'agent (`X-CertMate-Agent-Id`, défaut `certmate-mcp-server`).

### Exemple d'intégration (configuration de Claude Desktop)
Pour ajouter le serveur MCP CertMate à Claude Desktop, ajoutez ceci à votre fichier de configuration (généralement situé dans `~/Library/Application Support/Claude/claude_desktop_config.json` sur macOS ou `%APPDATA%\Claude\claude_desktop_config.json` sur Windows) :

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/absolute/path/to/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "your_secure_bearer_token"
      }
    }
  }
}
```

### Autres clients MCP (Gemini, etc.)

Le serveur parle MCP standard sur stdio, donc tout client qui supporte MCP fonctionne
de la même manière : pointez-le vers `node /absolute/path/to/certmate/mcp/index.js` et définissez les
deux variables d'environnement. Rien dans le serveur n'est spécifique à Claude.

## Utiliser CertMate avec un agent IA (tâches planifiées)

La plupart des assistants haut de gamme supportent désormais les **tâches planifiées** (Claude, Gemini et
d'autres). Combinez cela avec ce serveur MCP et vous obtenez un « gardien de
certificats » autonome : vous décrivez la politique en langage naturel avec des conditions explicites, le
modèle se planifie lui-même, et à chaque exécution il utilise les outils ci-dessus pour appliquer la
politique. Le schéma est agnostique vis-à-vis du modèle — tout ce qui peut exécuter un prompt sauvegardé selon un
calendrier et appeler des outils MCP fonctionnera.

### La boucle exécutée par l'agent

1. `certmate_list_certificates` (ou `certmate_get_certificate` par domaine) pour lire `days_left` / le statut.
2. Décider selon votre condition, par ex. *renouveler quand `days_left < 14`*.
3. `certmate_renew_certificate` pour chaque domaine arrivé à échéance.
4. Chaque renouvellement retourne un `job_id` ; appelez `certmate_get_job` jusqu'à ce qu'il indique `succeeded` / `failed`. Un certificat que CertMate ne considère pas encore comme dû réussit avec `renewed: false` : rien n'a été émis.
5. En cas d'échec, remontez-le. Un job de renouvellement ou de réémission en échec émet aussi `certificate_failed`, donc les propres canaux de notification de CertMate (email, Slack, Discord, Telegram, ntfy, Gotify) le signalent de toute façon. Deux exceptions : un job qui a échoué parce qu'une autre opération détenait déjà le domaine (`error_code: DOMAIN_OPERATION_IN_PROGRESS`) ne l'émet pas, et une création asynchrone en échec non plus ; dans ces cas, c'est le rapport de l'agent lui-même qui fait office de signal.

### Exemples de prompts planifiés

> **Quotidien, 08:00** — « En utilisant les outils MCP CertMate, liste tous les certificats. Pour ceux
> avec `days_left < 14`, appelle `certmate_renew_certificate`, puis interroge
> `certmate_get_job` jusqu'à la fin. Réponds avec un résumé d'une ligne par domaine et
> signale les échecs éventuels. »

> **Hebdomadaire** — « Appelle `certmate_get_activity` et `certmate_diagnostics`. Résume
> tout ce qui est inhabituel (renouvellements échoués, certificats expirés, planificateur arrêté) en trois
> points. Si rien ne va de travers, dis-le. »

> **Sur demande** — « Émets un certificat pour `shop.example.com` en utilisant `certmate_list_dns_providers`
> pour choisir un fournisseur configuré et `certmate_list_dns_accounts` pour l'ID du compte,
> puis suis le job jusqu'à son terme. »

Comme les conditions vivent dans le prompt, vous pouvez ajuster la politique (seuil,
quels domaines, que faire en cas d'échec) sans toucher au code. Donnez à l'agent un
token limité exactement à ce qu'il doit faire — `operator` pour renouveler, `admin`
seulement s'il doit exécuter des deploy hooks, lister les comptes DNS, supprimer des certificats ou lire les diagnostics.

## Sécurité

1. **Protection du token** — Le serveur MCP nécessite un `CERTMATE_TOKEN` valide. Il envoie ce token dans l'en-tête `Authorization` de chaque requête vers l'API CertMate. La valeur par défaut de `CERTMATE_URL` est `http://localhost:8000`, en HTTP simple ; quand CertMate tourne sur un autre hôte, utilisez une URL `https://`, sinon le token traverse le réseau en clair.
2. **Moindre privilège** — Limitez le token à ce dont l'agent a besoin. Un gardien de renouvellement planifié a besoin de `operator` ; réservez les tokens `admin` aux agents qui doivent exécuter des deploy hooks, lister les comptes DNS, supprimer des certificats ou extraire des diagnostics. Révoquez le token pour couper instantanément l'accès de l'agent.
3. **Compatibilité avec l'assainissement des logs** — Les outils comme `certmate_diagnostics` récupèrent les données après que le nettoyeur de logs a supprimé les identifiants sensibles, ce qui empêche les clés et les tokens de fuiter dans les contextes LLM.

## Attribution d'audit

Pour que la piste d'audit puisse distinguer les actions d'un agent de celles d'un opérateur humain,
donnez au serveur MCP une **clé API dédiée, marquée comme agent**, plutôt que le token Bearer
global legacy :

1. Dans CertMate, allez dans **Paramètres → Clés API**, créez une clé et cochez **Clé d'agent
   IA** (ou envoyez `"is_agent": true` à `POST /api/keys`). Donnez-lui le rôle le plus bas dont elle a besoin,
   et, pour une clé `viewer` ou `operator`, limitez-la avec `allowed_domains`. Une
   clé `admin` ne peut pas être limitée à des domaines : le serveur la refuse avec un 400.
2. Définissez cette clé comme `CERTMATE_TOKEN` pour le serveur MCP.

Chaque action sur un certificat que l'agent effectue ensuite est enregistrée avec
`actor.kind="agent"`, l'ID stable de la clé, et le `X-CertMate-Agent-Session`
par processus que le serveur envoie — vous pouvez ainsi montrer plus tard exactement quelles
modifications de certificat un agent IA a effectuées, sous quelle identité, et groupées par exécution.
Le token Bearer global legacy réduit chaque appelant à `api_user` sans ID de
clé et est enregistré comme `api_token`, pas `agent`. L'en-tête de session d'agent est une
déclaration informative et ne promeut jamais, à lui seul, un appelant au rang d'`agent`.

Les enregistrements qui en résultent font partie de la chaîne d'audit infalsifiable ; voir
[Journalisation d'audit](./api.md#journalisation-daudit) et [compliance.md](./compliance.md).
