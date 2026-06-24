# Serveur MCP (Model Context Protocol) CertMate

CertMate inclut un serveur MCP (Model Context Protocol) intégré écrit en Node.js. Cela permet aux assistants IA agentiques (tels que Claude ou Gemini) d'inspecter en toute sécurité les statuts des certificats, de déclencher des renouvellements, de demander des diagnostics et d'interagir directement avec l'API CertMate.

## Fonctionnalités et outils

Le serveur MCP CertMate expose les outils suivants aux assistants IA :

**Inventaire et statut**
1. **`certmate_list_certificates`** — Liste tous les certificats gérés (avec expiration, statut, domaines).
2. **`certmate_get_certificate`** — Détail complet pour un domaine : statut, jours avant expiration, SANs, fournisseur DNS/CA, renouvellement auto. Utilisez-le pour décider si un certificat doit être renouvelé.
3. **`certmate_get_activity`** — Activité récente/journal d'audit pour diagnostiquer les changements ou échecs.
4. **`certmate_diagnostics`** — Instantané de diagnostic complet et nettoyé.
5. **`certmate_get_settings`** — Paramètres globaux et configuration.

**Opérations sur le cycle de vie**
6. **`certmate_create_certificate`** — Demande un nouveau certificat TLS pour un domaine (DNS provider, account, CA optionnels). Peut retourner un `job_id` (HTTP 202) pour une émission asynchrone.
7. **`certmate_renew_certificate`** — Force le renouvellement d'un certificat existant (peut aussi retourner un `job_id`).
8. **`certmate_get_job`** — Interroge un travail asynchrone par `job_id` jusqu'à ce qu'il soit terminé ou en échec.
9. **`certmate_set_auto_renew`** — Active ou désactive le renouvellement automatique pour un seul domaine.
10. **`certmate_deploy_certificate`** — Exécute manuellement tous les hooks de déploiement configurés pour un domaine.
11. **`certmate_download_certificate`** — Retourne le matériel du certificat d'un domaine en JSON (fullchain, key, chain) pour qu'un agent puisse le déployer ailleurs.

**Fournisseurs**
12. **`certmate_list_dns_providers`** — Fournisseurs DNS supportés et configurés sur cette instance.
13. **`certmate_list_dns_accounts`** — Comptes fournisseurs DNS configurés (identifiants masqués) ; utilisez un ID de compte retourné comme `account_id` lors de la création d'un certificat.

## Configuration

### Prérequis
- Node.js (v18 ou supérieur)
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
- `CERTMATE_AGENT_SESSION` — Surcharge l'ID de session par processus que le serveur envoie à chaque appel (`X-CertMate-Agent-Session`), pour qu'une exécution puisse être corrélée avec un ID d'orchestrateur externe. Un UUID frais est généré par processus si non défini.
- `CERTMATE_AGENT_ID` — Un libellé pour ce déploiement d'agent (`X-CertMate-Agent-Id`, défaut `certmate-mcp-server`).

### Intégration avec Claude Desktop

Pour ajouter le serveur MCP CertMate à Claude Desktop, ajoutez ceci à votre fichier de configuration (généralement situé dans `~/Library/Application Support/Claude/claude_desktop_config.json` sur macOS ou `%APPDATA%\\Claude\\claude_desktop_config.json` sur Windows) :

```json
{
  "mcpServers": {
    "certmate": {
      "command": "node",
      "args": ["/chemin/absolu/vers/certmate/mcp/index.js"],
      "env": {
        "CERTMATE_URL": "http://localhost:8000",
        "CERTMATE_TOKEN": "votre_token_bearer_securise"
      }
    }
  }
}
```

### Autres clients MCP (Gemini, etc.)

Le serveur parle MCP standard sur stdio, donc tout client supportant MCP fonctionne de la même manière : pointez-le vers `node /chemin/absolu/vers/certmate/mcp/index.js` et définissez les deux variables d'environnement. Rien dans le serveur n'est spécifique à Claude.

## Utiliser CertMate avec un agent IA (tâches planifiées)

La plupart des assistants haut de gamme supportent désormais les **tâches planifiées** (Claude, Gemini, etc.). Combinez cela avec ce serveur MCP et vous obtenez un "gardien de certificats" autonome : vous décrivez la politique en langage naturel avec des conditions explicites, le modèle se planifie, et à chaque exécution il utilise les outils ci-dessus pour appliquer la politique. Le modèle est agnostique — tout ce qui peut exécuter une instruction sauvegardée sur un calendrier et appeler des outils MCP fonctionnera.

### La boucle d'exécution de l'agent

1. `certmate_list_certificates` (ou `certmate_get_certificate` par domaine) pour lire `days_left` / statut.
2. Décision selon votre condition, ex. *renouveler quand `days_left < 14`*.
3. `certmate_renew_certificate` pour chaque domaine concerné.
4. Si un renouvellement retourne un `job_id`, `certmate_get_job` jusqu'à ce qu'il signale `completed` / `failed`.
5. En cas d'échec, remontez-le — et les canaux de notification de CertMate (email, Slack, Discord, Telegram, ntfy, Gotify) se déclencheront également sur `certificate_failed`.

### Exemples de prompts planifiés

> **Quotidien, 08:00** — "Utilise les outils MCP CertMate, liste tous les certificats. Pour ceux avec `days_left < 14`, appelle `certmate_renew_certificate`, puis interroge `certmate_get_job` jusqu'à la fin. Résume par domaine et signale les échecs."

> **Hebdomadaire** — "Appelle `certmate_get_activity` et `certmate_diagnostics`. Résume les anomalies (renouvellements échoués, certificats expirés, planificateur arrêté) en trois points. Si rien ne va, dis-le."

> **Sur demande** — "Émets un certificat pour `shop.example.com` en utilisant `certmate_list_dns_providers` pour choisir un fournisseur configuré et `certmate_list_dns_accounts` pour l'ID du compte, puis surveille le travail jusqu'à la fin."

Comme les conditions vivent dans le prompt, vous pouvez ajuster la politique (seuil, domaines, action en cas d'échec) sans toucher au code. Donnez à l'agent un token scoped exactement pour ce qu'il doit faire — `operator` pour renouveler/déployer, `admin` seulement s'il doit modifier les paramètres ou lire les diagnostics.

## Sécurité

1. **Protection du jeton** — Le serveur MCP nécessite un `CERTMATE_TOKEN` valide. Il transmet ce token de manière sécurisée dans l'en-tête `Authorization` pour toutes les requêtes vers l'API CertMate.
2. **Moindre privilège** — Limitez le token à ce dont l'agent a besoin. Un gardien de renouvellement planifié a besoin de `operator` ; réservez les tokens `admin` pour les agents qui doivent modifier les paramètres ou extraire des diagnostics. Révoquez le token pour couper instantanément l'accès de l'agent.
3. **Compatibilité d'assainissement des logs** — Les outils comme `certmate_diagnostics` récupèrent les données après que le nettoyeur de logs a supprimé les identifiants sensibles, protégeant les clés et tokens contre les fuites dans les contextes LLM.

## Attribution d'audit

Pour que la piste d'audit distingue les actions d'un agent de celles d'un opérateur humain, donnez au serveur MCP une **clé API dédiée marquée comme agent** plutôt que le token Bearer global legacy :

1. Dans CertMate, allez dans **Paramètres → Clés API**, créez une clé et cochez **Clé d'agent IA** (ou envoyez `"is_agent": true` à `POST /api/keys`). Limitez-la avec `allowed_domains` et le rôle le plus bas nécessaire.
2. Définissez cette clé comme `CERTMATE_TOKEN` pour le serveur MCP.

Chaque action de certificat effectuée par l'agent est enregistrée avec `actor.kind="agent"`, l'ID stable de la clé, et le `X-CertMate-Agent-Session` par processus que le serveur envoie — vous pouvez ainsi montrer exactement quels changements de certificat ont été effectués par un agent IA, sous quelle identité, et groupés par exécution. Le token Bearer global legacy réduit chaque appelant à `api_user` sans ID de clé et est enregistré comme `api_token`, pas `agent`. L'en-tête de session d'agent est une information déclarative et ne promeut jamais un appelant vers `agent` par lui-même.

Les enregistrements qui en résultent font partie de la chaîne d'audit infalsifiable ; voir [Journal d'audit](./api.md#journalisation-daudit) et [conformité.md](./compliance.md).

---

<div align="center">

[← Retour à la documentation](./README.md)

</div>
