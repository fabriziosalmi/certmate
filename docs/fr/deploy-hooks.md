# Hooks de déploiement

<!-- CERTMATE-TRANSLATED-FROM 380a402d93da0cfb -->
<!-- CERTMATE-STALE-TRANSLATION -->
> **Cette traduction n'est pas à jour.** La version anglaise ([`docs/deploy-hooks.md`](../deploy-hooks.md)) a été modifiée depuis et fait foi. En cas de divergence, le document anglais prévaut.

Clôture [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Les hooks de déploiement sont des commandes shell courtes que CertMate exécute **après** l'émission, le renouvellement ou la révocation d'un certificat. Utilisez-les pour recharger des services, pousser le nouveau certificat vers un équilibreur de charge, envoyer une notification, ou toute autre action nécessaire suite à une exécution réussie de certbot.

Ce guide couvre :

1. [Qu'est-ce qu'un hook](#quest-ce-quun-hook)
2. [Configuration des hooks (UI + JSON)](#configuration-des-hooks)
3. [Variables d'environnement transmises à votre commande](#variables-denvironnement-transmises-à-votre-commande)
4. [Déclenchement manuel](#déclenchement-manuel)
5. [Modèle de sécurité : pourquoi certaines commandes sont rejetées](#modèle-de-sécurité)
6. [Recettes courantes](#recettes-courantes)
7. [Audit, historique et débogage](#audit-historique-et-débogage)

---

## Qu'est-ce qu'un hook

Un hook est un objet JSON avec cinq champs :

| Champ | Type | Requis | Notes |
|---|---|---|---|
| `id` | string | oui | Identifiant stable (un UUID convient ; l'UI en auto-génère un). Utilisé par `/api/deploy/test/<id>`. |
| `name` | string | oui | Libellé affiché dans l'UI et le journal d'audit. |
| `command` | string | oui | Commande shell unique (`sh -c`). Max 1024 caractères. Voir [sécurité](#modèle-de-sécurité). |
| `enabled` | boolean | non | Par défaut `true`. Les hooks désactivés sont ignorés pendant le déclenchement automatique mais peuvent encore être testés manuellement. |
| `timeout` | integer | non | Secondes. Défaut 30, plafonné au `MAX_TIMEOUT` système (actuellement 300). |
| `on_events` | string array | non | Sous-ensemble de `["created", "renewed", "revoked"]`. Si absent lors de l'enregistrement de la configuration, il est fixé à `["created", "renewed"]` — `revoked` doit être choisi explicitement, afin qu'ajouter un hook ne se mette pas à exécuter des commandes sur des révocations pour lesquelles personne ne l'a écrit. Un hook écrit à la main dans `settings.json` n'est jamais normalisé : sans `on_events`, il ne s'exécute sur aucun événement de certificat ; un déclenchement manuel le lance toujours. |

Les hooks vivent sous deux clés dans `deploy_hooks` :

- **`global_hooks`** — s'exécutent pour chaque domaine. Idéal pour "recharger nginx après tout changement de certificat".
- **`domain_hooks`** — indexés par nom de domaine exact. Idéal pour "pousser le certificat LB pour `api.example.com` vers S3 après le renouvellement de ce certificat spécifique".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Recharger nginx",
        "command": "curl -fsS -X POST https://lb.internal/api/reload",
        "enabled": true,
        "timeout": 30,
        "on_events": ["created", "renewed"]
      }
    ],
    "domain_hooks": {
      "api.example.com": [
        {
          "id": "9b1...",
          "name": "Pousser vers le LB",
          "command": "/opt/scripts/push-cert-to-lb.sh",
          "enabled": true,
          "timeout": 120,
          "on_events": ["renewed"]
        }
      ]
    }
  }
}
```

Si `enabled` au niveau supérieur est `false`, aucun hook ne s'exécute lors des événements de certificat. Les tests manuels (`POST /api/deploy/test/<id>`) fonctionnent toujours — utile pour itérer sur un hook avant d'activer l'interrupteur principal.

---

## Configuration des hooks

### Via l'UI

`Paramètres → Hooks de déploiement`. Activez/désactivez l'interrupteur **Activé**, puis ajoutez des hooks globaux ou par domaine. Chaque ligne comporte :

- nom + commande + timeout + cases à cocher d'événements
- un bouton **Test** (exécute le hook contre un domaine synthétique `test.example.com` avec `CERTMATE_EVENT=manual`)
- interrupteur d'activation/désactivation
- suppression

Sauvegardez les paramètres pour persister.

### Via l'API

```bash
# Lire la configuration actuelle
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Remplacer la configuration (écriture complète du document)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Le POST remplace tout le bloc `deploy_hooks` ; fusionnez côté client si vous souhaitez préserver les entrées existantes.

---

## Variables d'environnement transmises à votre commande

Chaque invocation définit ces variables dans l'environnement du processus du hook :

| Variable | Exemple de valeur |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (intermédiaires uniquement, sans le feuillet) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` |
| `CERTMATE_DRY_RUN` | Défini à `1` uniquement pendant les tests à sec ; absent autrement. |

Votre commande peut référencer ces variables comme `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. Les valeurs sont passées par environnement, pas par interpolation de chaîne, donc le quoting fonctionne comme dans tout shell normal.

Le hook s'exécute en tant qu'utilisateur du processus CertMate (dans l'image Docker : `certmate`, UID/GID 1000:1000) à l'intérieur du conteneur. Tout ce que vous faites avec `cp`, `curl`, `ssh`, etc. doit être accessible depuis là.

---

## Déclenchement manuel

Deux façons de déclencher un hook en dehors du cycle de vie normal du certificat :

### Test par hook (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Exécute uniquement le hook avec cet `id`, contre le domaine synthétique `test.example.com`, avec `CERTMATE_EVENT=manual`. Contourne le filtre `on_events` — utile pour "est-ce que cette commande fonctionne réellement ?".

### Exécuter tous les hooks pour un domaine (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Déclenche tous les hooks globaux + spécifiques au domaine activés pour `api.example.com` avec `CERTMATE_EVENT=manual`, ignorant `on_events`. Retourne un résumé structuré :

```jsonc
{
  "ok": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "results": [
    {"hook_name": "Recharger nginx", "exit_code": 0, "duration_ms": 142, ...},
    ...
  ]
}
```

C'est ce que le bouton **Exécuter les hooks maintenant** dans le panneau de détail du certificat appelle.

---

## Modèle de sécurité

Les hooks sont une exécution de code arbitraire par conception — c'est la fonctionnalité. Pour limiter l'impact, la commande est validée **à la sauvegarde et à l'exécution** (défense en profondeur) et rejetée si elle contient :

### Motifs shell bloqués

| Motif | Raison |
|---|---|
| `` ` `` (backticks) | Substitution de commande |
| `$(...)` | Substitution de commande |
| `${...}` | Développement de paramètre (l'expansion de variable d'env est autorisée — seule la forme `${...}` est bloquée) |
| `&&` / `\|\|` | Chaînage logique |
| `;` | Séparateur d'instruction |
| `\|` | Pipe |
| `\r` / `\n` | Sauts de ligne (empêche `sh -c` de les interpréter comme `;`) |
| `> /` (redirection vers chemin absolu) | Empêche l'écrasement de fichiers système |
| `<<` | Here-doc |
| `eval`, `source`, `.` (le raccourci de source, avec n’importe quel argument) | Builtins shell qui chargent du code arbitraire |

Si vous avez besoin de l'un de ces éléments, mettez la logique dans un fichier script à l'intérieur du conteneur et appelez le script directement :

```sh
/opt/scripts/deploy.sh
```

### Références de fichiers bloquées

Les références aux fichiers sensibles de CertMate sont rejetées (insensible à la casse) :

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`, `private*key`, `.pem`

Ainsi `cat $CERTMATE_FULLCHAIN_PATH` est acceptable (la variable est développée par le shell, la chaîne littérale `.pem` n'apparaît pas dans `command`), mais `cat /app/data/settings.json` serait rejeté à la sauvegarde.

### Ce qui est autorisé

- **Commandes simples** : `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **Requêtes curl (webhooks)** : `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Expansion de variables dans les arguments** : `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Charges JSON avec `$VAR` (pas `${}`)** : `curl -d '{"domain":"$CERTMATE_DOMAIN"}' ...`
- **Invocation de script unique** : `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Si une commande que vous pouviez sauvegarder auparavant déclenche maintenant `Command blocked at runtime: contains dangerous shell metacharacters`, consultez les notes de version — le validateur a été renforcé dans v2.4.0 et légèrement assoupli dans v2.4.1+.

---

## Où s'exécute un hook

**Dans le conteneur CertMate**, en tant que processus ayant émis le certificat — pas sur l'hôte Docker, ni sur la machine que vous voulez recharger.

C'est le point à saisir avant d'écrire un hook, et les exemples de cette page se trompaient. `systemctl reload haproxy` se lit comme s'il rechargeait votre répartiteur de charge. Il n'en fait rien : il s'exécute dans un conteneur sans systemd, sans haproxy et sans nginx, et sort en 127 — *not found* — ce qu'a signalé [#856](https://github.com/fabriziosalmi/certmate/issues/856) pour `scp`.

Ce que l'image publiée contient réellement, pour un hook :

| | |
|---|---|
| **présents** | `sh`, `bash`, `curl`, `openssl` |
| **absents** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, et tout le reste |

La liste est courte à dessein : l'étape d'exécution installe trois paquets, et le Dockerfile explique pourquoi — chaque paquet ajouté est une surface à corriger et à analyser ([#403](https://github.com/fabriziosalmi/certmate/issues/403)).

### Trois façons d'agir sur une autre machine

**Le lui demander par le réseau.** Presque tout ce qui mérite d'être rechargé a une API, et `curl` est présent.

**Construire sa propre image.** Celle de CertMate est une base comme une autre :

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

**Monter un script.** Un hook peut appeler n'importe quel chemin du conteneur — mais il s'exécute toujours dans le conteneur, et ce qu'il invoque doit donc s'y trouver aussi.

---

## Recettes courantes

Elles s'exécutent dans l'image telle qu'elle est publiée. Chacune est vérifiée contre elle.

### Envoyer vers un webhook Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Prévenir autre chose que le certificat a changé

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` compte : sans lui, `curl` sort en 0 même sur une erreur HTTP, et le hook signale un succès pour un déploiement qui n'a pas eu lieu.

### Vérifier ce qui a été émis

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Exécuter son propre script

```sh
/opt/scripts/deploy.sh
```

Monté dans le conteneur et écrit pour ce que le conteneur possède.
---

## Audit, historique et débogage

### Flux d'activité

`GET /api/deploy/history?limit=50` et l'onglet **Activité** de l'UI montrent les N dernières exécutions de hooks avec : nom du hook, domaine, événement, code de sortie, durée, stdout/stderr (tronqués à 4096 octets chacun) et horodatage.

### Console de débogage

Paramètres → Hooks de déploiement a une console de débogage (bouton de bascule en bas à droite) qui diffuse les événements `loadConfig` / `saveConfig` / `testHook` côté client. Utile pour itérer sur l'UI.

### Journal d'audit

Chaque exécution de hook écrit une entrée `operation: deploy_hook` dans le journal d'audit avec le statut `success`/`failure` plus le nom du hook, le code de sortie et la durée. Visible via l'onglet Activité et `/api/audit`.

### Échecs courants

| Symptôme | Cause probable |
|---|---|
| `Hook not found` | L'ID du hook dans la requête de test ne correspond à aucun hook dans la configuration sauvegardée (l'UI était obsolète ou le hook vient d'être supprimé). Rafraîchissez la page. |
| `Command blocked at runtime` | Un des [motifs bloqués](#motifs-shell-bloqués) a contourné la sauvegarde. Déplacez la logique problématique dans un fichier script. |
| `exit code 127` | Commande introuvable dans le conteneur (ex. `nginx` n'est pas dans `$PATH`). Utilisez des chemins absolus ou installez le binaire dans l'image. |
| `timeout after 30s` | Le hook a dépassé son `timeout`. Augmentez-le (max 300s) ou déplacez le travail vers un script en arrière-plan. |
| `Deploy hooks disabled` | `deploy_hooks.enabled` est `false`. Activez l'interrupteur principal dans Paramètres. |
| `No hooks configured for <domain>` | Tentative d'exécution de hooks pour un domaine sans hooks globaux ET sans entrée sous `domain_hooks[<domaine>]`. Ajoutez un hook (ou appelez `/api/deploy/test/<id>` pour un hook spécifique). |

---

## Voir aussi

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implémentation
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoints `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — composant Alpine

---

<div align="center">

[← Retour à la documentation](./README.md)

</div>
