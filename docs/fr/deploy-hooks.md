# Hooks de déploiement

<!-- CERTMATE-TRANSLATED-FROM 0d31dc7a82589489 -->

Clôture [#117](https://github.com/fabriziosalmi/certmate/issues/117).

Les hooks de déploiement sont des commandes shell courtes que CertMate exécute **après** l'émission, le renouvellement ou la révocation d'un certificat. Utilisez-les pour recharger des services, pousser le nouveau certificat vers un équilibreur de charge, envoyer une notification, ou pour toute autre action qui doit suivre une exécution réussie de certbot.

> **À propos de `revoked`.** Seuls les certificats clients peuvent être révoqués via CertMate — `POST /api/client-certs/<id>/revoke` — et c'est donc à ce moment qu'un hook `revoked` se déclenche, avec `CERTMATE_DOMAIN` défini sur l'identifiant du certificat client. Il n'existe aucune opération de révocation pour un certificat serveur, donc aucun hook ne se déclenche pour un tel certificat.

Ce guide couvre :

1. [Qu'est-ce qu'un hook](#quest-ce-quun-hook)
2. [Configuration des hooks (UI + JSON)](#configuration-des-hooks)
3. [Variables d'environnement transmises à votre commande](#variables-denvironnement-transmises-à-votre-commande)
4. [Fenêtres de maintenance](#fenêtres-de-maintenance)
5. [Déclenchement manuel](#déclenchement-manuel)
6. [Modèle de sécurité : pourquoi certaines commandes sont rejetées](#modèle-de-sécurité)
7. [Où s'exécute un hook](#où-sexécute-un-hook)
8. [Recettes courantes](#recettes-courantes)
9. [Audit, historique et débogage](#audit-historique-et-débogage)
10. [Cibles de déploiement typées](#cibles-de-déploiement-typées)

---

## Qu'est-ce qu'un hook

Un hook est un objet JSON avec ces champs :

| Champ | Type | Requis | Notes |
|---|---|---|---|
| `id` | string | oui | Identifiant stable (un UUID convient ; l'UI en génère un automatiquement). Utilisé par `/api/deploy/test/<id>`. |
| `name` | string | oui | Libellé lisible affiché dans l'UI et dans le journal d'audit. |
| `command` | string | oui | Une seule commande shell (`sh -c`). 1024 caractères au maximum. Voir [sécurité](#modèle-de-sécurité). |
| `enabled` | boolean | non | `true` par défaut. Les hooks désactivés sont ignorés lors du déclenchement automatique mais peuvent toujours être testés manuellement. |
| `timeout` | integer | non | En secondes. 30 par défaut, plafonné au `MAX_TIMEOUT` du système (actuellement 300). |
| `on_events` | string array | non | Sous-ensemble de `["created", "renewed", "revoked"]`. S'il est absent lors de l'enregistrement de la configuration, il est fixé à `["created", "renewed"]` — `revoked` doit être choisi explicitement, afin qu'ajouter un hook ne se mette pas à exécuter des commandes sur des révocations pour lesquelles personne ne l'a écrit. Un hook écrit à la main dans `settings.json` n'est jamais normalisé : sans `on_events`, il ne se déclenche sur aucun événement de certificat ; un déclenchement manuel le lance toujours. |
| `window` | object | non | Une [fenêtre de maintenance](#fenêtres-de-maintenance). S'il est absent, le hook s'exécute dès que le certificat est émis ou renouvelé — le comportement qu'ont eu tous les hooks jusqu'à présent. |

Les hooks se trouvent sous deux clés de `deploy_hooks` :

- **`global_hooks`** — se déclenchent pour chaque domaine. Idéal pour "recharger nginx après tout changement de certificat".
- **`domain_hooks`** — indexés par nom de domaine exact. Idéal pour "pousser le certificat du LB pour `api.example.com` vers S3 après le renouvellement de ce certificat précis".

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "global_hooks": [
      {
        "id": "5f8...",
        "name": "Tell the load balancer",
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
          "name": "Push to LB",
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

Si `enabled` au niveau supérieur vaut `false`, aucun hook ne s'exécute lors des événements de certificat. Les tests par hook (`POST /api/deploy/test/<id>`) fonctionnent toujours — utile pour mettre au point un hook avant d'activer l'interrupteur principal. L'exécution de tous les hooks d'un domaine (`POST /api/certificates/<domain>/deploy`), elle, ne fonctionne pas : elle est refusée tant que l'interrupteur est désactivé.

---

## Configuration des hooks

### Via l'UI

`Settings → Deploy Hooks`. Activez l'interrupteur **Enabled**, puis ajoutez des hooks globaux ou par domaine. Chaque ligne comporte :

- nom + commande + timeout + cases à cocher des événements
- un bouton **Test** (exécute le hook contre un domaine synthétique `test.example.com` avec `CERTMATE_EVENT=test` et `CERTMATE_DRY_RUN=1`)
- un interrupteur d'activation/désactivation
- la suppression

Enregistrez les paramètres pour les rendre persistants.

### Via l'API

```bash
# Lire la configuration actuelle
curl -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/config

# Écrire la configuration (les clés de premier niveau envoyées remplacent celles enregistrées)
curl -X POST -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d @hooks.json https://certmate.local/api/deploy/config
```

Le POST fusionne au premier niveau de `deploy_hooks` : chaque clé que vous envoyez (`enabled`, `global_hooks`, `domain_hooks`, `targets`) remplace entièrement la valeur enregistrée, et une clé que vous omettez est conservée telle quelle. Envoyer `global_hooks` remplace donc toute la liste ; pour ajouter un hook, lisez la liste, ajoutez-y l'entrée et renvoyez-la. Une liste vide explicite efface cette clé.

---

## Variables d'environnement transmises à votre commande

Chaque invocation définit ces variables dans l'environnement du processus du hook :

| Variable | Exemple de valeur |
|---|---|
| `CERTMATE_DOMAIN` | `api.example.com` |
| `CERTMATE_CERT_PATH` | `/app/certificates/api.example.com/cert.pem` |
| `CERTMATE_KEY_PATH` | `/app/certificates/api.example.com/privkey.pem` — **non définie** pour un [certificat CSR-only](../csr-only-certificates.md), dont la clé reste sur l'appareil |
| `CERTMATE_FULLCHAIN_PATH` | `/app/certificates/api.example.com/fullchain.pem` |
| `CERTMATE_CHAIN_PATH` | `/app/certificates/api.example.com/chain.pem` (intermédiaires uniquement, sans le certificat feuille — pour les cibles qui veulent la chaîne dans un fichier séparé) |
| `CERTMATE_TAGS` | `loadbalancer,env:prod` — les [tags](./api.md) du certificat, séparés par des virgules et en minuscules ; **vide** s'il n'en a aucun, et toujours définie, pour qu'un hook puisse s'y fier (depuis le contrat d'API 2.33) |
| `CERTMATE_EVENT` | `created` / `renewed` / `revoked` / `manual` (Deploy Now) / `test` (test par hook). `renewed` suit aussi le [remplacement d'un certificat externe](../api.md#replace-an-external-certificate) par téléversement. |
| `CERTMATE_DRY_RUN` | Définie à `1` uniquement pour un test par hook (`/api/deploy/test/<id>`, le bouton **Test**) ; absente sinon, y compris pour Deploy Now. La commande s'exécute quand même ; ce n'est qu'un signal que votre script peut vérifier. |

Les chemins se trouvent dans le répertoire des certificats de CertMate : `/app/certificates` dans l'image Docker, ou l'endroit vers lequel pointe `CERTMATE_CERT_DIR`.

Votre commande peut référencer ces variables sous la forme `$CERTMATE_DOMAIN`, `"$CERTMATE_FULLCHAIN_PATH"`, etc. Les valeurs sont transmises par l'environnement, et non par interpolation de chaîne, donc les guillemets fonctionnent comme dans n'importe quel shell normal.

Le hook s'exécute en tant qu'utilisateur du processus CertMate (dans l'image Docker : `certmate`, UID/GID 1000:1000) à l'intérieur du conteneur. Tout ce que vous visez avec `cp`, `curl`, `ssh`, etc. doit être accessible depuis là.

---

## Fenêtres de maintenance

Clôture [#632](https://github.com/fabriziosalmi/certmate/issues/632).

Un certificat est renouvelé quand il arrive à échéance, à un moment que personne n'a choisi : le balayage de renouvellement s'exécute à 02:00 avec une heure de décalage aléatoire, et seulement pour les certificats qui passent sous le seuil cette nuit-là. Le hook s'exécutait alors immédiatement. Pour un hook qui redémarre une base de données ou recharge un équilibreur de charge, cela signifie une interruption de service à une heure imprévisible.

Une `window` sépare les deux. Le certificat est toujours renouvelé dès qu'il arrive à échéance — c'est dicté par l'expiration et ce n'est pas négociable — mais le **déploiement** est retenu jusqu'à la prochaine ouverture de la fenêtre.

```jsonc
"window": {
  "start": "02:00",          // obligatoire, HH:MM sur 24 heures
  "end": "04:00",            // obligatoire, exclue
  "days": ["sat", "sun"],    // facultatif ; omettre ou laisser vide pour tous les jours
  "timezone": "Europe/Rome"  // nom IANA facultatif, UTC par défaut
}
```

Le même champ fonctionne sur les cibles de déploiement typées, et c'est généralement là que vous en avez besoin : le déploiement d'un secret Kubernetes est exactement le genre de déploiement qui a sa place dans une fenêtre de maintenance.

### Quelles sont les règles

- **`end` est exclue.** `02:00`–`04:00` et `04:00`–`06:00` sont adjacentes, sans chevauchement.
- **Une fenêtre peut franchir minuit**, et appartient au jour où elle **commence**. Une fenêtre `22:00`–`04:00` sur `["fri"]` est ouverte à 02:00 le samedi matin. La lire dans l'autre sens vous obligerait, sans le dire, à cocher aussi le samedi.
- **`start` et `end` ne peuvent pas être égales.** Cela se lit aussi bien "toujours ouverte" que "jamais ouverte", donc c'est refusé plutôt que deviné. Utilisez `00:00`–`23:59` pour une journée entière.
- **Le fuseau horaire est un nom IANA** (`Europe/Rome`, `America/New_York`), validé à l'enregistrement. Une faute de frappe est refusée à ce moment-là, plutôt que de retenir silencieusement chaque déploiement pour une fenêtre qui ne s'ouvre jamais.
- **L'heure d'été est gérée par le fuseau, pas par de l'arithmétique.** Le jour du passage à l'heure d'été, une fenêtre `02:00`–`04:00` à Rome s'ouvre à 03:00 heure locale, car 02:00–02:59 n'existe pas ; le jour du passage à l'heure d'hiver, elle est ouverte pendant les deux passages de 02:00–02:59.

### Ce qui se passe pendant qu'un déploiement est retenu

La file d'attente se trouve dans `data/pending_deploys.json` et survit à un redémarrage — la fenêtre est généralement à plusieurs heures de distance.

- Un second renouvellement avant l'ouverture de la fenêtre ne met **pas** en file un second déploiement. Le hook lit le certificat sur le disque au moment où il s'exécute, donc une seule exécution différée publie toujours le plus récent.
- Si le hook est supprimé ou désactivé, ou si les hooks de déploiement sont entièrement désactivés, le déploiement en file est **abandonné** au prochain vidage de la file. Votre configuration actuelle dit de ne pas l'exécuter.
- Si vous supprimez la fenêtre, le déploiement est libéré au prochain vidage plutôt que d'attendre une fois de plus.
- **Deploy Now consomme le déploiement qui attendait.** Si le hook (ou la cible typée) que vous exécutez à la main réussit, son entrée en file pour ce domaine est supprimée : le certificat a été livré, et l'exécuter de nouveau à l'ouverture de la fenêtre serait un second déploiement non annoncé. Si l'exécution manuelle **échoue**, l'entrée reste, et le déploiement dans la fenêtre sert de nouvelle tentative. Un renouvellement survenu *pendant* que Deploy Now s'exécute conserve son entrée, car ce certificat est plus récent que celui qu'a lu l'exécution manuelle. Les deux n'exécutent jamais le même déploiement en même temps : si la fenêtre s'ouvre pendant que Deploy Now exécute un hook, l'exécution planifiée le saute et le passage suivant le trouve soit livré, soit encore dû ; et si l'exécution planifiée est déjà dans le hook quand vous appuyez sur le bouton, Deploy Now attend qu'elle se termine, puis s'exécute. Un déploiement en file dont vous ne voulez pas ne peut toujours être retiré qu'en désactivant ou en supprimant le hook (il est alors abandonné au prochain vidage).
- Un hook qui échoue à l'intérieur de sa fenêtre n'est **pas** remis en file. Il est enregistré dans l'historique comme tout autre échec ; le remettre en file le relancerait chaque minute tant que la fenêtre resterait ouverte.
- Un déploiement qui attend encore au bout de sept jours est journalisé comme avertissement. Ce n'est pas une limite — attendre est précisément la fonctionnalité — mais une semaine signifie que la fenêtre ne s'est pas ouverte du tout, ce qui veut généralement dire que les jours ou le fuseau horaire ne sont pas ceux que vous vouliez.

Les déploiements retenus pour une fenêtre sont invisibles partout ailleurs : le certificat a été renouvelé, l'historique ne montre rien, et rien n'a échoué. `GET /api/deploy/pending` les liste avec la fenêtre qu'ils attendent et le moment de sa prochaine ouverture.

```bash
curl -H "Authorization: Bearer $TOKEN" https://certmate.local/api/deploy/pending
```

```json
[
  {
    "kind": "hook", "id": "6f0…", "domain": "api.example.com",
    "event": "renewed", "queued_at": "2026-09-08T13:12:04+00:00",
    "window": "02:00-04:00 Europe/Rome (sat, sun)",
    "next_run": "2026-09-12T00:00:00+00:00", "orphaned": false
  }
]
```

### Ce qui ignore la fenêtre

**Deploy Now** l'ignore. Appuyer sur ce bouton, c'est choisir ce moment-là ; retenir le déploiement jusqu'à 02:00 ferait que le bouton n'aurait aucun effet visible. Ce qu'il livre n'est pas livré une seconde fois : voir *Ce qui se passe pendant qu'un déploiement est retenu*. Il en va de même pour `POST /api/deploy/test/<id>`, qui ignore lui aussi la fenêtre et ne touche jamais à la file.

---

## Déclenchement manuel

Deux façons de déclencher un hook en dehors du cycle de vie normal du certificat :

### Test par hook (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/deploy/test/<hook_id>
```

Exécute uniquement le hook avec cet `id`, contre le domaine synthétique `test.example.com` (ou le `domain` indiqué dans un corps JSON), avec `CERTMATE_EVENT=test` et `CERTMATE_DRY_RUN=1`. La commande s'exécute réellement. Contourne le filtre `on_events`, l'indicateur `enabled` du hook lui-même et l'interrupteur principal — utile pour "est-ce que cette commande fonctionne vraiment ?".

### Exécuter tous les hooks pour un domaine (admin)

```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  https://certmate.local/api/certificates/api.example.com/deploy
```

Déclenche tous les hooks globaux + spécifiques au domaine qui sont activés (et toutes les cibles de déploiement typées correspondantes) pour `api.example.com` avec `CERTMATE_EVENT=manual`, en ignorant `on_events`. Refusé tant que l'interrupteur principal est désactivé. Retourne un résumé structuré :

```jsonc
{
  "ok": true,
  "total": 3,
  "succeeded": 2,
  "failed": 1,
  "results": [
    {"hook_name": "Reload nginx", "exit_code": 0, "duration_ms": 142, ...},
    ...
  ]
}
```

C'est ce qu'appelle le bouton **Run deploy hooks now** (icône de lecture, section Deployment du panneau de détail du certificat).

---

## Modèle de sécurité

Les hooks sont une exécution de code arbitraire par conception — c'est la fonctionnalité. Pour limiter le rayon d'impact, le champ de commande est validé **à l'enregistrement et de nouveau à l'exécution** (défense en profondeur) et rejeté s'il contient :

### Motifs shell bloqués

| Motif | Raison |
|---|---|
| `` ` `` (backticks) | substitution de commande |
| `$(...)` | substitution de commande |
| `${...}` | développement de paramètre. `$VAR` est accepté, tout comme `${CERTMATE_NAME}` avec l'accolade fermante juste après le nom ; toute autre forme `${...}`, y compris `${CERTMATE_DOMAIN:-x}`, est bloquée |
| `&&` / `\|\|` | chaînage logique |
| `;` | séparateur d'instructions |
| `\r` / `\n` | sauts de ligne (pour que `sh -c` ne puisse pas les interpréter comme `;`) |
| `> /` (redirection vers un chemin absolu) | empêche l'écrasement de fichiers système |
| `<<` | here-doc |
| `eval`, `source`, `.` (le raccourci de source, avec n'importe quel argument) | builtins shell qui chargent du code arbitraire |

Deux choses qui semblent avoir leur place dans cette liste sont autorisées volontairement (#115) : un pipe simple, pour un post-traitement comme `curl ... | grep -q ok` (les deux côtés doivent être une commande présente dans l'image — `jq` n'en fait pas partie), et une redirection vers un chemin relatif (`> out.txt`). Seule une redirection vers un chemin absolu est bloquée.

Si vous avez besoin de l'un de ces éléments, mettez la logique dans un fichier script à l'intérieur du conteneur et appelez le script directement :

```sh
/opt/scripts/deploy.sh
```

### Références de fichiers bloquées

Une commande qui nomme l'un des fichiers sensibles propres à CertMate est rejetée (insensible à la casse) :

`settings.json`, `api_bearer_token`, `client_secret`, `vault_token`, `.env`

Les fichiers du certificat ne sont pas dans la liste : installer le certificat et sa clé (`privkey.pem`, `$CERTMATE_KEY_PATH`) est le travail normal d'un hook. `cat /app/data/settings.json` est rejeté à l'enregistrement.

Le contrôle reconnaît ces noms **tels qu'ils sont écrits**. Il intercepte un hook qui nomme l'un de ces fichiers par erreur. Il n'arrête pas une commande qui atteint le même fichier sans écrire son nom : un glob (`settings*`), un joker `?` ou un nom coupé par des guillemets (`settings"."json`) passent tous. C'est une protection contre les accidents, pas une frontière de sécurité. Seul un admin peut enregistrer ou exécuter un hook, et un admin qui peut enregistrer un hook peut déjà exécuter n'importe quelle commande en tant que CertMate. Il en va de même pour les motifs shell ci-dessus.

### Envoyer la clé privée depuis un hook

Un hook peut envoyer la clé vers une URL : `CERTMATE_KEY_PATH` n'est pas dans la liste des blocages et `curl` est dans l'image, donc `curl --data-binary @"$CERTMATE_KEY_PATH" …` s'enregistre. CertMate ne regarde pas ce qu'une telle commande fait de la clé. Les vérifications vous reviennent :

- utilisez `https://`, jamais `http://` : la clé traverserait le réseau en clair ;
- n'ajoutez pas `-k`/`--insecure`, qui désactive la vérification que le serveur est bien celui que vous visiez ;
- n'ajoutez pas `-L`/`--location`, qui répète la requête, clé comprise, à n'importe quelle adresse indiquée par la réponse ;
- ne laissez pas la commande écrire dans sa sortie ce que le serveur répond : la sortie des hooks est conservée dans l'historique, et le journal d'audit ne peut pas être modifié.

Pour Kubernetes, utilisez plutôt la [cible typée](#cibles-de-déploiement-typées), qui respecte pour vous les trois premières règles.

### Ce qui est autorisé

- **Commandes simples** : `curl -fsS https://lb.internal/api/reload`, `openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -dates`
- **POST curl (webhooks)** : `curl -X POST -H "Content-Type: application/json" https://hooks.slack.com/...`
- **Expansion de variables dans les arguments** : `curl -d "domain=$CERTMATE_DOMAIN" https://...`
- **Charges JSON avec `$VAR`** : `curl -H "Content-Type: application/json" -d "{\"domain\":\"$CERTMATE_DOMAIN\"}" ...`. Le corps doit être entre guillemets doubles : entre guillemets simples, le shell ne développe jamais `$CERTMATE_DOMAIN`, et le destinataire reçoit le texte littéral.
- **Invocation d'un script unique** : `/opt/scripts/deploy.sh "$CERTMATE_DOMAIN"`

Si une commande que vous pouviez enregistrer auparavant déclenche maintenant `Command blocked at runtime: contains dangerous shell metacharacters`, consultez les notes de version — le validateur a été renforcé dans v2.4.0 et légèrement assoupli dans v2.4.1+.

---

## Où s'exécute un hook

**Dans le conteneur CertMate**, en tant que processus qui a émis le certificat — pas sur l'hôte Docker, ni sur la machine que vous voulez recharger.

C'est le seul point à bien comprendre avant d'écrire un hook, et les exemples de cette page se trompaient auparavant à ce sujet. Une commande comme `systemctl reload haproxy` se lit comme si elle rechargeait votre équilibreur de charge. Ce n'est pas le cas : elle s'exécute dans un conteneur qui n'a ni systemd, ni haproxy, ni nginx, et sort avec le code 127 — `not found` — ce qu'a signalé [#856](https://github.com/fabriziosalmi/certmate/issues/856) pour `scp`.

Ce que l'image publiée contient réellement, à l'usage d'un hook :

| | |
|---|---|
| **présents** | `sh`, `bash`, `curl`, `openssl` |
| **absents** | `ssh`, `scp`, `sftp`, `rsync`, `jq`, `nginx`, `systemctl`, `haproxy`, et tout le reste |

Cette liste est courte à dessein. L'étape d'exécution installe trois paquets, et le Dockerfile explique pourquoi : chaque paquet ajouté est une surface qu'il faut corriger et analyser ([#403](https://github.com/fabriziosalmi/certmate/issues/403)). Ce n'est pas un oubli, donc un hook doit faire avec ce qui est là — ou atteindre quelque chose qui en a davantage.

`tests/test_a_hook_runs_where_certmate_runs.py` vérifie les exemples ci-dessous contre l'image, afin que ce tableau ne puisse plus s'en écarter.

### Trois façons d'agir sur une machine qui n'est pas celle-ci

**Le lui demander par le réseau.** La plupart des choses qui méritent d'être rechargées ont une API, et `curl` est présent. C'est le schéma qui fonctionne sans aucune modification.

**Construire votre propre image.** L'image de CertMate est une base comme une autre :

```
FROM fabriziosalmi/certmate:latest
USER root
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*
USER certmate
```

Désormais `scp` est présent, avec tout ce que vous avez ajouté d'autre, et c'est à vous de corriger cette surface plutôt qu'à tout le monde.

**Monter un script et ses dépendances.** Un hook peut appeler n'importe quel chemin du conteneur, donc un script monté en bind mount fonctionne — mais il s'exécute toujours dans le conteneur, et tout ce qu'il invoque doit donc s'y trouver aussi.

---

## Recettes courantes

Elles s'exécutent dans l'image telle qu'elle est publiée. Chacune est vérifiée contre elle.

### Envoyer vers un webhook Slack

```sh
curl -X POST -H 'Content-Type: application/json' -d "{\"text\":\"Cert renewed: $CERTMATE_DOMAIN\"}" https://hooks.slack.com/services/XXX/YYY/ZZZ
```

### Signaler à autre chose que le certificat a changé

Tout ce qui a une API HTTP — un équilibreur de charge, un endpoint de gestion de configuration, votre propre petit agent placé à côté du service :

```sh
curl -fsS -X POST -H "Authorization: Bearer $DEPLOY_TOKEN" --data-binary "@$CERTMATE_FULLCHAIN_PATH" https://lb.internal/api/certs/$CERTMATE_DOMAIN
```

`-f` compte : sans lui, `curl` sort avec 0 sur une erreur HTTP, et le hook signale un succès pour un déploiement qui n'a pas eu lieu.

### Vérifier ce qui a été émis avant de le livrer

```sh
openssl x509 -in "$CERTMATE_FULLCHAIN_PATH" -noout -subject -dates
```

### Exécuter votre propre script

```sh
/opt/scripts/deploy.sh
```

Monté dans le conteneur, et écrit pour ce que le conteneur contient. Utilisez un script dès que vous avez besoin de `;` ou de `&&` — le champ de commande rejette les deux, et c'est de toute façon dans le script que cette logique a sa place.

### Agir seulement sur certains certificats

Ajoutez un tag à un certificat (`PATCH /api/certificates/<domain>` avec `tags`, ou **Edit** dans son panneau de détail) et un seul hook global peut décider, certificat par certificat, s'il doit agir. `CERTMATE_TAGS` est toujours définie, séparée par des virgules et en minuscules, et un tag ne contient que des lettres, des chiffres et `. _ - : /`, donc on peut l'utiliser sans guillemets en toute sécurité. Dans votre script :

```sh
echo ",$CERTMATE_TAGS," | grep -q ',loadbalancer,' || exit 0
```

Ce sont les virgules qui l'entourent qui rendent la correspondance exacte : sans elles, `loadbalancer` correspondrait aussi à un tag nommé `loadbalancer-old`.

### Ignorer le vrai travail pendant une exécution de Test

Dans votre script (la variable n'est définie que par le **Test** par hook) :

```sh
[ -n "${CERTMATE_DRY_RUN:-}" ] && { echo "dry run, skipping"; exit 0; }
```

---

## Audit, historique et débogage

### Flux d'activité

`GET /api/deploy/history?limit=50` et l'onglet **Activity** de l'UI montrent les N dernières exécutions de hooks avec : nom du hook, domaine, événement, code de sortie, durée, stdout/stderr (tronqués à 4096 octets chacun) et horodatage.

### Console de débogage

Settings → Deploy Hooks dispose d'une console de débogage (bouton de bascule en bas à droite) qui diffuse côté client les événements `loadConfig` / `saveConfig` / `testHook`. Utile pour mettre au point l'UI.

### Journal d'audit

Chaque exécution de hook écrit une entrée `operation: deploy_hook` dans le journal d'audit avec le statut `success`/`failure`, ainsi que le nom du hook, le code de sortie et la durée. Visible via l'onglet Activity et `/api/audit`.

### Échecs courants

| Symptôme | Cause probable |
|---|---|
| `Hook <id> is no longer in settings...` | L'ID du hook dans la requête de test ne correspond à aucun hook de la configuration enregistrée : la page est obsolète, le hook vient d'être supprimé, ou sa commande a été rejetée à l'enregistrement. Rafraîchissez la page. |
| `Command blocked at runtime` | Un des [motifs bloqués](#motifs-shell-bloqués) a franchi l'enregistrement. Déplacez la logique en cause dans un fichier script. |
| `exit code 127` | Commande introuvable dans le conteneur (p. ex. `nginx` n'est pas dans le `$PATH`). Utilisez des chemins absolus ou installez le binaire dans l'image. |
| `timeout after 30s` | Le hook a duré plus longtemps que son `timeout`. Augmentez-le (300s max) ou déplacez le travail vers un script en arrière-plan. |
| `Deploy hooks are disabled. Enable them in Settings → Deploy.` | `deploy_hooks.enabled` vaut `false` et vous avez exécuté tous les hooks d'un domaine. Activez l'interrupteur principal dans Settings. |
| `No enabled hooks or deploy targets configured for <domain>...` | Tentative d'exécution des hooks d'un domaine qui n'a aucun hook global activé, aucune entrée activée sous `domain_hooks[<domain>]` et aucune cible typée. Ajoutez un hook (ou appelez `/api/deploy/test/<id>` pour un hook précis). |

---

## Cibles de déploiement typées

Une **cible de déploiement typée** est une alternative déclarative à un hook shell pour une destination courante, afin que vous n'ayez pas à bricoler vous-même `kubectl` + identifiants. Les cibles se trouvent sous `deploy_hooks.targets` et se déclenchent aux mêmes points du cycle de vie que les hooks (émission + chaque renouvellement, et déploiement manuel), avec la même isolation des échecs — une cible qui échoue journalise, audite et lève l'alerte `deploy_hook_failed`, mais ne bloque jamais l'opération sur le certificat.

La première cible typée est **Kubernetes Secret** : elle écrit les `fullchain.pem` / `privkey.pem` renouvelés dans un Secret `kubernetes.io/tls` via Server-Side Apply (une seule création-ou-mise-à-jour idempotente).

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "prod-web-tls",
        "name": "Publish to prod web Secret",
        "type": "kubernetes-secret",
        "enabled": true,
        "on_events": ["created", "renewed"],
        "domains": ["example.com"],          // vide/omis = tous les domaines gérés
        "config": {
          "secret_name": "example-tls",
          "namespace": "web",
          // Option A — parler directement au serveur d'API :
          "api_server": "https://10.0.0.1:6443",
          "token": "<service-account bearer token>",
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",  // facultatif ; sinon les CA du système
          "verify_ssl": true
          // Option B — exécution dans le cluster : définissez plutôt "in_cluster": true,
          // et le serveur d'API, le token, la CA et le namespace par défaut sont lus
          // depuis le compte de service monté.
        }
      }
    ]
  }
}
```

Configurez-la via `POST /api/deploy/config` (le même endpoint réservé aux admins que pour les hooks shell). Le token de compte de service utilisé doit être limité à `patch`/`create` sur les Secrets du namespace cible.

> **Sécurité :** la configuration de déploiement est réservée aux admins, et — comme un secret intégré dans un hook shell — le `token` Kubernetes est stocké dans les paramètres et renvoyé aux admins par `GET /api/deploy/config`. Donnez au token la portée la plus réduite possible.

Une cible envoie la clé privée à l'adresse avec laquelle elle est configurée, donc deux règles sont respectées :

- **Les redirections ne sont pas suivies.** Une redirection répéterait la requête, clé comprise, à n'importe quelle adresse indiquée par la réponse. Un `3xx` du serveur d'API est signalé comme un échec qui le dit (sans l'adresse qu'il indiquait) ; faites pointer `api_server` vers l'adresse qui répond directement.
- **Ce qui revient n'est jamais copié dans les enregistrements.** La réponse à une requête échouée est montrée à l'opérateur, et aboutit aussi dans le journal d'audit, l'historique des déploiements et l'alerte d'échec. Le journal d'audit est une chaîne de hachage et ne peut pas être modifié après coup, donc la réponse est débarrassée du bearer token et de la clé (en PEM, échappée JSON, en base64, encodée URL, ou une seule ligne de celle-ci) avant d'être raccourcie et conservée.

`verify_ssl: false` est toujours accepté pour un cluster dont vous ne pouvez pas vérifier le certificat. Il désactive la vérification que le serveur est bien celui que vous avez configuré, donc ne l'utilisez que sur un réseau que vous contrôlez.

### Cible webhook : livrer le certificat, et éventuellement la clé

Un **webhook de notification** (Settings → Notifications) *annonce* un renouvellement, et ce qu'il rapporte atteint les alertes, les e-mails et les journaux. Il ne transporte jamais la clé privée ([webhooks.md](../webhooks.md)). La **cible webhook** *livre* : elle envoie le certificat et la chaîne, et, si le modèle le demande, la clé privée, à un endpoint HTTPS de votre choix, typiquement une appliance ou un service doté d'une API de téléversement. Ce sont des choses différentes avec des règles différentes, c'est pourquoi il s'agit d'une cible de déploiement et non d'une variable de plus du webhook de notification.

```jsonc
{
  "deploy_hooks": {
    "enabled": true,
    "targets": [
      {
        "id": "lb-cert",
        "name": "Upload to the load balancer",
        "type": "webhook",
        "enabled": true,
        "domains": ["shop.example.com"],      // obligatoire : jamais "tous les domaines" par défaut
        "on_events": ["created", "renewed"],
        "config": {
          "url": "https://lb.internal:8443/api/certificate",
          "method": "POST",                   // POST, PUT ou PATCH
          "payload_template": "{\"name\": \"{{domain}}\", \"cert\": \"{{fullchain}}\", \"key\": \"{{privkey_pkcs8}}\"}",
          "auth_type": "bearer", "auth_token": "<token>",   // none | bearer | basic | header
          "ca_cert": "-----BEGIN CERTIFICATE-----\n…",     // ou "pin_sha256": "<fingerprint>"
          "allow_internal": true,             // la destination est sur un réseau privé
          "acknowledge_key_delivery_to": "lb.internal"      // nécessaire car le modèle nomme la clé
        }
      }
    ]
  }
}
```

**Dans l'UI.** Settings → Deploy → **Deploy Targets** liste toutes les cibles et permet de modifier les cibles webhook : nom, domaines (obligatoires), événements, URL, méthode, authentification, secret de signature, manière de vérifier le serveur, un interrupteur de réseau privé, délai d'expiration et nombre de tentatives, et la charge utile avec les variables sous forme de boutons. Les variables de clé sont en rouge, et c'est l'ajout de l'une d'elles qui déclenche la confirmation décrite plus bas. **Preview what would be sent** appelle l'endpoint de prévisualisation décrit plus bas et affiche la destination avec son port, la manière dont le serveur est vérifié, les fichiers qu'une livraison lit, les en-têtes (identifiants masqués) et le corps rendu avec un certificat et une clé d'exemple. Une prévisualisation disparaît dès que le formulaire change, de sorte que ce qui est à l'écran est toujours ce qui serait enregistré.

Si la charge utile nomme une variable de clé privée, le formulaire affiche un encadré rouge avec l'hôte de destination et laisse **Save target** désactivé jusqu'à ce que vous ayez saisi cet hôte. Une cible déjà confirmée pour son hôte n'est pas redemandée quand vous la renommez ou changez ses domaines ; un hôte différent redemande la confirmation et indique pour quel hôte elle avait été donnée. L'enregistrement n'écrit que `targets`, à partir de la liste que le serveur détient à ce moment-là avec cette seule cible modifiée, de sorte qu'il ne peut pas écraser une modification faite entre-temps via l'API, et il laisse les autres types de cibles (secrets Kubernetes) exactement tels qu'ils sont. Ceux-ci y sont listés et se modifient via l'API. La page n'envoie jamais de consentement : c'est le serveur qui l'écrit.

**Variables du modèle.** La charge utile est du JSON que vous écrivez. Une variable placée à l'intérieur d'une chaîne est insérée échappée, donc un PEM (qui contient des sauts de ligne) ne peut pas casser le JSON.

| Variable | Ce que c'est |
|---|---|
| `{{cert}}`, `{{fullchain}}`, `{{chain}}` | le certificat, le certificat avec sa chaîne, la chaîne seule (PEM) |
| `{{privkey_pkcs8}}` | la clé privée en PKCS#8 (`BEGIN PRIVATE KEY`) |
| `{{privkey_traditional}}` | la clé privée en PKCS#1 pour RSA (`BEGIN RSA PRIVATE KEY`) ou en SEC1 pour EC (`BEGIN EC PRIVATE KEY`). Un type de clé sans une telle forme, comme Ed25519, est refusé avec un message, et non remplacé silencieusement |
| `{{event}}`, `{{domain}}`, `{{timestamp}}`, `{{certificate_sha256}}` | l'événement, le nom du certificat, l'heure, et le SHA-256 du certificat feuille |

Il n'existe pas de `privkey` tout court : les deux graphies rendent le choix visible, et une faute de frappe dans un nom est refusée à l'enregistrement au lieu de n'envoyer silencieusement rien. Un nom qui ne figure pas dans ce tableau est refusé.

**Envoyer la clé est une décision qui porte sur une destination.** Si le modèle nomme une variable de clé privée, l'enregistrement doit contenir `config.acknowledge_key_delivery_to` défini sur l'hôte de `url`. Le serveur enregistre alors qui l'a confirmé et quand (`delivery_consent`, renvoyé par `GET /api/deploy/config`) ; cette valeur n'est jamais lue depuis ce que vous envoyez. Si vous changez l'hôte par la suite, la confirmation ne s'applique plus : la cible refuse d'envoyer tant qu'elle n'a pas été redonnée, et un enregistrement sans elle est refusé. Chaque confirmation figure dans le journal d'audit.

**Comment le serveur est vérifié.** Toujours. Par défaut, avec le magasin du système. Avec `ca_cert`, avec cette CA seulement (elle remplace le magasin du système). Avec `pin_sha256`, avec l'empreinte SHA-256 exacte du certificat propre au serveur, pour une appliance qui se signe elle-même : donnez l'empreinte (deux-points autorisés), pas le certificat. Aucun réglage ne désactive la vérification, et l'URL doit être en `https://`.

**Où elle peut envoyer.** L'hôte est résolu une seule fois, chaque adresse est vérifiée, et la connexion va vers cette adresse. Une adresse de loopback, link-local ou de métadonnées cloud n'est jamais une destination. Une destination sur un réseau privé nécessite `allow_internal: true` **sur cette cible**, ce qui est délibéré et plus restreint qu'un interrupteur pour toute l'instance. Les redirections ne sont pas suivies : un `3xx` est un échec qui le dit.

**Ce qu'elle fait quand quelque chose tourne mal.** Une erreur réseau, ou un statut `408`, `425`, `429`, `500`, `502`, `503` ou `504`, est retentée avec un délai croissant jusqu'à `attempts` fois (3 par défaut, 5 au plus). Tout autre statut ne l'est pas : un `4xx` signifie que la requête est erronée, et renvoyer une clé pour se l'entendre redire n'aide personne. Chaque livraison porte une `Idempotency-Key` qui est la même pour les nouvelles tentatives d'une livraison et pour le même certificat renvoyé, et différente pour le certificat suivant, de sorte qu'un destinataire peut distinguer une répétition d'une nouvelle livraison. Avec `signing_secret`, le corps est signé dans `X-CertMate-Signature`, comme pour le webhook de notification.

**Ce qui est enregistré, et ce qui ne l'est pas.** Un résultat est un statut et une phrase qui nomme l'hôte : jamais l'adresse, la query string, les en-têtes, le corps que vous avez envoyé ni le corps de la réponse du destinataire, qui peut renvoyer en écho ce qu'on lui a envoyé. Une livraison qui a transporté la clé privée est signalée dans le journal d'audit : où elle est allée (`key_sent_to`), pour quel domaine, l'empreinte du certificat, le statut et les tentatives, et jamais la clé. Une réinitialisation de connexion après la négociation TLS est enregistrée comme peut-être envoyée, car on ne peut pas la distinguer d'une réinitialisation survenue avant celle-ci.

**Il n'existe pas de fonction "envoyer un test" pour une cible qui envoie la clé**, et c'est voulu. Un test qui livrerait une clé à une appliance acceptant les téléversements l'installerait à la place de la vraie. Utilisez plutôt la **prévisualisation** ([`POST /api/deploy/targets/preview`](./api.md)) : elle rend la requête avec un certificat et une clé d'exemple, ne lit aucun fichier et n'envoie rien. Pour livrer réellement une fois, utilisez [*Exécuter tous les hooks pour un domaine*](#exécuter-tous-les-hooks-pour-un-domaine-admin) (admin), qui est une action explicite.

**Ce contre quoi cela protège, et ce contre quoi cela ne protège pas.**

| Cela protège contre | Cela ne protège pas contre |
|---|---|
| L'envoi de la clé vers un hôte que vous n'avez pas confirmé, y compris après une modification de l'URL | Un destinataire compromis ou qui journalise ce qu'on lui envoie : il détient la clé dès qu'il l'a reçue. Certaines plateformes d'automatisation conservent chaque corps de requête dans un historique d'exécution ; ne faites pas pointer une cible qui transporte la clé vers l'une d'elles |
| Une redirection, une réponse DNS issue d'un rebinding ou une adresse de métadonnées qui emmène la requête ailleurs | Un administrateur : quiconque peut enregistrer cette configuration peut déjà écrire un [hook shell](#envoyer-la-clé-privée-depuis-un-hook) qui envoie la clé, sans aucune des vérifications ci-dessus |
| L'envoi en HTTP simple, ou vers un serveur que personne n'a vérifié | Le fait de tenir la clé à l'écart des sauvegardes et des journaux propres au destinataire |
| La réponse du destinataire qui emporterait la clé dans le journal d'audit | |
| | Les identifiants propres à la cible : `auth_token`, `auth_password` et `signing_secret` sont conservés dans `settings.json` (mode `0600`) et renvoyés à un administrateur par `GET /api/deploy/config`, exactement comme le token d'une cible Kubernetes. Le formulaire les affiche comme des champs de mot de passe. Donnez au destinataire un token qui ne peut faire que cette seule chose |

Pas dans cette version : un bundle sous forme de fichier téléversé ou en PKCS#12, et des en-têtes de requête personnalisés autres que celui d'authentification. Dites-nous ce dont un destinataire a besoin.

#### Le recevoir dans n8n

Vérifié avec n8n 2.41.4, un vrai certificat, un nœud Webhook et la charge utile ci-dessous ; les trois étapes décrivent ce qu'il a fallu faire, pas ce qui vaut en général pour n8n.

```json
{"domain": "{{domain}}", "event": "{{event}}",
 "certificates": {"cert": "{{cert}}", "key": "{{privkey_pkcs8}}", "rsa_key": "{{privkey_traditional}}",
                  "fullchain": "{{fullchain}}", "intermediate": "{{chain}}"}}
```

1. **n8n doit répondre en HTTPS.** Par défaut, n8n écoute en HTTP simple, et une cible le refuse (`url must be https://`). Placez un terminateur TLS devant lui, ou donnez à n8n lui-même un certificat avec `N8N_PROTOCOL=https`, `N8N_SSL_KEY=/path/key.pem` et `N8N_SSL_CERT=/path/cert.pem`. Pour un certificat que n8n a signé lui-même, définissez `pin_sha256` sur la cible avec son empreinte : les chiffres seulement, pas le libellé. La commande `openssl x509 -in cert.pem -noout -fingerprint -sha256` affiche `SHA256 Fingerprint=AA:BB:...` ; collez ce qui suit le `=`, car le champ refuse le libellé. Si n8n se trouve à une adresse privée, définissez aussi `allow_internal: true` sur la cible.
2. **Le nœud Webhook :** HTTP Method `POST`, un Path tel que `certmate`, Respond *Immediately*, puis publiez le workflow. La cible doit appeler l'URL de **production** (`https://host:5678/webhook/certmate`), pas celle de test.
3. **Ce que le nœud reçoit.** `$json.body` est la charge utile que vous avez écrite, donc l'exemple ci-dessus donne `{{ $json.body.certificates.fullchain }}` et ainsi de suite, sous forme de chaîne PEM ordinaire sur plusieurs lignes. Les en-têtes se trouvent dans `$json.headers` : `x-certmate-event`, `idempotency-key` (identique pour une nouvelle tentative d'une même livraison, de sorte qu'un workflow peut ignorer une répétition) et `user-agent: CertMate-Deploy/1`. Lors de la vérification, chaque certificat est arrivé identique au fichier, la clé PKCS#8 identique à `privkey.pem`, et la clé sous sa forme traditionnelle (`RSA PRIVATE KEY` ou `EC PRIVATE KEY`) était bien la clé du certificat, pour un certificat RSA comme pour un certificat EC.

**n8n conserve ce qu'il reçoit.** Avec ses réglages par défaut, n8n a stocké chaque corps de requête dans sa propre base de données, et lors de la vérification la clé privée pouvait être lue dans ces données d'exécution. Considérez que la base de données de n8n et ses sauvegardes détiennent la clé, ou laissez les variables de clé hors d'une cible n8n et récupérez la clé par un autre moyen. Configurer le workflow pour ne pas enregistrer les exécutions ne s'est **pas** comporté comme prévu lors de la même vérification (les exécutions sont restées à l'état `running` avec leurs données), donc ne vous fiez pas à ce réglage sans regarder ce que votre propre instance stocke. C'est le cas que le tableau ci-dessus désigne par "certaines plateformes d'automatisation conservent chaque corps de requête dans un historique d'exécution".

---

## Voir aussi

- [`modules/core/deployer.py`](../../modules/core/deployer.py) — implémentation
- [`modules/core/deploy_targets.py`](../../modules/core/deploy_targets.py) — cibles de déploiement typées
- [`modules/web/settings_routes.py`](../../modules/web/settings_routes.py) — endpoints `/api/deploy/*`
- [`templates/partials/settings_deploy.html`](../../templates/partials/settings_deploy.html) — partial UI
- [`static/js/settings-deploy.js`](../../static/js/settings-deploy.js) — composant Alpine
