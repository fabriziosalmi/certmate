# Conformité et piste d'audit

<!-- CERTMATE-TRANSLATED-FROM 0ddda303c6fe494a -->

Cette page fait le lien entre la piste d'audit de CertMate et les régimes sur lesquels les opérateurs
s'interrogent le plus souvent — l'AI Act européen, NIS2 et l'ISO/IEC 42001 — lorsqu'ils laissent un agent IA/MCP
gérer des certificats selon un calendrier.

> **À lire d'abord.** CertMate est un outil MIT auto-hébergé mono-instance. Ce
> n'est **pas** un système d'IA, **pas** un système d'IA à haut risque, et **pas** une
> entité réglementée, et il ne « se conforme » à rien ni ne « certifie » quoi que ce soit. Les obligations
> de conformité incombent à **l'opérateur** qui l'exécute. Ce que CertMate fournit, ce sont des
> **artefacts de preuve** qu'un opérateur peut utiliser pour *ses propres* obligations.
> Chaque affirmation ci-dessous signifie « permet à l'opérateur de prouver X », avec les limites
> explicitement énoncées.

## Ce que la piste d'audit fournit aujourd'hui

- **Attribution.** Chaque action du cycle de vie des certificats — création, renouvellement, réémission,
  déploiement, activation/désactivation du renouvellement automatique, et renouvellements planifiés non supervisés — est enregistrée
  avec un `actor` structuré (humain vs token API vs agent IA, jusqu'à l'ID de la
  clé API) et un `trigger` (manuel, API, agent ou job du planificateur). Les
  actions d'un agent IA sont distinguables de celles d'un humain, à condition que l'agent utilise une
  clé marquée `is_agent`. Voir [API : Journalisation d'audit](./api.md#journalisation-daudit) et
  le [guide MCP](./mcp.md#attribution-daudit).
- **Preuve d'intégrité.** Les entrées sont écrites dans une chaîne de hachage SHA-256 en append-only
  (`data/audit/certificate_audit.chain.jsonl`). Toute modification,
  suppression ou réordonnancement par quiconque ne peut pas recalculer la chaîne est détectable
  et localisable.
- **Vérification indépendante.** Un vérificateur autonome
  (`python -m modules.core.audit_verify`) recalcule la chaîne et retourne
  PASS/FAIL sans avoir besoin d'exécuter CertMate ni de lui faire confiance ; `GET /api/audit/verify`
  expose la même vérification via l'API et, lorsque la signature est activée, recoupe aussi
  la chaîne avec le dernier point de contrôle signé — de sorte qu'une troncature
  de la queue ou une réécriture au niveau de ce point de contrôle ou en deçà fait échouer la vérification (voir
  « troncature de la queue » dans Limites honnêtes).
- **Export signé, vérifiable par un tiers.** L'instance signe la tête de la chaîne
  (points de contrôle périodiques) et `GET /api/audit/export` produit un bundle
  signé Ed25519. Un auditeur le vérifie hors de la machine, en épinglant la clé publique de l'instance
  (`GET /api/audit/public-key`) hors bande — ce qui prouve à la fois que l'enregistrement a été
  écrit, et non modifié, et quelle instance l'a produit. Cet endpoint retourne
  du JSON, pas un fichier PEM : enregistrez son champ `public_key_pem` comme le `.pem` qu'attend
  l'option `--pubkey` du vérificateur. Il répond 404 lorsque l'instance n'a pas de
  clé de signature.
- **Puits d'audit SIEM (push).** Chaque entrée d'audit peut aussi être transmise en direct à un
  collecteur externe dans un format standard — **syslog** (RFC 5424) ou **CEF**
  sur UDP/TCP, ou **HTTP/JSON générique** — configuré sous `audit_sink` dans
  les paramètres. Les entrées passent par le nettoyeur d'identifiants/secrets avant de
  quitter le processus (un token dans un champ de détail est masqué), et le puits est
  isolé des défaillances avec un délai d'expiration court, comme la chaîne de hachage : un collecteur hors service
  ne bloque ni ne casse jamais une opération sur un certificat. La couverture du cycle de vie inclut
  création / renouvellement / déploiement / révocation, ainsi que le récapitulatif planifié : c'est une
  entrée d'audit, il atteint donc le puits comme n'importe quelle autre. Ce qu'il enregistre, c'est le
  résultat, le nombre de destinataires auxquels il était adressé et les compteurs qu'il a rapportés — **pas
  les destinataires eux-mêmes**, qui sont des données personnelles que cette chaîne ne peut plus retirer
  par la suite. Un récapitulatif ignoré parce que les notifications ou le SMTP sont désactivés
  n'écrit rien : les paramètres répondent à cette question, et une entrée hebdomadaire le signalant ferait
  grossir la chaîne indéfiniment pour ne rien dire.

## Correspondance avec les régimes

### NIS2 (Directive (UE) 2022/2555) — la meilleure adéquation

- **Ce à quoi cela aide.** Les opérations sur les certificats modifient la posture de confiance des
  services, ce sont donc des événements pertinents pour la sécurité. CertMate produit un
  enregistrement infalsifiable, attribué et horodaté de chacune de ces opérations, ainsi
  qu'une vérification indépendante — utilisable dans le cadre des pratiques de journalisation
  (Art. 21) et de preuve d'incident (Art. 23) de l'opérateur.
- **Limite.** NIS2 s'impose aux **entités** essentielles/importantes, pas aux outils logiciels.
  CertMate fournit des journaux et un vérificateur que l'opérateur peut utiliser ; il n'évalue,
  ne surveille ni ne signale les incidents, et le fait d'être une entité dans le champ d'application (et de respecter NIS2
  dans son intégralité) relève de la responsabilité de l'opérateur.

### AI Act UE — Article 50 transparence (esprit seulement ; la moins bonne adéquation)

- **Ce à quoi cela aide.** Quand un agent IA gère la PKI de manière autonome, l'enregistrement
  porte un marqueur explicite `actor.kind="agent"` ainsi que la session de l'agent, de sorte que
  l'opérateur peut démontrer a posteriori quels changements ont été effectués par un agent IA
  plutôt que par un humain, sous quelle identité et ce qui les a déclenchés — ce qui soutient
  l'esprit de transparence et de supervision humaine du règlement.
- **Limite.** Les obligations de l'Art. 50 incombent aux **fournisseurs/déployeurs de systèmes d'IA** et
  concernent l'information des personnes physiques qui interagissent avec une IA. Un agent qui renouvelle
  des certificats TLS n'est pas un cas d'école de l'Art. 50, et CertMate est un outil, pas un
  système d'IA. Nous nous alignons uniquement sur l'esprit de transparence ; CertMate ne satisfait **pas**
  l'Art. 50 pour le compte de quiconque.

### ISO/IEC 42001 (système de management de l'IA) — enregistrements opérationnels

- **Ce à quoi cela aide.** Les enregistrements attribués et infalsifiables sont des preuves
  objectives qu'un agent IA a effectué des actions spécifiques sur des certificats — utilisables pour les
  contrôles d'enregistrements opérationnels et de traçabilité du propre AIMS de l'opérateur.
- **Limite.** ISO 42001 certifie le système de management d'une organisation, pas un outil.
  CertMate n'est pas certifié ISO 42001 et ne peut pas certifier l'opérateur ; il
  produit des enregistrements que l'opérateur peut présenter comme preuves pour ses propres contrôles.

## Limites honnêtes (ne pas les surinterpréter)

- **La clé de signature ne lie pas l'opérateur.** Un bundle d'export signé (et
  les points de contrôle signés périodiques) permettent à un tiers de vérifier, hors de la machine, quelle
  instance a produit l'enregistrement et qu'il n'a pas été modifié — pour quiconque ne détient
  **pas** la clé de signature. Mais l'opérateur détient la clé et pourrait signer à nouveau
  une chaîne réécrite. Contraindre complètement l'opérateur nécessite d'envoyer les points de contrôle
  signés vers un puits externe en append-only (**ancrage externe optionnel — une
  évolution prévue, pas encore livrée**). Considérez la garantie actuelle comme
  « authenticité, ordonnancement et attribution à l'instance des entrées enregistrées »,
  vérifiable indépendamment par un tiers qui détient une copie exportée et signée.
- **Authenticité, pas exhaustivité.** Les écritures d'audit sont faites au mieux et ne
  bloquent jamais une opération sur un certificat ; la chaîne prouve que les entrées enregistrées sont
  authentiques et ordonnées, et un `seq` manquant au milieu prouve une suppression, mais une
  écriture qui a échoué avant d'être enregistrée ne laisse aucune entrée à vérifier.
- **La troncature de la queue est détectée jusqu'au dernier point de contrôle signé.** Supprimer
  des entrées à la **fin** de la chaîne laisse une chaîne plus courte mais
  cohérente en interne. `GET /api/audit/verify` recoupe désormais la chaîne avec
  le point de contrôle signé le plus récent qui se vérifie avec la clé de l'instance, de sorte que toute
  troncature, tout retour en arrière ou toute réécriture **au niveau de ce point de contrôle ou en deçà** fait échouer
  la vérification — les points de contrôle, auparavant seulement écrits, sont désormais relus. La
  queue est **scellée lors d'un arrêt propre** : tout ce qui a été écrit depuis le dernier
  point de contrôle est signé à la sortie, de sorte qu'un conteneur qui s'arrête normalement
  ne laisse rien sans attestation. Deux lacunes subsistent : (a) un **crash**, un `SIGKILL` ou une
  coupure de courant s'arrête avant cela, et les entrées écrites depuis le dernier point de contrôle peuvent
  alors encore être supprimées sans être détectées jusqu'à ce que le suivant les scelle — la lacune est réduite
  de « chaque arrêt » à « un arrêt non propre », pas comblée ; et (b) un opérateur qui
  détient la clé de signature peut signer à nouveau un point de contrôle récent sur une chaîne réécrite.
  Conservez des exports signés successifs, ou attendez l'ancrage externe optionnel, si vous
  avez besoin de combler ces lacunes.
- **L'en-tête de session d'agent est une déclaration.** Il est enregistré pour la corrélation mais il est
  fourni par le client ; l'identité digne de confiance est la clé API authentifiée.
- **Les actions d'amorçage sont attribuées à `setup_user`.** Tant que la configuration initiale n'est pas terminée,
  une instance traite chaque requête en tant qu'admin, il n'y a donc aucune identité réelle à
  enregistrer et la chaîne le dit clairement. Une entrée telle que `create` / `user` /
  `setup_user` signifie que cet utilisateur a été créé alors que quiconque pouvait atteindre
  l'instance était admin. Sur une version actuelle, seul le premier admin peut être
  créé de cette façon — un deuxième utilisateur ou une clé API est refusé — on attend donc exactement une
  telle entrée. Plus d'une entrée signifie que l'instance a été amorcée
  sous une version plus ancienne, et chaque utilisateur au-delà du premier mérite d'être confirmé
  ou supprimé. Les clés API créées pendant cette fenêtre portent un badge dans la page Clés API
  et attendent un opérateur ; les utilisateurs ne portent pas de badge, et c'est dans la chaîne que se trouve la
  réponse les concernant.
- **Limite historique.** La chaîne commence quand la fonctionnalité est activée pour la première fois ;
  l'historique `.log` antérieur ne fait pas partie de la chaîne vérifiable.
- **Une chaîne élaguée prouve moins, et le dit.** Si vous avez exécuté
  `audit_prune` (ci-dessous), la vérification couvre les entrées à partir de l'ancre.
  Le préfixe archivé est attesté par l'ancre signée et par le bundle
  exporté que vous conservez hors de la machine — pas par le fichier de la chaîne. `verify` indique
  `anchored` et le seq de l'ancre précisément pour cette raison ; considérez une simple affirmation « intact »
  concernant une instance élaguée comme exagérée.

## Rétention : archiver une partie de la chaîne

La chaîne grandit d'une ligne par opération auditée — de l'ordre de quelques centaines de
kilo-octets par an sur une instance chargée — donc la plupart des opérateurs n'en ont jamais besoin. Cette fonction
existe pour le cas où une politique de rétention exige que les enregistrements anciens quittent la
machine.

Il n'y a pas d'élagage automatique, ni d'endpoint d'API pour cela. Supprimer
l'historique d'audit est exactement ce que voudrait faire quelqu'un qui vient de compromettre un compte
administrateur, et un opérateur soumis à une obligation de rétention légitime
dispose de toute façon d'un accès shell — il doit bien déposer l'archive quelque part. C'est donc une
commande explicite, exécutée avec CertMate arrêté :

```bash
# 1. Exportez le préfixe que vous comptez archiver (token admin).
curl -H "Authorization: Bearer $TOKEN" \
     "https://certmate.example.com/api/audit/export?to_seq=1199" > archive-0-1199.json

# 2. Vérifiez-le HORS de cette machine, en épinglant la clé de l'instance.
python -m modules.core.audit_verify --bundle archive-0-1199.json --pubkey instance.pem

# 3. Stockez-le là où votre politique l'indique. Puis, avec CertMate arrêté :
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit --yes
```

La commande sans `--yes` est une simulation. Elle refuse, et ne supprime rien, si
le bundle ne se vérifie pas, n'est pas signé, est vide, n'est pas un préfixe de *cette*
chaîne, ou diverge de la chaîne à un seq quelconque, ou si l'élagage laisserait la
chaîne sans aucune entrée après le préfixe archivé — vous ne supprimez jamais d'enregistrements
dont la seule copie restante n'est pas vérifiée, et vous ne vous retrouvez jamais avec une chaîne qui
n'a plus rien à vérifier.

Elle refuse aussi si `--key-dir` ne contient aucune clé de signature, ou en contient une appartenant à
une autre instance que celle qui a exporté le bundle. Les deux sont vérifiés
**avant** toute suppression : une ancre signée par la mauvaise clé est une ancre que le
propre `verify` de l'instance rejette, et le découvrir après la disparition des enregistrements
est trop tard pour être utile.

Faites pointer `--key-dir` vers la clé de l'instance. Sa valeur par défaut est `data` (relatif au
répertoire depuis lequel vous lancez la commande) et il doit contenir le fichier
`.audit_signing_key` de l'instance, sauf si `AUDIT_SIGNING_KEY_FILE` est défini de la même manière que
l'instance le définit. L'outil ne crée jamais de clé ici : une nouvelle clé serait une nouvelle
identité d'instance, pas celle de cette instance.

Ce qu'elle fait ensuite est la partie qui compte pour la conformité :

- **La suppression est enregistrée dans la chaîne qui lui survit.** Une entrée `archive`
  est ajoutée, qui indique la plage de seq, le nombre d'entrées, leur hachage de tête et
  le SHA-256 du fichier d'archive. Un lecteur de la chaîne élaguée peut voir que
  des entrées ont été supprimées, quand, et quelle archive les contient.
- **Le reste se vérifie à partir d'une ancre signée.** `certificate_audit.anchor.json`
  indique où la chaîne commence désormais et ce dont elle est la suite, signé avec la
  clé de l'instance, de sorte qu'une chaîne simplement tronquée ne peut pas être présentée comme une
  chaîne élaguée — l'ancre ne peut pas être falsifiée sans la clé.
- **Elle reste honnête par la suite.** La vérification d'une chaîne élaguée n'indique jamais un
  simple « intact » : l'API comme le vérificateur autonome indiquent à partir de quel seq la
  garantie commence.

Deux limites méritent d'être mentionnées. L'ancre décrit l'archive **la plus récente** ; l'historique
complet est la séquence des bundles exportés, c'est pourquoi ils doivent être
conservés et pourquoi l'empreinte de chacun est enregistrée dans la chaîne. Et, comme partout ailleurs
sur cette page, la clé de l'instance ne lie pas l'opérateur : quelqu'un qui la détient peut
signer une ancre sur une chaîne qu'il a réécrite. N'élaguez que jusqu'où vos archives
remontent réellement.

Les exports signés qu'un auditeur externe épingle à une clé publiée sont disponibles
aujourd'hui. Si vos obligations exigent de lier l'opérateur *lui-même* — afin que
même le détenteur de la clé ne puisse pas réécrire l'historique sans être détecté — cela nécessite l'ancrage
externe optionnel des points de contrôle signés vers un puits append-only hors de la machine,
qui est prévu mais pas encore livré. Suivez son évolution avant de vous y fier.
