# Conformité et piste d'audit

Cette page fait le lien entre la piste d'audit de CertMate et les régimes que les opérateurs interrogent le plus souvent — l'AI Act européen, NIS2 et l'ISO/IEC 42001 — lorsqu'ils laissent un agent IA/MCP gérer des certificats sur un calendrier.

> **À lire d'abord.** CertMate est un outil MIT auto-hébergé mono-instance. Ce n'est **pas** un système d'IA, **pas** un système d'IA à haut risque, et **pas** une entité réglementée, et il ne « se conforme pas » à quoi que ce soit ni ne « certifie » rien. Les obligations de conformité incombent à **l'opérateur** qui l'exécute. Ce que CertMate fournit, ce sont des **artefacts de preuve** qu'un opérateur peut utiliser pour *ses propres* obligations. Chaque affirmation ci-dessous signifie « permet à l'opérateur de prouver X », avec les limites explicitement énoncées.

---

## Ce que la piste d'audit fournit aujourd'hui

- **Attribution.** Chaque action du cycle de vie des certificats — création, renouvellement, réémission, déploiement, activation/désactivation du renouvellement automatique et renouvellements planifiés non supervisés — est enregistrée avec un `actor` structuré (humain vs jeton API vs agent IA, jusqu'à l'ID de la clé API) et un `trigger` (manuel, API, agent ou job du planificateur). Les actions d'un agent IA sont distinguables de celles d'un humain, à condition que l'agent utilise une clé marquée `is_agent`. Voir [API : Journalisation d'audit](./api.md#journalisation-daudit) et le [Guide MCP](./mcp.md#attribution-daudit).
- **Preuve d'intégrité.** Les entrées sont écrites dans une chaîne de hachage SHA-256 en append-only (`data/audit/certificate_audit.chain.jsonl`). Toute modification, suppression ou réordonnancement par quiconque ne peut pas recalculer toute la chaîne est détectable et localisable.
- **Vérification indépendante.** Un vérificateur autonome (`python -m modules.core.audit_verify`) recalcule la chaîne et retourne PASS/FAIL sans avoir à exécuter ou faire confiance à CertMate ; `GET /api/audit/verify` expose la même vérification via l'API.
- **Export signé vérifiable par un tiers.** L'instance signe le sommet de la chaîne (points de contrôle périodiques) et `GET /api/audit/export` produit un bundle signé Ed25519. Un auditeur le vérifie hors de la machine, en épinglant la clé publique de l'instance (`GET /api/audit/public-key`) hors bande — prouvant à la fois que l'enregistrement n'a pas été modifié et quelle instance l'a produit.

---

## Correspondance avec les régimes

### NIS2 (Directive (UE) 2022/2555) — la meilleure adéquation

- **Ce à quoi ça aide.** Les opérations sur les certificats modifient la posture de confiance des services, ce sont donc des événements liés à la sécurité. CertMate produit un enregistrement infalsifiable, attribué et horodaté de chaque opération, ainsi qu'une vérification indépendante — utilisable dans le cadre des pratiques de journalisation (Art. 21) et de preuve d'incident (Art. 23) de l'opérateur.
- **Limite.** NIS2 s'impose aux **entités** essentielles/importantes, pas aux outils logiciels. CertMate fournit des journaux et un vérificateur que l'opérateur peut utiliser ; il n'évalue, ne surveille ni ne signale les incidents, et le fait d'être une entité dans le champ d'application (et de respecter NIS2 dans son intégralité) relève de la responsabilité de l'opérateur.

### AI Act UE — Article 50 transparence (esprit seulement ; la moins bonne adéquation)

- **Ce à quoi ça aide.** Quand un agent IA gère la PKI de manière autonome, l'enregistrement porte un marqueur explicite `actor.kind="agent"` plus la session de l'agent, permettant à l'opérateur de démontrer a posteriori quels changements ont été effectués par un agent IA versus un humain, sous quelle identité et avec quel déclencheur — soutenant l'esprit de transparence et de supervision humaine de l'Acte.
- **Limite.** Les obligations de l'Art. 50 incombent aux **fournisseurs/déployeurs de systèmes d'IA** et concernent la divulgation aux personnes physiques interagissant avec l'IA. Un agent qui renouvelle des certificats TLS n'est pas un cas d'école de l'Art. 50, et CertMate est un outil, pas un système d'IA. Nous nous alignons sur l'esprit de transparence uniquement ; CertMate ne **satisfait pas** l'Art. 50 pour quiconque.

### ISO/IEC 42001 (Système de management de l'IA) — enregistrements opérationnels

- **Ce à quoi ça aide.** Les enregistrements attribués et infalsifiables sont des preuves objectives qu'un agent IA a effectué des actions spécifiques sur des certificats — utilisables pour les contrôles d'enregistrements opérationnels et de traçabilité du propre AIMS de l'opérateur.
- **Limite.** ISO 42001 certifie le système de management d'une organisation, pas un outil. CertMate n'est pas certifié ISO 42001 et ne peut pas certifier l'opérateur ; il produit des enregistrements que l'opérateur peut présenter comme preuve pour ses propres contrôles.

---

## Limites honnêtes (ne pas surinterpréter)

- **La clé de signature ne lie pas l'opérateur.** Un bundle d'export signé (et les points de contrôle signés périodiques) permettent à un tiers de vérifier, hors de la machine, quelle instance a produit l'enregistrement et qu'il n'a pas été modifié — pour quiconque ne détient **pas** la clé de signature. Mais l'opérateur détient la clé et pourrait resigner une chaîne réécrite. Contraindre complètement l'opérateur nécessite d'envoyer les points de contrôle signés vers un puits externe en append-only (**ancrage externe optionnel — une fonctionnalité prévue mais pas encore livrée**). Considérez la garantie actuelle comme « authenticité, ordonnancement et attribution à l'instance des entrées enregistrées », vérifiable indépendamment par un tiers qui détient une copie signée exportée.
- **Authenticité, pas exhaustivité.** Les écritures d'audit sont au mieux et ne bloquent jamais une opération de certificat ; la chaîne prouve que les entrées enregistrées sont authentiques et ordonnées, et un `seq` manquant au milieu prouve une suppression, mais une écriture qui a échoué avant d'être enregistrée ne laisse aucune entrée à vérifier.
- **La troncature de queue nécessite une référence externe.** La suppression d'entrées à la **fin** d'une chaîne unique laisse une chaîne plus courte mais interne cohérente qui reste vérifiable comme intacte. Les points de contrôle signés et les bundles d'export sont les ancres pour détecter cela : un export signé ultérieur avec moins d'entrées qu'un précédent (ou qu'un point de contrôle détenu par un auditeur) révèle la troncature. Un export unique ne peut pas, à lui seul, prouver que rien n'a été supprimé de la fin — conservez des exports signés successifs, ou attendez l'ancrage externe optionnel, si vous avez besoin de cette garantie.
- **L'en-tête de session d'agent est une information déclarative.** Il est enregistré pour corrélation mais est fourni par le client ; l'identité de confiance est la clé API authentifiée.
- **Limite historique.** La chaîne commence quand la fonctionnalité est activée pour la première fois ; l'historique `.log` antérieur ne fait pas partie de la chaîne vérifiable.

Les exports signés qu'un auditeur externe peut épingler à une clé publiée sont disponibles aujourd'hui. Si vos obligations exigent de lier l'opérateur *lui-même* — afin que même le détenteur de la clé ne puisse pas réécrire l'historique sans être détecté — cela nécessite l'ancrage externe optionnel des points de contrôle signés vers un puits append-only hors de la machine, qui est prévu mais pas encore livré. Suivez son évolution avant de vous y fier.

---

<div align="center">

[← Retour à la documentation](./README.md)

</div>
