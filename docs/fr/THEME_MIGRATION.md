# Migration de thème — découplage clair/sombre via les tokens CSS

Statut : **livrée** (Phases 0-5 dans v2.9.0 ; Phase 6 suit) · Propriétaire : Fabrizio · Créé : 2026-05-25

## Objectif

Aujourd'hui, changer le thème signifie éditer les couleurs dans ~19 templates et le JS frontend. Cette migration fait d'un seul bloc de propriétés personnalisées CSS la source de vérité pour toute la palette, de sorte que changer de thème (ou en ajouter un nouveau) signifie éditer `:root` / `.dark` dans un seul fichier — pas des centaines de points d'appel.

## État des lieux (mesuré le 2026-05-25)

| Métrique | Valeur |
|---|---|
| Références de classes de couleur dans les templates | ~3 197 dans 19 fichiers |
| Paires `dark:` dans les templates | ~1 665 |
| Classes de couleur dans le JS applicatif (non vendorisé) | ~789 (dashboard.js 372, settings.js 150, setup-wizard.js 131, certmate.js 60, client-certs.js 57, …) |
| Hex codés en dur dans le JS applicatif | ~17 (palettes toast/graphique) ; 80 de plus dans `redoc.standalone.js` sont **vendorisés, ignorer** |
| Classes de composants R-3 adoptées | `.card` seulement (12×) ; `.btn-*`, `.badge-*`, `.form-*` = 0 |

Fichiers les plus lourds : `partials/settings_dns.html` (635 / 395 dark:), `index.html` (311 / 150), `partials/settings_deploy.html`, `partials/settings_ca.html`.

## Risques de processus à corriger d'abord

1. **Le CSS compilé est commis à la main.** `package.json` n'a que `css:build` / `css:watch` ; aucun CI ne reconstruit `static/css/tailwind.min.css`. Modifier `input.css` sans reconstruire livre silencieusement un CSS obsolète. → ajouter une construction CI + vérification de fraîcheur dans la Phase 0.
2. **~3 200 éditions manuelles = régressions garanties.** Besoin d'une référence visuelle (captures d'écran clair+sombre de chaque page) et d'un codemod semi-automatique pour les paires `dark:` mécaniques, pas un find-replace aveugle.

## Stratégie : propriétés CSS personnalisées comme source unique

Style shadcn sur Tailwind v3 : les couleurs deviennent des variables CSS dans `:root` / `.dark`, exposées à Tailwind en tant que tokens sémantiques (triplets de canaux HSL pour que les utilitaires `/opacity` continuent de fonctionner). Les ~1 665 paires `dark:` se réduisent à des classes uniques.

### Table de correspondance des tokens proposée

| Token Tailwind | Remplace (exemples) | Utilisation |
|---|---|---|
| `bg-background` | `bg-gray-50 dark:bg-surface-dark` | page |
| `bg-surface` | `bg-white dark:bg-surface-card` | carte |
| `bg-surface-2` | `bg-gray-100 dark:bg-gray-800` | surélevé |
| `text-foreground` | `text-gray-900 dark:text-white` | texte principal |
| `text-muted` | `text-gray-500 dark:text-gray-400` | texte secondaire |
| `border-border` | `border-gray-200 dark:border-gray-700` | bordures |
| `bg-primary` / `text-primary` | marque (maintenant basé sur var) | marque |
| `*-success/warning/danger/info` | vert=valide, rouge=expiré… | **statut**, pas surfaces |

## Phases

Chaque phase = un commit atomique (scinder les partials dans la Phase 3 en leurs propres commits). Les phases se regroupent dans un ou plusieurs PRs de version `vX.Y.Z`.

### Phase 0 — Fondations et garde-fous (aucun changement visuel)
- [x] Étape CI qui lance `npm run css:build` et échoue si `tailwind.min.css` est obsolète (`git diff --exit-code`). → job `frontend-css` dans `.github/workflows/ci.yml`. Le bundle commis avait déjà dévié ; reconstruit et commis.
- [x] Définir la couche de tokens : variables CSS dans `:root` / `.dark` (input.css) + mapping dans `tailwind.config.js`, **en parallèle** de la palette existante — aucun template touché. Tokens : `bg-background`, `bg-surface`, `bg-surface-2`, `text-foreground`, `text-muted`, `border-border` (safelistés).
- [x] Écrire le codemod : `scripts/theme_codemod.py` — table de correspondance des paires `dark:` récurrentes → tokens, rapport dry-run + `--apply`. Rapport d'ambiguïté ci-dessous.
- [x] Outillage de capture d'écran : `scripts/theme_baseline.py` — construit Docker avec un répertoire de données éphémère, initialise un admin jetable, capture chaque page UI réelle en clair + sombre. À réexécuter après chaque phase et faire un diff. **Capture pas encore exécutée** (nécessite `playwright install chromium` + une construction Docker locale).

#### Périmètre de référence (pages réelles uniquement)
Capturées : `/` (setup, puis index), `/login`, `/settings`, `/help`, `/activity`, `/redoc` — 7 pages × clair/sombre.

> **Constat (hors périmètre, signalé) :** les routes `/certificates` et `/audit` dans `modules/web/ui_routes.py:25-41` rendent `certificates.html` / `audit.html`, qui **n'existent pas** — les deux retournent 500. Routes mortes, exclues de la référence. Mérite un correctif séparé (supprimer les routes ou restaurer les templates).

#### Utilisation du codemod
```
python scripts/theme_codemod.py                     # rapport dry-run, tous les templates
python scripts/theme_codemod.py templates/base.html # rapport, un fichier
python scripts/theme_codemod.py --apply templates/base.html
```
Après chaque `--apply` : `npm run css:build`, diff contre la référence, examiner les variantes `dark:` résiduelles.

#### Aperçu du rapport (2026-05-25)
**607 paires auto-réduites** sur ~1 665 variantes `dark:` :

| Token | Paires |
|---|---|
| `text-muted` | 203 |
| `border-border` | 169 |
| `text-foreground` | 141 |
| `bg-surface` | 77 |
| `bg-surface-2` | 16 |
| `bg-background` | 1 |

**557 occurrences / 29 variantes non mappées** — décisions de conception pour le pilote Phase 1, pas devinées automatiquement :

- `dark:bg-gray-700` (137) : s'associe avec `bg-white` (cartes/inputs) **et** `bg-gray-50` — décider surface vs surface-2 par contexte.
- `dark:text-white` (120) : celles associées à `text-gray-900` se mappent déjà à `text-foreground` ; les autres sont du texte toujours blanc sur fond coloré — à laisser telles quelles.
- `dark:text-gray-300` (112) : surtout `text-gray-700 dark:text-gray-300` = le motif des labels de formulaire — décider un token label dédié vs `text-muted`/`text-foreground`.
- `dark:border-gray-600` (41), `dark:text-gray-200` (39), surfaces suffixées par opacité (`dark:bg-gray-700/50` etc.), et `dark:border-white/5`.

Quelques reliquats (`dark:text-gray-400{%`, `dark:text-gray-300'`) sont des attributs de classe contenant des expressions Jinja/JS — à migrer à la main.

### Phase 1 — Pilote : shell + primitives
- [x] Migrer `base.html` (nav/header/footer/barre d'onglets) vers les tokens. 19 paires réduites ; les valeurs des tokens correspondent exactement aux originales.
- [x] Migrer `login.html` vers les tokens. 12 paires réduites.
- [ ] Adopter les classes de composants `.btn` / `.form-*` (reporté — le pilote a utilisé uniquement les tokens ; les inputs de connexion diffèrent en taille de `.form-input`, donc l'adoption des composants est une étape séparée).
- [x] Valider la parité clair/sombre. Vérifié en direct dans Docker (base.html + login.html, les deux thèmes) — pilote accepté.

#### Décisions de conception ouvertes (soulevées par le pilote)
1. **Texte des labels de formulaire** (`text-gray-700 dark:text-gray-300`). **RÉSOLU dans la Phase 5 → option (b) :** ajout du token `--color-label` aux valeurs exactes gray-700/gray-300 (fidèle, aucun changement visuel) et migration des 137 occurrences vers `text-label`. La fusion dans `text-foreground` a été rejetée (assombrirait le mode clair de 27%→11% L).
2. **Unification des bordures** : `border-gray-300` (inputs) se mappe maintenant à `border-border` (= gray-200), donc les bordures d'inputs s'éclaircissent d'un cran en mode clair. Accepté pour le pilote (un seul token de bordure est l'objectif) ; à revoir avec `--color-input-border` seulement si la revue ne l'apprécie pas.
3. **Inputs glass / `dark:border-white/5` trait fin / variantes hover / couleurs de statut** : intentionnellement NON tokenisées — les contrôles glass n'ont pas de contrepartie claire, le trait fin white/5 est le bord canonique de `.card`, et hover/statut nécessitent leur propre passe de tokens de variante (une phase ultérieure).

### Phase 2 — Tableau de bord ✅
- [x] `index.html` (chrome du tableau de bord) : formulaire de création, cartes liste/statistiques, en-têtes de tableau + séparateurs, panneau de détail, modales. Les ternaires Alpine `:class` et `divide-border` traités à la main.
- [x] `static/js/dashboard.js` : lignes rendues en JS, statistiques, états vides/bienvenue, panneau de détail, sortie de vérification d'alias. `node --check` propre.
- Les couleurs de statut santé/déploiement (vert/ambre/rouge/bleu) laissées intentionnellement comme couleurs de statut littérales — elles portent un sens et auront une passe de tokens de statut dédiée plus tard, pas des tokens de surface.
- Inputs de formulaire glass (`dark:bg-gray-700`/`dark:text-white`), labels de formulaire et variantes hover laissés pour leur propre traitement (cohérent avec le pilote).

### Phase 3 — Cluster de paramètres ✅
- [x] `settings.html` + 10 partials + `_modal` : 441 paires réduites. Les paires intérieures des ternaires Alpine `:class` tokenisées par le codemod (les guillemets ne collent que les classes de bord de branche) ; structure ternaire vérifiée intacte.
- [x] `settings.js` + `setup-wizard.js` : 49 paires, `node --check` propre. Les autres `settings-*.js` ne portent pas de classes de couleur.
- Laissé tel quel (cohérent avec les phases précédentes) : inputs glass (`dark:bg-gray-700` ~99), labels de formulaire (`dark:text-gray-300` ~78, reporté), badges de statut, surfaces d'opacité, variantes hover, et classes de bord de branche ternaires.

### Phase 4 — Pages restantes ✅
- [x] Templates : activity, help, setup, `_client_certs` (123 paires ; pas de ternaires Alpine ici).
- [x] JS : client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js (26 paires, `node --check` propre). setup-wizard.js déjà fait dans la Phase 3.
- Mêmes réserves que précédemment : inputs glass, gris de corps/label, surfaces d'opacité, couleurs de statut, hover, et classes aux limites de concaténation de chaînes.

### Phase 5 — Nettoyage et verrouillage ✅
- [x] Décision sur le label clôturée : token `text-label` + 137 sites migrés (voir ci-dessus).
- [x] Angle mort du codemod détecté : il ne scannait que `class=\"...\"`, manquant `className='...'` et la concaténation de chaînes JS. Ajout d'un **passage littéral conscient des limites** (réduit les sous-chaînes `CLAIR FONCÉ` adjacentes dans tout contexte) + la porte `--check`. La réexécution du balayage complet a réduit les paires JS restantes (dialogues confirm/prompt, modales report-issue + shortcuts).
- [x] Suppression des alias legacy inutilisés `success`/`warning`/`danger` de `tailwind.config.js` (0 sites d'appel). Conservé `primary` (~375) et `secondary` (dégradés).
- [x] **Garde-fou CI** : `python3 scripts/theme_codemod.py --check` dans le job `frontend-css` — échoue la construction si une paire clair+foncé réductible est réintroduite dans un template ou un fichier JS propriétaire.
- **Hex JS laissé tel quel, par conception :** la palette `#60a5fa`/etc. dans `certmate.js` est le **logger de console de débogage** sur une surface fixe toujours sombre (`bg-black`) ; `TOAST_COLORS` sont des classes de statut littérales. Les deux sont des accents de statut indépendants du thème — conventionnellement pas concernés par le thème clair/sombre — donc ils restent littéraux plutôt que de devenir des tokens de thème. Une future **passe de tokens de statut** (success/warning/danger/info en tant que vars) est l'endroit approprié pour les unifier si jamais souhaité.
- Rafraîchissement de la référence : optionnel ; pas exécuté (la capture a été différée — vérification Docker en direct utilisée à chaque phase à la place).

### Phase 6 — Passe des tokens de statut ✅
- [x] Rajout de `success`/`warning`/`danger` (+ nouveau `info`) en tant que **groupes de tokens** (`surface`/`line`/`fg`/`strong`), adossés à des variables dans `:root`/`.dark` (HSL, fidèle aux valeurs inline, surfaces sombres fondues sur la carte).
- [x] Extension du codemod avec une table teinte×nuance générée (`_expand_status`) qui replie les paires vert/rouge/ambre/bleu des info-box sur les tokens — normalisant la dérive 50-vs-100 / 700-vs-800 des callouts inline. **300 paires réduites** dans les templates + JS propriétaire.
- [x] `--check` vérifie maintenant aussi les paires de statut (elles vivent dans `MAPPINGS`), donc une paire clair+foncé de statut réintroduite échoue CI comme toute autre.
- Laissé littéral par conception : les accents de statut uniques sans paire clair/foncé (icône `text-*-500`), et les teintes foncé uniquement (sans contrepartie claire).

### Phase 7 — Surface des champs de formulaire ✅ (v2.9.1)
- [x] Ajout de `--color-input` (blanc / gray-700) → `bg-input` ; réduction de 40 paires `bg-white dark:bg-gray-700`. Correspondance exacte des valeurs.

### Phase 8 — Surfaces de survol et creuses ✅ (v2.9.1)
- [x] Ajout de `--color-hover` (gray-100/700), `border.strong` (gray-300/500) et `--color-sunken` (gray-50/700) ; réduction de 51 paires hover/creuses. Les teintes de survol minoritaires laissées littérales pour que la passe reste strictement sans changement.

### Phase 9 — Tokenisation de la couche composants + accent ✅
- [x] Les règles `@apply` des composants R-3 (`.card`, `.form-input`/`.form-select`/`.form-label`, `.btn-secondary`, `.btn-ghost`, `.nav-active`, `.nav-inactive`) étaient un **angle mort du codemod** — `--check` scanne `class=\"…\"`, pas `@apply` — et portaient encore des classes raw gray/blue. Migrées vers les tokens.
- [x] Ajout d'un token `accent` sensible au thème (blue-600 → blue-400 en sombre) pour que `.nav-active` ne code plus le bleu en dur ; c'est l'accent de surface qui manquait à #254.
- Non fait (par conception) : adoption des `.btn`/`.form-*` sur les sites d'appel (les sites d'appel inline sont déjà tokenisés ; forcer les composants changerait la taille des boutons pour zéro gain de découplage). `.btn-danger` (rouge d'action solide) et les variantes `.badge-*` de statut restent littéraux. La couche `@apply` reste en dehors de la porte `--check` — une future amélioration du codemod pourrait la scanner.

### Phase 10 — Décomposition des queues de couleur (planifiée, progressive)

Le découplage a laissé **565 utilitaires `dark:`** que le codemod ne peut pas réduire : ils n'ont pas de sibling clair avec lequel s'associer, donc `--check` ne les voit jamais. L'audit (2026-05-25) montre qu'il ne s'agit pas d'un problème mais de trois, avec des profils de risque opposés :

| Lot | Nombre | Se résout en | Nouveaux tokens |
|---|---|---|---|
| 1 — Neutres (blanc/gris) | 388 (69%) | `foreground / surface / surface-2 / sunken / muted / border` | 0 |
| 2 — Statut (bleu/rouge/ambre) | 63 (11%) | `info / success / warning / danger` | 0 |
| 3 — Arc-en-ciel (violet/indigo/orange) | 111 (20%) | **neutre** (décoratif, rétrogradé) | 0 |

Constat clé : **zéro nouveau token nécessaire.** Le système de tokens déjà livré *est* le contrat ; les 565 sont tout ce qui y a échappé. Le correctif est l'application + la rétrogradation, pas un nouveau vocabulaire.

Ordre, par risque UX croissant :
- **10a — Neutres (388).** Invisible : `dark:text-white` → `text-foreground`, `dark:bg-gray-700` → `bg-input`/`bg-surface-2`/`bg-sunken` (désambiguïsé par contexte — même gris foncé, intention *claire* différente, donc classifié humainement par cluster, pas sed aveugle). Étendre `theme_codemod.py` avec une passe solo-dark→token. Risque ~0, nettoie ~70%.
- **10b — Statut (63).** Mapper les callouts bleu/rouge/ambre sur les groupes info/success/warning/danger existants. Normalise la dérive 50-vs-100. Risque faible.
- **10c — Arc-en-ciel (111).** La décision produit (voir contrat ci-dessous). Les teintes décoratives de section se réduisent en neutre. Changement visible, fait en dernier, bloc par bloc avec QA de capture avant/après. Décidé : **contrat α** (couleur = sens).

## Contrat de couleur (la norme que les 565 ont fuie)

Décidé le 2026-05-25. Quatre règles ; les tokens déjà livrés sont la seule palette.

1. **La couleur se gagne, elle n'est jamais décorative.** Une teinte n'apparaît que si elle porte le *statut* (info/success/warning/danger) ou la *marque* (accent : liens, nav active, primaire, focus). Tout le reste est neutre (background/surface/surface-2/sunken/border/foreground/muted/label).
2. **L'identité vient de la structure, pas de la couleur.** Les sections sont distinguées par l'espacement, les titres, les icônes, les séparateurs — pas par une teinte de remplissage.
3. **Une seule primitive d'accentuation.** Les blocs de configuration/avancés utilisent un seul panneau neutre en retrait (`bg-sunken border-border rounded-md`) ; une bordure gauche de marque optionnelle marque "actif/important". Pas de palette par section.
4. **Les icônes se teintent uniquement avec la marque ou le statut.** Pas de teintes violet/indigo/orange pour les icônes.

Application : la porte `--check` gagne une règle qui échoue CI sur le `purple|indigo|orange` brut (et toute couleur non-tokenisée) dans `templates/` — un contrat avec un compilateur derrière, qui ne peut pas pourrir.

## Couleurs de statut — maintenant tokenisées (Phase 6)
Les phases précédentes ont délibérément différé les couleurs de statut (vert/ambre/rouge/bleu avec leurs variantes `dark:`) comme une passe séparée et optionnelle — elles portent un sens et sont conventionnellement invariantes de thème. **La Phase 6 a fait cette passe :** les surfaces/bordes/texte des info-box appairées utilisent maintenant `bg-success-surface`, `text-danger-strong`, etc. Les accents de statut *uniques* (icône `text-*-500`, sans paire sombre) restent littéraux — ceux-ci sont indépendants du thème et ne font pas partie du theming clair/sombre.

## Alignement du workflow
- Zéro emoji dans les commits/PRs/notes de version.
- Commits atomiques (un par phase, ou par partial dans la Phase 3) ; un PR par version.
- Avant push public : fumée Docker + émission de certificat réel contre le domaine de Fab avec des sous-domaines aléatoires.

---

<div align="center">

[← Retour à la documentation](./README.md)

</div>
