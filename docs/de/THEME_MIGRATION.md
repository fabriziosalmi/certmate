# Theme-Migration — Entkopplung von Hell/Dunkel über CSS-Variable-Tokens

Status: **ausgeliefert** (Phasen 0–5 in v2.9.0; Phase 6 folgt) · Verantwortlicher: Fabrizio · Erstellt: 2026-05-25

## Ziel

Bisher bedeutet ein Themenwechsel, Farben in ~19 Templates und im Frontend-JS zu bearbeiten. Diese Migration macht einen einzigen Block von CSS Custom Properties zur einzigen Quelle der Wahrheit für die gesamte Palette — ein Retheming (oder das Hinzufügen eines neuen Themes) erfordert danach nur noch die Bearbeitung von `:root` / `.dark` in einer einzigen Datei, nicht an Hunderten von Verwendungsstellen.

## Ausgangszustand (gemessen am 2026-05-25)

| Metrik | Wert |
|---|---|
| Farbklassen-Referenzen in Templates | ~3.197 in 19 Dateien |
| `dark:`-Paare in Templates | ~1.665 |
| Farbklassen im Anwendungs-JS (nicht vendored) | ~789 (dashboard.js 372, settings.js 150, setup-wizard.js 131, certmate.js 60, client-certs.js 57, …) |
| Hartcodierte Hex-Werte im Anwendungs-JS | ~17 (Toast-/Diagramm-Paletten); 80 weitere in `redoc.standalone.js` sind **vendored, ignorieren** |
| Übernommene R-3-Komponentenklassen | nur `.card` (12×); `.btn-*`, `.badge-*`, `.form-*` = 0 |

Schwerste Dateien: `partials/settings_dns.html` (635 / 395 dark:), `index.html`
(311 / 150), `partials/settings_deploy.html`, `partials/settings_ca.html`.

## Prozessrisiken, die zuerst behoben werden müssen

1. **Das kompilierte CSS wird manuell eingecheckt.** `package.json` hat nur `css:build` /
   `css:watch`; kein CI baut `static/css/tailwind.min.css` neu. Eine Bearbeitung von
   `input.css` ohne anschließenden Build liefert stillschweigend veraltetes CSS aus. → CI-Build + Aktualitätsprüfung in Phase 0 hinzufügen.
2. **~3.200 manuelle Bearbeitungen = garantierte Regressionen.** Es wird eine visuelle Baseline
   (Hell+Dunkel-Screenshots jeder Seite) und ein halbautomatischer Codemod für die
   mechanischen `dark:`-Paare benötigt — kein blindes Suchen und Ersetzen.

## Strategie: CSS Custom Properties als einzige Quelle

shadcn-Stil auf Tailwind v3: Farben werden zu CSS-Variablen in `:root` / `.dark`,
die Tailwind als semantische Tokens zur Verfügung gestellt werden (HSL-Kanal-Triplets, damit
die `/opacity`-Utilities weiterhin funktionieren). Die ~1.665 `dark:`-Paare reduzieren sich auf einzelne Klassen.

### Vorgeschlagene Token-Zuordnungstabelle

| Tailwind-Token | Ersetzt (Beispiele) | Verwendung |
|---|---|---|
| `bg-background` | `bg-gray-50 dark:bg-surface-dark` | Seite |
| `bg-surface` | `bg-white dark:bg-surface-card` | Karte |
| `bg-surface-2` | `bg-gray-100 dark:bg-gray-800` | erhöht |
| `text-foreground` | `text-gray-900 dark:text-white` | Haupttext |
| `text-muted` | `text-gray-500 dark:text-gray-400` | Sekundärtext |
| `border-border` | `border-gray-200 dark:border-gray-700` | Rahmen |
| `bg-primary` / `text-primary` | Marke (jetzt variablenbasiert) | Marke |
| `*-success/warning/danger/info` | grün=gültig, rot=abgelaufen… | **Status, keine Oberflächen** |

## Phasen

Jede Phase = ein atomarer Commit (Partials in Phase 3 in eigene Commits aufteilen). Phasen werden in einem oder mehreren `vX.Y.Z`-Release-PRs zusammengefasst.

### Phase 0 — Grundlagen und Absicherungen (keine visuelle Änderung)
- [x] CI-Schritt führt `npm run css:build` aus und schlägt fehl, wenn `tailwind.min.css` veraltet ist (`git diff --exit-code`). → `frontend-css`-Job in `.github/workflows/ci.yml`. Das eingecheckte Bundle war bereits abgewichen; neu gebaut und eingecheckt.
- [x] Token-Schicht definieren: CSS-Variablen in `:root` / `.dark` (input.css) + Zuordnung in `tailwind.config.js`, **neben** der bestehenden Palette — noch keine Templates geändert. Tokens: `bg-background`, `bg-surface`, `bg-surface-2`, `text-foreground`, `text-muted`, `border-border` (safelisted).
- [x] Den Codemod schreiben: `scripts/theme_codemod.py` — Zuordnungstabelle häufig auftretender `dark:`-Paare → Tokens, Dry-run-Report + `--apply`. Mehrdeutigkeitsbericht unten.
- [x] Screenshot-Baseline-Tooling: `scripts/theme_baseline.py` — baut Docker mit einem frischen, kurzlebigen Datenverzeichnis, initialisiert einen Wegwerf-Admin, erfasst jede echte UI-Seite in Hell + Dunkel. Nach jeder Phase erneut ausführen und Diff erstellen. **Erfassungslauf noch ausstehend** (erfordert `playwright install chromium` + einen lokalen Docker-Build).

#### Baseline-Umfang (nur echte Seiten)
Erfasst: `/` (Setup, dann Index), `/login`, `/settings`, `/help`, `/activity`, `/redoc` — 7 Seiten × Hell/Dunkel.

> **Befund (außerhalb des Umfangs, markiert):** Die Routen `/certificates` und `/audit` in `modules/web/ui_routes.py:25-41` rendern `certificates.html` / `audit.html`, die **nicht existieren** — beide liefern 500. Tote Routen, von der Baseline ausgeschlossen. Eine separate Korrektur wäre sinnvoll (Routen entfernen oder Templates wiederherstellen).

#### Codemod-Verwendung
```
python scripts/theme_codemod.py                     # dry-run report, all templates
python scripts/theme_codemod.py templates/base.html # report, one file
python scripts/theme_codemod.py --apply templates/base.html
```
Nach jedem `--apply`: `npm run css:build`, Diff gegen Baseline, verbleibende `dark:`-Varianten prüfen.

#### Report-Snapshot (2026-05-25)
**607 Paare werden automatisch zusammengefasst** von ~1.665 `dark:`-Varianten:

| Token | Paare |
|---|---|
| `text-muted` | 203 |
| `border-border` | 169 |
| `text-foreground` | 141 |
| `bg-surface` | 77 |
| `bg-surface-2` | 16 |
| `bg-background` | 1 |

**557 Vorkommen / 29 Varianten sind nicht zugeordnet** — Designentscheidungen für den Phase-1-Piloten, nicht automatisch erraten:

- `dark:bg-gray-700` (137): wird mit `bg-white` (Karten/Inputs) **und** `bg-gray-50` kombiniert — je nach Kontext surface vs. surface-2 entscheiden.
- `dark:text-white` (120): die mit `text-gray-900` kombinierten werden bereits auf `text-foreground` abgebildet; der Rest ist immer weißer Text auf farbigem Hintergrund — wahrscheinlich so belassen.
- `dark:text-gray-300` (112): meist `text-gray-700 dark:text-gray-300` = das Formularlabel-Muster — einen dedizierten Label-Token vs. `text-muted`/`text-foreground` entscheiden.
- `dark:border-gray-600` (41), `dark:text-gray-200` (39), Oberflächen mit Opacity-Suffix (`dark:bg-gray-700/50` etc.) und `dark:border-white/5`.

Einige Überreste (`dark:text-gray-400{%`, `dark:text-gray-300'`) sind Klassenattribute mit Jinja/JS-Ausdrücken — manuell migrieren.

### Phase 1 — Pilot: Shell + Primitive
- [x] `base.html` (Nav/Header/Footer/Tab-Leiste) auf Tokens migrieren. 19 Paare zusammengefasst; Token-Werte stimmen exakt mit den Originalen überein.
- [x] `login.html` auf Tokens migrieren. 12 Paare zusammengefasst.
- [ ] `.btn` / `.form-*`-Komponentenklassen übernehmen (zurückgestellt — der Pilot verwendete nur Tokens; die Login-Inputs unterscheiden sich in der Größe von `.form-input`, daher ist die Komponentenübernahme ein eigener Schritt).
- [x] Hell/Dunkel-Parität validieren. Live in Docker verifiziert (base.html + login.html, beide Themes) — Pilot akzeptiert.

#### Offene Designentscheidungen (durch den Pilot aufgedeckt)
1. **Formularlabel-Text** (`text-gray-700 dark:text-gray-300`). **In Phase 5 gelöst → Option (b):** `--color-label`-Token mit den genauen gray-700/gray-300-Werten hinzugefügt (treu, keine visuelle Änderung) und alle 137 Vorkommen auf `text-label` migriert. Das Zusammenführen mit `text-foreground` wurde abgelehnt (würde den Hellmodus von 27 %→11 % L abdunkeln).
2. **Rahmenvereinheitlichung**: `border-gray-300` (Inputs) wird jetzt auf `border-border` (= gray-200) abgebildet, sodass Input-Rahmen im Hellmodus eine Stufe heller werden. Für den Piloten akzeptiert (ein einziger Rahmen-Token ist das Ziel); mit `--color-input-border` nochmals überdenken, falls die Review es ablehnt.
3. **Glass-Inputs / `dark:border-white/5`-Haarlinie / hover:-Varianten / Statusfarben**: absichtlich NICHT tokenisiert — Glass-Steuerelemente haben kein Hell-Gegenstück, die white/5-Haarlinie ist der kanonische `.card`-Rand, und Hover/Status benötigen ihren eigenen Varianten-Token-Durchlauf (eine spätere Phase).

### Phase 2 — Dashboard ✅
- [x] `index.html` (Dashboard-Chrome): Zertifikat-Erstellungsformular, Listen-/Statistikkarten, Tabellenköpfe + Trennlinien, Detailbereich, Modale. Alpine `:class`-Ternaries und `divide-border` manuell behandelt.
- [x] `static/js/dashboard.js`: JS-gerenderte Zeilen, Statistiken, Leer-/Willkommenszustände, Detailbereich, Alias-Prüfausgabe. `node --check` sauber.
- Gesundheits-/Deployment-Statusfarben (grün/amber/rot/blau) wurden absichtlich als buchstäbliche Statusfarben belassen — sie tragen Bedeutung und erhalten später einen dedizierten Status-Token-Durchlauf, keine Oberflächen-Tokens.
- Glass-Formular-Inputs (`dark:bg-gray-700`/`dark:text-white`), Formularlabels und hover:-Varianten für ihre eigene Behandlung zurückgestellt (konsistent mit dem Piloten).

### Phase 3 — Einstellungscluster ✅
- [x] `settings.html` + 10 Partials + `_modal`: 441 Paare zusammengefasst. Innere Alpine-`:class`-Ternary-Paare vom Codemod tokenisiert (Anführungszeichen verbinden nur die Branch-Edge-Klassen); Ternary-Struktur als intakt verifiziert.
- [x] `settings.js` + `setup-wizard.js`: 49 Paare, `node --check` sauber. Die anderen `settings-*.js` enthalten keine Farbklassen.
- Unverändert belassen (konsistent mit den vorangegangenen Phasen): Glass-Inputs (`dark:bg-gray-700` ~99), Formularlabels (`dark:text-gray-300` ~78, zurückgestellt), Status-Badges, Opacity-Oberflächen, hover:-Varianten und Ternary-Branch-Edge-Klassen.

### Phase 4 — Verbleibende Seiten ✅
- [x] Templates: activity, help, setup, `_client_certs` (123 Paare; keine Alpine-Ternaries hier).
- [x] JS: client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js (26 Paare, `node --check` sauber). setup-wizard.js wurde bereits in Phase 3 erledigt.
- Dieselben Ausnahmen wie zuvor: Glass-Inputs, Body-/Label-Grautöne, Opacity-Oberflächen, Statusfarben, hover: und Klassen an String-Verkettungsgrenzen.

### Phase 5 — Bereinigung und Festschreibung ✅
- [x] Label-Entscheidung abgeschlossen: `text-label`-Token + 137 Stellen migriert (siehe oben).
- [x] Blinden Fleck des Codemods entdeckt: Er scannte nur `class="..."` und übersah `className='...'`-Zuweisungen sowie JS-String-Verkettung. Ein **grenzenbewusster Literal-Durchlauf** hinzugefügt (fasst benachbarte `HELL DUNKEL`-Teilstrings in beliebigem Kontext zusammen) + das `--check`-Gate. Das erneute Ausführen des vollständigen Durchlaufs fasste die verbleibenden JS-Paare zusammen (confirm/prompt-Dialog, report-issue + shortcuts-Modale).
- [x] Ungenutzte Legacy-Aliasse `success`/`warning`/`danger` aus `tailwind.config.js` entfernt (0 Verwendungsstellen). `primary` (~375) und `secondary` (Verläufe) beibehalten.
- [x] **CI-Absicherung**: `python3 scripts/theme_codemod.py --check` im `frontend-css`-Job — schlägt den Build fehl, wenn ein zusammenfassbares Hell+Dunkel-Paar in einem Template oder einer First-Party-JS-Datei wieder eingeführt wird.
- **JS-Hex unverändert belassen, by design:** Die `#60a5fa`/etc.-Palette in `certmate.js` ist der **Debug-Konsolen-Logger** auf einer festen, immer dunklen Oberfläche (`bg-black`); `TOAST_COLORS` sind buchstäbliche Statusklassen. Beides sind themenunabhängige Statusakzente — konventionell kein Bestandteil von Hell/Dunkel-Theming — und bleiben daher buchstäblich statt zu Theme-Tokens zu werden. Ein künftiger **Status-Token-Durchlauf** (success/warning/danger/info als Variablen) ist der richtige Ort, um sie zu vereinheitlichen, falls je gewünscht.
- Baseline-Aktualisierung: optional; nicht ausgeführt (Erfassung wurde zurückgestellt — stattdessen wurde in jeder Phase eine Live-Docker-Verifizierung verwendet).

### Phase 6 — Status-Token-Durchlauf ✅
- [x] `success`/`warning`/`danger` (+ neues `info`) als **Token-Gruppen** neu hinzugefügt
  (`surface`/`line`/`fg`/`strong`), variablenbasiert in `:root`/`.dark` (HSL,
  treu zu den Inline-Werten, dunkle Oberflächen über die Karte geblendet).
- [x] Den Codemod um eine generierte Farbton×Abstufungstabelle (`_expand_status`) erweitert,
  die die grün/rot/amber/blau-Info-Box-Paare auf die Tokens faltet —
  und den 50-vs-100 / 700-vs-800-Drift der Inline-Callouts normalisiert.
  **300 Paare zusammengefasst** in Templates + First-Party-JS.
- [x] `--check` bewacht jetzt auch Status-Paare (sie leben in `MAPPINGS`), sodass ein
  wieder eingeführtes Hell+Dunkel-Status-Paar den CI wie jedes andere fehlschlagen lässt.
- Buchstäblich belassen by design: einzelne Statusakzente ohne Hell/Dunkel-Paar
  (Icon `text-*-500`) und eigenständige Nur-Dunkel-Töne (ohne Hell-Gegenstück).

### Phase 7 — Formularfeld-Oberfläche ✅ (v2.9.1)
- [x] `--color-input` (weiß / gray-700) → `bg-input` hinzugefügt; 40
  `bg-white dark:bg-gray-700`-Feldpaare zusammengefasst. Exakte Wertübereinstimmung.

### Phase 8 — Hover- und eingesenkte Oberflächen ✅ (v2.9.1)
- [x] `--color-hover` (gray-100/700), `border.strong` (gray-300/500) und
  `--color-sunken` (gray-50/700) hinzugefügt; 51 Hover-/eingesenkte Paare zusammengefasst. Minderheit
  der Hover-Abstufungen buchstäblich belassen, damit der Durchlauf strikt nullverändernd bleibt.

### Phase 9 — Komponentenschicht-Tokenisierung + Akzent ✅
- [x] Die `@apply`-Regeln der R-3-Komponenten (`.card`, `.form-input`/`.form-select`/
  `.form-label`, `.btn-secondary`, `.btn-ghost`, `.nav-active`, `.nav-inactive`)
  waren ein **blinder Fleck des Codemods** — `--check` scannt `class="…"`, nicht `@apply` —
  und enthielten noch rohe gray/blue-Klassen. Auf die Tokens migriert.
- [x] Einen thema-bewussten `accent`-Token hinzugefügt (blue-600 → blue-400 im Dunkelmodus), sodass
  `.nav-active` die Blaufarbe nicht mehr fest kodiert; das ist der On-Surface-Akzent, den #254
  vermisste.
- Nicht erledigt (by design): Übernahme von `.btn`/`.form-*` an den Verwendungsstellen (die Inline-
  Verwendungsstellen sind bereits tokenisiert; das Erzwingen der Komponenten würde die Button-Größe
  ohne Entkopplungsgewinn ändern). `.btn-danger` (solide Aktionsrot) und die
  `.badge-*`-Statusvarianten bleiben buchstäblich. Die `@apply`-Schicht bleibt außerhalb
  des `--check`-Gates — eine künftige Codemod-Erweiterung könnte sie scannen.

### Phase 10 — Farb-Tail-Zerlegung (geplant, schrittweise)
Die Entkopplung hinterließ **565 `dark:`-Utilities**, die der Codemod nicht zusammenfassen kann: Sie
haben kein helles Geschwisterelement zum Paaren, sodass `--check` sie nie sieht. Die Prüfung
(2026-05-25) zeigt, dass es sich nicht um ein Problem, sondern um drei handelt, mit gegensätzlichen Risikoprofilen:

| Gruppe | Anzahl | Wird aufgelöst zu | Neue Tokens |
|---|---|---|---|
| 1 — Neutraltöne (weiß/grau) | 388 (69%) | `foreground / surface / surface-2 / sunken / muted / border` | 0 |
| 2 — Status (blau/rot/amber) | 63 (11%) | `info / success / warning / danger` | 0 |
| 3 — Regenbogen (lila/indigo/orange) | 111 (20%) | **neutral** (dekorativ, herabgestuft) | 0 |

Wichtigste Erkenntnis: **null neue Tokens nötig.** Das bereits ausgelieferte Token-System *ist*
der Vertrag; die 565 sind alles, was ihm entkommen ist. Die Korrektur ist Durchsetzung +
Herabstufung, kein neues Vokabular. (Die Regenbogenfarben wurden als dekorative
Abschnittscodierung gemessen — lila = "erweiterte Konfiguration", indigo = CA/Enterprise, orange =
Speicher — kein Status, und über Dateien hinweg inkonsistent.)

Reihenfolge, nach steigendem UX-Risiko:
- **10a — Neutraltöne (388).** Unsichtbar: `dark:text-white` → `text-foreground`,
  `dark:bg-gray-700` → `bg-input`/`bg-surface-2`/`bg-sunken` (nach Kontext disambiguiert —
  dasselbe Dunkelgrau, unterschiedliche *helle* Bedeutung, daher menschlich klassifiziert pro
  Cluster, kein blindes sed). `theme_codemod.py` um einen Solo-Dark→Token-Durchlauf erweitern. Risiko ~0, bereinigt ~70%.
- **10b — Status (63).** Die blau/rot/amber-Callouts den vorhandenen
  info/success/warning/danger-Gruppen zuordnen. Normalisiert den 50-vs-100-Drift. Geringes Risiko.
- **10c — Regenbogen (111).** Die Produktentscheidung (siehe Vertrag unten).
  Dekorative Abschnittsfarbtöne werden auf Neutral reduziert. Sichtbare Änderung, zuletzt erledigt,
  Block für Block mit Vorher/Nachher-Screenshot-QA. Entschieden: **Vertrag α**
  (Farbe = Bedeutung).

## Farbvertrag (der Standard, dem die 565 entkamen)
Entschieden am 2026-05-25. Vier Regeln; die bereits ausgelieferten Tokens sind die einzige Palette.

1. **Farbe wird verdient, nie dekorativ eingesetzt.** Ein Farbton erscheint nur, wenn er
   *Status* (info/success/warning/danger) oder *Marke* (Akzent: Links, aktive Nav, Primary, Fokus) trägt. Alles andere ist neutral
   (background/surface/surface-2/sunken/border/foreground/muted/label).
2. **Identität kommt aus der Struktur, nicht aus der Farbe.** Abschnitte werden durch
   Abstände, Überschriften, Icons, Trennlinien unterschieden — nicht durch einen Füllton.
3. **Eine einzige Betonungsprimitiv.** Konfigurations-/erweiterte Blöcke verwenden ein einzelnes neutrales
   eingesenktes Panel (`bg-sunken border-border rounded-md`); ein optionaler linker Markenrand markiert "aktiv/wichtig". Keine abschnittsspezifische Palette.
4. **Icons erhalten nur Marken- oder Statusfarbe.** Keine lila/indigo/orange-Icon-Töne.

Durchsetzung: Das `--check`-Gate erhält eine Regel, die den CI bei rohem
`purple|indigo|orange` (und jeder nicht-tokenisierten Farbe) unter `templates/` fehlschlagen lässt — ein Vertrag mit einem Compiler dahinter, sodass er nicht wieder verfallen kann.

## Statusfarben — jetzt tokenisiert (Phase 6)
Frühere Phasen haben Statusfarben (grün/amber/rot/blau mit ihren `dark:`-Varianten) bewusst als
separaten, optionalen Durchlauf zurückgestellt — sie tragen Bedeutung und sind konventionell thema-invariant. **Phase 6 hat diesen Durchlauf vorgenommen:** Die kombinierten Info-Box-Oberflächen/Rahmen/Texte verwenden jetzt `bg-success-surface`,
`text-danger-strong` usw. Einzelne Status-*Akzente* (Icon `text-*-500`, kein dunkles Paar) bleiben buchstäblich — diese sind themenunabhängig und kein Bestandteil von Hell/Dunkel-Theming.

## Workflow-Abstimmung
- Kein Emoji in Commits/PRs/Release-Notes.
- Atomare Commits (einer pro Phase, oder pro Partial in Phase 3); ein PR pro Release.
- Vor dem öffentlichen Push: Docker-Smoke-Test + echte Zertifikatsausstellung gegen Fabs Domain mit zufälligen Subdomains.

---

<div align="center">

[← Zurück zur Dokumentation](./README.md)

</div>
