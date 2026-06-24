# Migrazione del tema — disaccoppiamento chiaro/scuro tramite token CSS

Stato: **rilasciata** (Fasi 0–5 nella v2.9.0; Fase 6 segue) · Responsabile: Fabrizio · Creato: 2026-05-25

## Obiettivo

Attualmente, cambiare il tema significa modificare i colori in ~19 template e nel
frontend JS. Questa migrazione fa di un singolo blocco di proprietà personalizzate CSS la
fonte di verità per l'intera palette, cosicché reimpostare il tema (o aggiungere un nuovo tema)
significa modificare `:root` / `.dark` in un unico file — non centinaia di punti di chiamata.

## Stato di partenza (rilevato il 2026-05-25)

| Metrica | Valore |
|---|---|
| Riferimenti a classi di colore nei template | ~3 197 in 19 file |
| Coppie `dark:` nei template | ~1 665 |
| Classi di colore nel JS applicativo (non vendorizzato) | ~789 (dashboard.js 372, settings.js 150, setup-wizard.js 131, certmate.js 60, client-certs.js 57, …) |
| Hex codificati nel JS applicativo | ~17 (palette toast/grafici); altri 80 in `redoc.standalone.js` sono **vendorizzati, ignorare** |
| Classi di componenti R-3 adottate | solo `.card` (12×); `.btn-*`, `.badge-*`, `.form-*` = 0 |

File più pesanti: `partials/settings_dns.html` (635 / 395 dark:), `index.html`
(311 / 150), `partials/settings_deploy.html`, `partials/settings_ca.html`.

## Rischi di processo da correggere prima

1. **Il CSS compilato viene committato a mano.** `package.json` ha solo `css:build` /
   `css:watch`; nessuna CI ricostruisce `static/css/tailwind.min.css`. Modificare
   `input.css` senza ricostruire consegna silenziosamente un CSS obsoleto. → aggiungere una build CI + verifica di aggiornamento nella Fase 0.
2. **~3 200 modifiche manuali = regressioni garantite.** Serve una baseline visiva
   (screenshot chiaro+scuro di ogni pagina) e un codemod semi-automatico per le
   coppie `dark:` meccaniche, non un find-replace alla cieca.

## Strategia: proprietà CSS personalizzate come fonte unica

Stile shadcn su Tailwind v3: i colori diventano variabili CSS in `:root` / `.dark`,
esposte a Tailwind come token semantici (triplette di canali HSL affinché le utility
`/opacity` continuino a funzionare). Le ~1 665 coppie `dark:` si riducono a classi singole.

### Tabella di corrispondenza dei token proposta

| Token Tailwind | Sostituisce (esempi) | Utilizzo |
|---|---|---|
| `bg-background` | `bg-gray-50 dark:bg-surface-dark` | pagina |
| `bg-surface` | `bg-white dark:bg-surface-card` | card |
| `bg-surface-2` | `bg-gray-100 dark:bg-gray-800` | elevato |
| `text-foreground` | `text-gray-900 dark:text-white` | testo principale |
| `text-muted` | `text-gray-500 dark:text-gray-400` | testo secondario |
| `border-border` | `border-gray-200 dark:border-gray-700` | bordi |
| `bg-primary` / `text-primary` | brand (ora basato su var) | brand |
| `*-success/warning/danger/info` | verde=valido, rosso=scaduto… | **stato, non superfici** |

## Fasi

Ogni fase = un commit atomico (suddividere i partial della Fase 3 nei propri
commit). Le fasi si raggruppano in uno o più PR di versione `vX.Y.Z`.

### Fase 0 — Fondamenta e guardrail (nessuna modifica visiva)
- [x] Step CI che esegue `npm run css:build` e fallisce se `tailwind.min.css` è obsoleto (`git diff --exit-code`). → job `frontend-css` in `.github/workflows/ci.yml`. Il bundle committato aveva già deviato; ricostruito e committato.
- [x] Definire il layer dei token: variabili CSS in `:root` / `.dark` (input.css) + mapping in `tailwind.config.js`, **in parallelo** alla palette esistente — nessun template modificato. Token: `bg-background`, `bg-surface`, `bg-surface-2`, `text-foreground`, `text-muted`, `border-border` (nella safelist).
- [x] Scrivere il codemod: `scripts/theme_codemod.py` — tabella di corrispondenza delle coppie `dark:` ricorrenti → token, report dry-run + `--apply`. Report sulle ambiguità di seguito.
- [x] Strumenti per gli screenshot: `scripts/theme_baseline.py` — costruisce Docker con una directory dati effimera, inizializza un admin usa-e-getta, cattura ogni pagina UI reale in chiaro + scuro. Da rieseguire dopo ogni fase e confrontare. **Esecuzione della cattura ancora in sospeso** (richiede `playwright install chromium` + una build Docker locale).

#### Ambito della baseline (solo pagine reali)
Catturate: `/` (setup, poi index), `/login`, `/settings`, `/help`, `/activity`, `/redoc` — 7 pagine × chiaro/scuro.

> **Rilievo (fuori ambito, segnalato):** le route `/certificates` e `/audit` in `modules/web/ui_routes.py:25-41` rendono `certificates.html` / `audit.html`, che **non esistono** — entrambe restituiscono 500. Route non funzionanti, escluse dalla baseline. Merita una correzione separata (rimuovere le route o ripristinare i template).

#### Utilizzo del codemod
```
python scripts/theme_codemod.py                     # report dry-run, tutti i template
python scripts/theme_codemod.py templates/base.html # report, un file
python scripts/theme_codemod.py --apply templates/base.html
```
Dopo ogni `--apply`: `npm run css:build`, diff rispetto alla baseline, esaminare le varianti `dark:` residue.

#### Panoramica del report (2026-05-25)
**607 coppie ridotte automaticamente** su ~1 665 varianti `dark:`:

| Token | Coppie |
|---|---|
| `text-muted` | 203 |
| `border-border` | 169 |
| `text-foreground` | 141 |
| `bg-surface` | 77 |
| `bg-surface-2` | 16 |
| `bg-background` | 1 |

**557 occorrenze / 29 varianti non mappate** — decisioni di design per il pilota della Fase 1, non indovinate automaticamente:

- `dark:bg-gray-700` (137): si accoppia con `bg-white` (card/input) **e** `bg-gray-50` — decidere surface vs surface-2 per contesto.
- `dark:text-white` (120): quelle accoppiate con `text-gray-900` si mappano già a `text-foreground`; le restanti sono testo sempre bianco su sfondo colorato — probabilmente da lasciare invariate.
- `dark:text-gray-300` (112): per lo più `text-gray-700 dark:text-gray-300` = il pattern delle label dei form — decidere se adottare un token label dedicato vs `text-muted`/`text-foreground`.
- `dark:border-gray-600` (41), `dark:text-gray-200` (39), superfici con suffisso opacità (`dark:bg-gray-700/50` ecc.), e `dark:border-white/5`.

Alcuni residui (`dark:text-gray-400{%`, `dark:text-gray-300'`) sono attributi di classe contenenti espressioni Jinja/JS — da migrare a mano.

### Fase 1 — Pilota: shell + primitive
- [x] Migrare `base.html` (nav/header/footer/barra delle schede) ai token. 19 coppie ridotte; i valori dei token corrispondono esattamente agli originali.
- [x] Migrare `login.html` ai token. 12 coppie ridotte.
- [ ] Adottare le classi di componenti `.btn` / `.form-*` (rimandato — il pilota ha usato solo i token; gli input di login differiscono nelle dimensioni da `.form-input`, quindi l'adozione dei componenti è uno step a parte).
- [x] Validare la parità chiaro/scuro. Verificato in tempo reale in Docker (base.html + login.html, entrambi i temi) — pilota accettato.

#### Decisioni di design aperte (emerse dal pilota)
1. **Testo delle label dei form** (`text-gray-700 dark:text-gray-300`). **RISOLTO nella Fase 5 → opzione (b):** aggiunto il token `--color-label` con i valori esatti gray-700/gray-300 (fedele, nessuna modifica visiva) e migrate le 137 occorrenze a `text-label`. La fusione in `text-foreground` è stata rifiutata (avrebbe scurito la modalità chiara dal 27% all'11% L).
2. **Unificazione dei bordi**: `border-gray-300` (input) si mappa ora a `border-border` (= gray-200), quindi i bordi degli input si schiariscono di un livello in modalità chiara. Accettato per il pilota (un singolo token di bordo è l'obiettivo); da riconsiderare con `--color-input-border` solo se la revisione lo ritiene problematico.
3. **Input glass / `dark:border-white/5` hairline / varianti hover / colori di stato**: intenzionalmente NON tokenizzati — i controlli glass non hanno una controparte chiara, la hairline white/5 è il bordo canonico di `.card`, e hover/stato necessitano di una propria passata di token variante (una fase successiva).

### Fase 2 — Dashboard ✅
- [x] `index.html` (chrome della dashboard): form di creazione certificato, card lista/statistiche, intestazioni di tabella + divisori, pannello di dettaglio, modali. I ternari Alpine `:class` e `divide-border` gestiti a mano.
- [x] `static/js/dashboard.js`: righe renderizzate da JS, statistiche, stati vuoti/benvenuto, pannello di dettaglio, output del controllo alias. `node --check` pulito.
- I colori di stato salute/deployment (verde/ambra/rosso/blu) lasciati intenzionalmente come colori di stato letterali — portano un significato e avranno una passata di token di stato dedicata in seguito, non token di superficie.
- Input glass (`dark:bg-gray-700`/`dark:text-white`), label dei form e varianti hover lasciati per un trattamento separato (coerente con il pilota).

### Fase 3 — Cluster delle impostazioni ✅
- [x] `settings.html` + 10 partial + `_modal`: 441 coppie ridotte. Le coppie interne dei ternari Alpine `:class` tokenizzate dal codemod (le virgolette incollano solo le classi di bordo del ramo); struttura ternaria verificata intatta.
- [x] `settings.js` + `setup-wizard.js`: 49 coppie, `node --check` pulito. Gli altri `settings-*.js` non portano classi di colore.
- Lasciato invariato (coerente con le fasi precedenti): input glass (`dark:bg-gray-700` ~99), label dei form (`dark:text-gray-300` ~78, rimandato), badge di stato, superfici con opacità, varianti hover, e classi di bordo del ramo ternario.

### Fase 4 — Pagine rimanenti ✅
- [x] Template: activity, help, setup, `_client_certs` (123 coppie; nessun ternario Alpine qui).
- [x] JS: client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js (26 coppie, `node --check` pulito). setup-wizard.js era già stato completato nella Fase 3.
- Stesse esclusioni delle fasi precedenti: input glass, grigi di corpo/label, superfici con opacità, colori di stato, hover, e classi ai limiti di concatenazione di stringhe.

### Fase 5 — Pulizia e consolidamento ✅
- [x] Decisione sulle label chiusa: token `text-label` + 137 siti migrati (vedi sopra).
- [x] Punto cieco del codemod rilevato: scansionava solo `class="..."`, tralasciando `className='...'` e la concatenazione di stringhe JS. Aggiunta una **passata letterale consapevole dei limiti** (riduce le sottostringhe `CHIARO SCURO` adiacenti in qualsiasi contesto) + il gate `--check`. La riesecuzione della scansione completa ha ridotto le coppie JS rimanenti (dialoghi confirm/prompt, modali report-issue + shortcuts).
- [x] Rimossi gli alias legacy inutilizzati `success`/`warning`/`danger` da `tailwind.config.js` (0 siti di chiamata). Mantenuti `primary` (~375) e `secondary` (gradienti).
- [x] **Guardrail CI**: `python3 scripts/theme_codemod.py --check` nel job `frontend-css` — fa fallire la build se una coppia chiaro+scuro riducibile viene reintrodotta in un template o in un file JS di prima parte.
- **Hex JS lasciati invariati, per scelta progettuale:** la palette `#60a5fa`/ecc. in `certmate.js` è il **logger della console di debug** su una superficie fissa sempre scura (`bg-black`); `TOAST_COLORS` sono classi di stato letterali. Entrambi sono accenti di stato indipendenti dal tema — per convenzione non fanno parte del theming chiaro/scuro — quindi rimangono letterali anziché diventare token di tema. Una futura **passata di token di stato** (success/warning/danger/info come variabili) è il luogo appropriato per unificarli se mai lo si desiderasse.
- Aggiornamento della baseline: opzionale; non eseguito (la cattura era rimasta in sospeso — verifica Docker in tempo reale usata ad ogni fase).

### Fase 6 — Passata dei token di stato ✅
- [x] Ri-aggiunti `success`/`warning`/`danger` (+ nuovo `info`) come **gruppi di token**
  (`surface`/`line`/`fg`/`strong`), adossati a variabili in `:root`/`.dark` (HSL,
  fedeli ai valori inline, superfici scure blended sulla card).
- [x] Esteso il codemod con una tabella generata tonalità×sfumatura (`_expand_status`)
  che piega le coppie verde/rosso/ambra/blu delle info-box sui token —
  normalizzando la deriva 50-vs-100 / 700-vs-800 dei callout inline.
  **300 coppie ridotte** nei template + JS di prima parte.
- [x] `--check` ora verifica anche le coppie di stato (vivono in `MAPPINGS`), quindi
  una coppia chiaro+scuro di stato reintrodotta fa fallire la CI come qualsiasi altra.
- Lasciato letterale per scelta progettuale: i singoli accenti di stato senza coppia chiaro/scuro
  (icona `text-*-500`), e le tinte solo-scuro (senza controparte chiara).

### Fase 7 — Superficie dei campi form ✅ (v2.9.1)
- [x] Aggiunto `--color-input` (bianco / gray-700) → `bg-input`; riduzione di 40
  coppie `bg-white dark:bg-gray-700`. Corrispondenza esatta dei valori.

### Fase 8 — Superfici hover e rientranti ✅ (v2.9.1)
- [x] Aggiunto `--color-hover` (gray-100/700), `border.strong` (gray-300/500) e
  `--color-sunken` (gray-50/700); riduzione di 51 coppie hover/rientranti. Le
  sfumature hover minoritarie lasciate letterali per mantenere la passata strettamente senza modifiche.

### Fase 9 — Tokenizzazione del layer dei componenti + accent ✅
- [x] Le regole `@apply` dei componenti R-3 (`.card`, `.form-input`/`.form-select`/
  `.form-label`, `.btn-secondary`, `.btn-ghost`, `.nav-active`, `.nav-inactive`)
  erano un **punto cieco del codemod** — `--check` scansiona `class="…"`, non `@apply` —
  e portavano ancora classi raw gray/blue. Migrate sui token.
- [x] Aggiunto un token `accent` sensibile al tema (blue-600 → blue-400 in modalità scura) affinché
  `.nav-active` non codifichi più il blu in modo rigido; questo è l'accent on-surface che
  mancava a #254.
- Non fatto (per scelta progettuale): adozione di `.btn`/`.form-*` sui siti di chiamata
  (i siti di chiamata inline sono già tokenizzati; forzare i componenti cambierebbe le
  dimensioni dei pulsanti a fronte di zero guadagno in termini di disaccoppiamento). `.btn-danger` (rosso d'azione solido) e le
  varianti `.badge-*` di stato rimangono letterali. Il layer `@apply` resta fuori dal gate
  `--check` — un futuro miglioramento del codemod potrebbe scansionarlo.

### Fase 10 — Decostruzione delle code di colore (pianificata, progressiva)
Il disaccoppiamento ha lasciato **565 utility `dark:`** che il codemod non riesce a ridurre: non
hanno un sibling chiaro con cui accoppiarsi, quindi `--check` non le vede mai. L'audit
(2026-05-25) mostra che non si tratta di un unico problema ma di tre, con profili di rischio opposti:

| Gruppo | Conteggio | Si risolve in | Nuovi token |
|---|---|---|---|
| 1 — Neutri (bianco/grigio) | 388 (69%) | `foreground / surface / surface-2 / sunken / muted / border` | 0 |
| 2 — Stato (blu/rosso/ambra) | 63 (11%) | `info / success / warning / danger` | 0 |
| 3 — Arcobaleno (viola/indigo/arancione) | 111 (20%) | **neutro** (decorativo, retrocesso) | 0 |

Rilievo chiave: **zero nuovi token necessari.** Il sistema di token già rilasciato *è*
il contratto; i 565 sono tutto ciò che vi è sfuggito. La correzione consiste nell'applicazione +
retrocessione, non in un nuovo vocabolario. (L'arcobaleno è risultato essere una codifica decorativa
delle sezioni — viola = "configurazione avanzata", indigo = CA/Enterprise, arancione =
Storage — non stato, e incoerente tra i file.)

Ordine, per rischio UX crescente:
- **10a — Neutri (388).** Invisibile: `dark:text-white` → `text-foreground`,
  `dark:bg-gray-700` → `bg-input`/`bg-surface-2`/`bg-sunken` (disambiguato per
  contesto — stesso grigio scuro, diversa intenzione *chiara*, quindi classificato da un
  umano per cluster, non sed alla cieca). Estendere `theme_codemod.py` con una
  passata solo-dark→token. Rischio ~0, pulisce ~70%.
- **10b — Stato (63).** Mappare i callout blu/rosso/ambra sui gruppi
  info/success/warning/danger esistenti. Normalizza la deriva 50-vs-100. Basso rischio.
- **10c — Arcobaleno (111).** La decisione di prodotto (vedi contratto di seguito).
  Le tonalità decorative di sezione collassano a neutro. Modifica visibile, eseguita per ultima,
  blocco per blocco con QA screenshot prima/dopo. Deciso: **contratto α**
  (colore = significato).

## Contratto di colore (lo standard che i 565 hanno eluso)
Deciso il 2026-05-25. Quattro regole; i token già rilasciati sono l'unica palette.

1. **Il colore si guadagna, non è mai decorativo.** Una tonalità compare solo se porta
   *stato* (info/success/warning/danger) o *brand* (accent: link, nav attiva, primary, focus).
   Tutto il resto è neutro
   (background/surface/surface-2/sunken/border/foreground/muted/label).
2. **L'identità viene dalla struttura, non dal colore.** Le sezioni si distinguono tramite
   spaziatura, intestazioni, icone, divisori — non una tonalità di riempimento.
3. **Una sola primitiva di enfasi.** I blocchi di configurazione/avanzati usano un unico
   pannello neutro rientrante (`bg-sunken border-border rounded-md`); un bordo sinistro
   brand opzionale indica "attivo/importante". Nessuna palette per sezione.
4. **Le icone si tingono solo con brand o stato.** Nessuna tinta viola/indigo/arancione sulle icone.

Applicazione: il gate `--check` acquisisce una regola che fa fallire la CI sul raw
`purple|indigo|orange` (e su qualsiasi colore non tokenizzato) in `templates/` — un
contratto con un compilatore alle spalle, che non può regredire.

## Colori di stato — ora tokenizzati (Fase 6)
Le fasi precedenti hanno deliberatamente rimandato i colori di stato (verde/ambra/rosso/blu con
le loro varianti `dark:`) come una passata separata e opzionale — portano un significato e sono
per convenzione invarianti rispetto al tema. **La Fase 6 ha eseguito quella passata:** le
superfici/bordi/testo delle info-box accoppiate usano ora `bg-success-surface`,
`text-danger-strong`, ecc. I singoli *accenti* di stato (icona `text-*-500`, senza coppia scura)
rimangono letterali — sono indipendenti dal tema e non fanno parte del theming chiaro/scuro.

## Allineamento del workflow
- Zero emoji in commit/PR/note di rilascio.
- Commit atomici (uno per fase, o per partial nella Fase 3); un PR per versione.
- Prima del push pubblico: smoke test Docker + emissione certificato reale sul dominio di Fab con sottodomini casuali.

---

<div align="center">

[← Torna alla documentazione](./README.md)

</div>
