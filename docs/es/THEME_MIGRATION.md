# Migración de tema — desacoplamiento claro/oscuro mediante tokens CSS

Estado: **entregado** (Fases 0-5 en v2.9.0; Fase 6 sigue) · Propietario: Fabrizio · Creado: 2026-05-25

## Objetivo

Hoy, cambiar el tema implica editar los colores en ~19 templates y el JS del frontend. Esta migración convierte un único bloque de propiedades personalizadas CSS en la fuente de verdad para toda la paleta, de modo que cambiar de tema (o añadir uno nuevo) significa editar `:root` / `.dark` en un solo archivo — no cientos de puntos de llamada.

## Estado inicial (medido el 2026-05-25)

| Métrica | Valor |
|---|---|
| Referencias de clases de color en los templates | ~3 197 en 19 archivos |
| Pares `dark:` en los templates | ~1 665 |
| Clases de color en el JS de la aplicación (no vendorizado) | ~789 (dashboard.js 372, settings.js 150, setup-wizard.js 131, certmate.js 60, client-certs.js 57, …) |
| Hex codificados en el JS de la aplicación | ~17 (paletas toast/gráfico); 80 más en `redoc.standalone.js` son **vendorizados, ignorar** |
| Clases de componentes R-3 adoptadas | `.card` solo (12×); `.btn-*`, `.badge-*`, `.form-*` = 0 |

Archivos más pesados: `partials/settings_dns.html` (635 / 395 dark:), `index.html` (311 / 150), `partials/settings_deploy.html`, `partials/settings_ca.html`.

## Riesgos de proceso a corregir primero

1. **El CSS compilado se confirma a mano.** `package.json` solo tiene `css:build` / `css:watch`; ningún CI reconstruye `static/css/tailwind.min.css`. Editar `input.css` sin reconstruir entrega silenciosamente un CSS obsoleto. → añadir compilación CI + verificación de frescura en la Fase 0.
2. **~3 200 ediciones manuales = regresiones garantizadas.** Se necesita una referencia visual (capturas de pantalla claro+oscuro de cada página) y un codemod semi-automático para los pares `dark:` mecánicos, no una sustitución ciega.

## Estrategia: propiedades CSS personalizadas como fuente única

Estilo shadcn sobre Tailwind v3: los colores se convierten en variables CSS en `:root` / `.dark`, expuestas a Tailwind como tokens semánticos (tripletes de canales HSL para que los utilitarios `/opacity` sigan funcionando). Los ~1 665 pares `dark:` se reducen a clases únicas.

### Tabla de correspondencia de tokens propuesta

| Token Tailwind | Reemplaza (ejemplos) | Uso |
|---|---|---|
| `bg-background` | `bg-gray-50 dark:bg-surface-dark` | página |
| `bg-surface` | `bg-white dark:bg-surface-card` | tarjeta |
| `bg-surface-2` | `bg-gray-100 dark:bg-gray-800` | elevado |
| `text-foreground` | `text-gray-900 dark:text-white` | texto principal |
| `text-muted` | `text-gray-500 dark:text-gray-400` | texto secundario |
| `border-border` | `border-gray-200 dark:border-gray-700` | bordes |
| `bg-primary` / `text-primary` | marca (ahora basado en var) | marca |
| `*-success/warning/danger/info` | verde=válido, rojo=expirado… | **estado**, no superficies |

## Fases

Cada fase = un commit atómico (dividir los partials de la Fase 3 en sus propios commits). Las fases se agrupan en uno o más PRs de versión `vX.Y.Z`.

### Fase 0 — Fundamentos y salvaguardas (sin cambio visual)
- [x] Paso de CI que ejecuta `npm run css:build` y falla si `tailwind.min.css` está obsoleto (`git diff --exit-code`). → job `frontend-css` en `.github/workflows/ci.yml`. El bundle confirmado ya había divergido; reconstruido y confirmado.
- [x] Definir la capa de tokens: variables CSS en `:root` / `.dark` (input.css) + mapping en `tailwind.config.js`, **en paralelo** con la paleta existente — sin tocar ningún template. Tokens: `bg-background`, `bg-surface`, `bg-surface-2`, `text-foreground`, `text-muted`, `border-border` (en safelist).
- [x] Escribir el codemod: `scripts/theme_codemod.py` — tabla de correspondencia de los pares `dark:` recurrentes → tokens, informe dry-run + `--apply`. Informe de ambigüedad a continuación.
- [x] Herramientas de captura de pantalla: `scripts/theme_baseline.py` — construye Docker con un directorio de datos efímero, inicializa un administrador desechable, captura cada página real de la UI en claro + oscuro. Volver a ejecutar tras cada fase y comparar. **Captura aún pendiente** (requiere `playwright install chromium` + una construcción Docker local).

#### Alcance de la referencia (solo páginas reales)
Capturadas: `/` (setup, luego index), `/login`, `/settings`, `/help`, `/activity`, `/redoc` — 7 páginas × claro/oscuro.

> **Hallazgo (fuera de alcance, señalado):** las rutas `/certificates` y `/audit` en `modules/web/ui_routes.py:25-41` renderizan `certificates.html` / `audit.html`, que **no existen** — ambas devuelven 500. Rutas muertas, excluidas de la referencia. Merece una corrección separada (eliminar las rutas o restaurar los templates).

#### Uso del codemod
```
python scripts/theme_codemod.py                     # informe dry-run, todos los templates
python scripts/theme_codemod.py templates/base.html # informe, un archivo
python scripts/theme_codemod.py --apply templates/base.html
```
Tras cada `--apply`: `npm run css:build`, comparar contra la referencia, revisar las variantes `dark:` residuales.

#### Resumen del informe (2026-05-25)
**607 pares auto-reducidos** de ~1 665 variantes `dark:`:

| Token | Pares |
|---|---|
| `text-muted` | 203 |
| `border-border` | 169 |
| `text-foreground` | 141 |
| `bg-surface` | 77 |
| `bg-surface-2` | 16 |
| `bg-background` | 1 |

**557 ocurrencias / 29 variantes sin mapear** — decisiones de diseño para el piloto de la Fase 1, no deducidas automáticamente:

- `dark:bg-gray-700` (137): se empareja con `bg-white` (tarjetas/inputs) **y** `bg-gray-50` — decidir surface vs surface-2 según el contexto.
- `dark:text-white` (120): los que se emparejan con `text-gray-900` ya se mapean a `text-foreground`; los demás son texto siempre blanco sobre fondos de color — probablemente dejar como están.
- `dark:text-gray-300` (112): principalmente `text-gray-700 dark:text-gray-300` = el patrón de labels de formulario — decidir un token de label dedicado vs `text-muted`/`text-foreground`.
- `dark:border-gray-600` (41), `dark:text-gray-200` (39), superficies con sufijo de opacidad (`dark:bg-gray-700/50` etc.), y `dark:border-white/5`.

Unos pocos residuos (`dark:text-gray-400{%`, `dark:text-gray-300'`) son atributos de clase que contienen expresiones Jinja/JS — migrar a mano.

### Fase 1 — Piloto: shell + primitivas
- [x] Migrar `base.html` (nav/header/footer/barra de pestañas) a tokens. 19 pares reducidos; los valores de los tokens coinciden exactamente con los originales.
- [x] Migrar `login.html` a tokens. 12 pares reducidos.
- [ ] Adoptar las clases de componentes `.btn` / `.form-*` (aplazado — el piloto usó solo tokens; los inputs de inicio de sesión difieren en tamaño de `.form-input`, por lo que la adopción de componentes es un paso separado).
- [x] Validar la paridad claro/oscuro. Verificado en vivo en Docker (base.html + login.html, ambos temas) — piloto aceptado.

#### Decisiones de diseño abiertas (surgidas del piloto)
1. **Texto de labels de formulario** (`text-gray-700 dark:text-gray-300`). **RESUELTO en la Fase 5 → opción (b):** añadido el token `--color-label` con los valores exactos gray-700/gray-300 (fiel, sin cambio visual) y migradas las 137 ocurrencias a `text-label`. La fusión en `text-foreground` fue rechazada (oscurecería el modo claro de 27%→11% L).
2. **Unificación de bordes**: `border-gray-300` (inputs) ahora se mapea a `border-border` (= gray-200), por lo que los bordes de los inputs se aclaran un paso en modo claro. Aceptado para el piloto (un único token de borde es el objetivo); revisar con `--color-input-border` solo si el resultado no convence en la revisión.
3. **Inputs glass / `dark:border-white/5` trazo fino / variantes hover / colores de estado**: intencionalmente NO tokenizados — los controles glass no tienen contrapartida en modo claro, el trazo fino white/5 es el borde canónico de `.card`, y hover/estado requieren su propia pasada de tokens de variante (una fase posterior).

### Fase 2 — Panel de control ✅
- [x] `index.html` (chrome del panel de control): formulario de creación, tarjetas de lista/estadísticas, cabeceras de tabla + divisores, panel de detalle, modales. Los ternarios Alpine `:class` y `divide-border` tratados a mano.
- [x] `static/js/dashboard.js`: filas renderizadas en JS, estadísticas, estados vacíos/bienvenida, panel de detalle, salida de verificación de alias. `node --check` limpio.
- Los colores de estado de salud/despliegue (verde/ámbar/rojo/azul) se dejan intencionalmente como colores de estado literales — llevan significado y tendrán una pasada de tokens de estado dedicada más adelante, no tokens de superficie.
- Los inputs de formulario glass (`dark:bg-gray-700`/`dark:text-white`), los labels de formulario y las variantes hover se dejan para su propio tratamiento (coherente con el piloto).

### Fase 3 — Cluster de ajustes ✅
- [x] `settings.html` + 10 partials + `_modal`: 441 pares reducidos. Los pares interiores de los ternarios Alpine `:class` tokenizados por el codemod (las comillas solo unen las clases de borde de rama); estructura ternaria verificada intacta.
- [x] `settings.js` + `setup-wizard.js`: 49 pares, `node --check` limpio. Los demás `settings-*.js` no tienen clases de color.
- Dejado como está (coherente con las fases anteriores): inputs glass (`dark:bg-gray-700` ~99), labels de formulario (`dark:text-gray-300` ~78, aplazado), badges de estado, superficies de opacidad, variantes hover, y clases de borde de rama ternarios.

### Fase 4 — Páginas restantes ✅
- [x] Templates: activity, help, setup, `_client_certs` (123 pares; sin ternarios Alpine aquí).
- [x] JS: client-certs.js, cmd-palette.js, report-issue.js, shortcuts.js (26 pares, `node --check` limpio). setup-wizard.js ya se hizo en la Fase 3.
- Las mismas exclusiones que antes: inputs glass, grises de cuerpo/label, superficies de opacidad, colores de estado, hover, y clases en los límites de concatenación de cadenas.

### Fase 5 — Limpieza y consolidación ✅
- [x] Decisión sobre el label cerrada: token `text-label` + 137 sitios migrados (véase más arriba).
- [x] Punto ciego del codemod detectado: solo escaneaba `class="..."`, omitiendo las asignaciones `className='...'` y la concatenación de cadenas JS. Añadida una **pasada literal consciente de los límites** (colapsa subcadenas `CLARO OSCURO` adyacentes en cualquier contexto) + la puerta `--check`. Volver a ejecutar el barrido completo colapsó los pares JS restantes (diálogos confirm/prompt, modales de report-issue + shortcuts).
- [x] Eliminados los alias legacy no utilizados `success`/`warning`/`danger` de `tailwind.config.js` (0 sitios de llamada). Se conservan `primary` (~375) y `secondary` (degradados).
- [x] **Salvaguarda CI**: `python3 scripts/theme_codemod.py --check` en el job `frontend-css` — falla la compilación si se reintroduce algún par claro+oscuro colapsable en un template o archivo JS de primera parte.
- **Hex JS dejado como está, por diseño:** la paleta `#60a5fa`/etc. en `certmate.js` es el **logger de consola de depuración** sobre una superficie fija siempre oscura (`bg-black`); `TOAST_COLORS` son clases de estado literales. Ambos son acentos de estado independientes del tema — convencionalmente no pertenecen al theming claro/oscuro — por lo que permanecen literales en lugar de convertirse en tokens de tema. Una futura **pasada de tokens de estado** (success/warning/danger/info como vars) es el lugar adecuado para unificarlos si algún día se desea.
- Actualización de la referencia: opcional; no ejecutada (la captura se aplazó — se usó la verificación Docker en vivo en cada fase en su lugar).

### Fase 6 — Pasada de tokens de estado ✅
- [x] Reintroducción de `success`/`warning`/`danger` (+ nuevo `info`) como **grupos de tokens**
  (`surface`/`line`/`fg`/`strong`), respaldados por variables en `:root`/`.dark` (HSL,
  fiel a los valores inline, superficies oscuras mezcladas sobre la tarjeta).
- [x] Extensión del codemod con una tabla de matiz×tono generada (`_expand_status`)
  que colapsa los pares verde/rojo/ámbar/azul de las info-box sobre los tokens —
  normalizando la desviación 50-vs-100 / 700-vs-800 que llevaban los callouts inline.
  **300 pares colapsados** en templates + JS de primera parte.
- [x] `--check` ahora también guarda los pares de estado (viven en `MAPPINGS`), por lo que
  un par claro+oscuro de estado reintroducido falla en CI como cualquier otro.
- Dejado literal por diseño: los acentos de estado únicos sin par claro/oscuro
  (icono `text-*-500`), y los tintes solo-oscuro (sin contrapartida clara).

### Fase 7 — Superficie de campos de formulario ✅ (v2.9.1)
- [x] Añadido `--color-input` (blanco / gray-700) → `bg-input`; colapso de 40
  pares `bg-white dark:bg-gray-700`. Coincidencia exacta de valores.

### Fase 8 — Superficies hover y hundidas ✅ (v2.9.1)
- [x] Añadidos `--color-hover` (gray-100/700), `border.strong` (gray-300/500) y
  `--color-sunken` (gray-50/700); colapso de 51 pares hover/hundidos. Los tonos
  hover minoritarios se dejan literales para que la pasada sea estrictamente sin cambio visual.

### Fase 9 — Tokenización de la capa de componentes + acento ✅
- [x] Las reglas `@apply` de los componentes R-3 (`.card`, `.form-input`/`.form-select`/
  `.form-label`, `.btn-secondary`, `.btn-ghost`, `.nav-active`, `.nav-inactive`)
  eran un **punto ciego del codemod** — `--check` escanea `class="…"`, no `@apply` —
  y seguían llevando clases raw gray/blue. Migradas a los tokens.
- [x] Añadido un token `accent` sensible al tema (blue-600 → blue-400 en oscuro) para que
  `.nav-active` no codifique el azul de forma fija; este es el acento de superficie que
  faltaba en #254.
- No hecho (por diseño): adopción de `.btn`/`.form-*` en los sitios de llamada (los sitios
  de llamada inline ya están tokenizados; forzar los componentes cambiaría el tamaño de los
  botones sin ninguna ganancia de desacoplamiento). `.btn-danger` (rojo de acción sólido) y
  las variantes `.badge-*` de estado permanecen literales. La capa `@apply` queda fuera de
  la puerta `--check` — una mejora futura del codemod podría escanearla.

### Fase 10 — Descomposición de colas de color (planificada, gradual)
El desacoplamiento dejó **565 utilitarios `dark:`** que el codemod no puede colapsar: no
tienen un sibling claro con el que emparejarse, por lo que `--check` nunca los detecta. La
auditoría (2026-05-25) muestra que no se trata de un solo problema sino de tres, con perfiles
de riesgo opuestos:

| Grupo | Cantidad | Se resuelve en | Nuevos tokens |
|---|---|---|---|
| 1 — Neutros (blanco/gris) | 388 (69%) | `foreground / surface / surface-2 / sunken / muted / border` | 0 |
| 2 — Estado (azul/rojo/ámbar) | 63 (11%) | `info / success / warning / danger` | 0 |
| 3 — Arcoíris (morado/indigo/naranja) | 111 (20%) | **neutro** (decorativo, degradado) | 0 |

Hallazgo clave: **cero nuevos tokens necesarios.** El sistema de tokens ya entregado *es*
el contrato; los 565 son todo lo que escapó de él. La corrección es la aplicación + la
degradación, no un nuevo vocabulario. (El arcoíris fue medido como codificación decorativa
de secciones — morado = "configuración avanzada", indigo = CA/Enterprise, naranja =
Storage — no como estado, e inconsistente entre archivos.)

Orden, por riesgo UX creciente:
- **10a — Neutros (388).** Invisible: `dark:text-white` → `text-foreground`,
  `dark:bg-gray-700` → `bg-input`/`bg-surface-2`/`bg-sunken` (disambiguado por
  contexto — mismo gris oscuro, diferente intención *clara*, por lo que se clasifica
  manualmente por cluster, no con sed ciego). Extender `theme_codemod.py` con una
  pasada solo-dark→token. Riesgo ~0, resuelve ~70%.
- **10b — Estado (63).** Mapear los callouts azul/rojo/ámbar sobre los grupos
  info/success/warning/danger existentes. Normaliza la desviación 50-vs-100. Riesgo bajo.
- **10c — Arcoíris (111).** La decisión de producto (ver contrato a continuación).
  Los tonos decorativos de sección se colapsan a neutro. Cambio visible, hecho en último
  lugar, bloque a bloque con QA de capturas antes/después. Decidido: **contrato α**
  (color = significado).

## Contrato de color (la norma que los 565 escaparon)
Decidido el 2026-05-25. Cuatro reglas; los tokens ya entregados son la única paleta.

1. **El color se gana, nunca es decorativo.** Un tono aparece solo si lleva
   *estado* (info/success/warning/danger) o *marca* (acento: enlaces, nav activa,
   primario, foco). Todo lo demás es neutro
   (background/surface/surface-2/sunken/border/foreground/muted/label).
2. **La identidad viene de la estructura, no del color.** Las secciones se distinguen por
   el espaciado, los encabezados, los iconos, los divisores — no por un tono de relleno.
3. **Una sola primitiva de énfasis.** Los bloques de configuración/avanzados usan un único
   panel neutro hundido (`bg-sunken border-border rounded-md`); un borde izquierdo de marca
   opcional marca "activo/importante". Sin paleta por sección.
4. **Los iconos solo se tiñen con marca o estado.** Sin tintes morado/indigo/naranja en iconos.

Aplicación: la puerta `--check` gana una regla que falla en CI con cualquier
`purple|indigo|orange` en bruto (y cualquier color no tokenizado) en `templates/` — un
contrato con un compilador detrás, que no puede volver a degradarse.

## Colores de estado — ahora tokenizados (Fase 6)
Las fases anteriores aplazaron deliberadamente los colores de estado (verde/ámbar/rojo/azul
con sus variantes `dark:`) como una pasada separada y opcional — llevan significado y son
convencionalmente invariantes de tema. **La Fase 6 realizó esa pasada:** las
superficies/bordes/texto de las info-box emparejadas usan ahora `bg-success-surface`,
`text-danger-strong`, etc. Los acentos de estado *únicos* (icono `text-*-500`, sin par
oscuro) permanecen literales — son independientes del tema y no forman parte del theming
claro/oscuro.

## Alineación del flujo de trabajo
- Cero emoji en commits/PRs/notas de versión.
- Commits atómicos (uno por fase, o por partial en la Fase 3); un PR por versión.
- Antes del push público: smoke de Docker + emisión de certificado real contra el dominio de Fab con subdominios aleatorios.

---

<div align="center">

[← Volver a la documentación](./README.md)

</div>
