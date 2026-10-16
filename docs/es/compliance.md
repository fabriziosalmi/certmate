# Cumplimiento normativo y pista de auditoría

<!-- CERTMATE-TRANSLATED-FROM 0ddda303c6fe494a -->

Esta página relaciona la pista de auditoría de CertMate con los regímenes por los que los operadores preguntan
con mayor frecuencia — el AI Act de la UE, NIS2 y la ISO/IEC 42001 — cuando permiten que un agente IA/MCP
gestione certificados de forma programada.

> **Lea esto primero.** CertMate es una herramienta MIT auto-alojada mono-instancia. **No**
> es un sistema de IA, **no** es un sistema de IA de alto riesgo y **no** es una entidad
> regulada, y no «cumple» ni «certifica» nada. Las obligaciones de
> cumplimiento recaen sobre el **operador** que lo ejecuta. Lo que CertMate proporciona son
> **artefactos de evidencia** que un operador puede utilizar para *sus propias* obligaciones.
> Cada afirmación a continuación significa «permite al operador evidenciar X», con los límites
> indicados de forma explícita.

## Qué proporciona la pista de auditoría hoy

- **Atribución.** Cada acción del ciclo de vida de los certificados — creación, renovación, reemisión,
  deploy, activación/desactivación de la renovación automática y renovaciones programadas no supervisadas — queda registrada
  con un `actor` estructurado (humano vs token de API vs agente IA, hasta el ID de la clave
  de API) y un `trigger` (manual, API, agente o el job del planificador). Las acciones de un agente IA
  son distinguibles de las de un humano, siempre que el agente utilice una
  clave marcada como `is_agent`. Véase [API: Registro de auditoría](./api.md#registro-de-auditoría) y
  la [guía MCP](./mcp.md#atribución-de-auditoría).
- **Prueba de integridad.** Las entradas se escriben en una cadena de hash SHA-256 de solo anexado
  (`data/audit/certificate_audit.chain.jsonl`). Cualquier modificación,
  eliminación o reordenamiento por parte de alguien que no pueda recalcular la cadena es detectable
  y localizable.
- **Verificación independiente.** Un verificador autónomo
  (`python -m modules.core.audit_verify`) recalcula la cadena y devuelve
  PASS/FAIL sin necesidad de ejecutar ni confiar en CertMate; `GET /api/audit/verify`
  expone la misma comprobación a través de la API y, cuando la firma está activada, además
  contrasta la cadena con el último punto de control firmado, de modo que un truncado
  de cola o una reescritura en ese punto de control o por debajo de él no supera la verificación (véase
  «el truncado de cola» en Límites honestos).
- **Exportación firmada verificable por terceros.** La instancia firma el head de la cadena
  (puntos de control periódicos) y `GET /api/audit/export` produce un bundle firmado con Ed25519.
  Un auditor lo verifica fuera de la máquina, vinculando la clave pública de la instancia
  (`GET /api/audit/public-key`) fuera de banda — demostrando tanto que el registro fue
  escrito y no modificado como qué instancia lo produjo. Ese endpoint devuelve
  JSON, no un archivo PEM: guarde su campo `public_key_pem` como el `.pem` que espera
  el `--pubkey` del verificador. Responde 404 cuando la instancia no tiene
  clave de firma.
- **Destino de auditoría SIEM (push).** Cada entrada de auditoría puede además enviarse en vivo a un
  colector externo en un formato estándar — **syslog** (RFC 5424) o **CEF**
  sobre UDP/TCP, o **HTTP/JSON genérico** — configurado en `audit_sink` en los
  ajustes. Las entradas pasan por el saneador de credenciales/secretos antes de
  salir del proceso (un token en un campo de detalle queda ocultado), y el destino está
  aislado frente a fallos con un timeout corto, como la cadena de hash: un colector caído
  nunca bloquea ni rompe una operación sobre certificados. La cobertura del ciclo de vida incluye
  creación / renovación / deploy / revocación, y el resumen periódico programado: es una
  entrada de auditoría, así que llega al destino como cualquier otra. Lo que registra es el
  resultado, para cuántos destinatarios era y los recuentos que comunicó — **no
  los propios destinatarios**, que son datos personales que esta cadena no puede retirar
  después. Un resumen omitido porque las notificaciones o el SMTP están desactivados
  no escribe nada: eso ya lo responden los ajustes, y una entrada semanal que lo dijera
  haría crecer la cadena para siempre sin decir nada.

## Correspondencia con los regímenes

### NIS2 (Directiva (UE) 2022/2555) — la mejor adecuación

- **En qué ayuda.** Las operaciones sobre certificados modifican la postura de confianza de los
  servicios, por lo que son eventos relevantes para la seguridad. CertMate produce un
  registro a prueba de manipulaciones, atribuido y con marca de tiempo de cada una de esas operaciones, más
  una comprobación verificable de forma independiente — utilizable como parte de las prácticas de registro
  (Art. 21) y de evidencia de incidentes (Art. 23) del operador.
- **Límite.** NIS2 obliga a **entidades** esenciales/importantes, no a herramientas de software.
  CertMate proporciona registros y un verificador que el operador puede usar; no evalúa,
  monitoriza ni notifica incidentes, y ser una entidad en el ámbito de aplicación (y cumplir NIS2 en
  su totalidad) es responsabilidad del operador.

### AI Act de la UE — Artículo 50 transparencia (solo en espíritu; la peor adecuación)

- **En qué ayuda.** Cuando un agente IA opera la PKI de forma autónoma, el registro
  lleva un marcador explícito `actor.kind="agent"` más la sesión del agente, de modo que el
  operador puede demostrar a posteriori qué cambios realizó un agente IA
  frente a un humano, bajo qué identidad y qué los desencadenó — respaldando el
  espíritu de transparencia y supervisión humana del Acto.
- **Límite.** Las obligaciones del Art. 50 recaen sobre los **proveedores/desplegadores de sistemas de IA** y
  se refieren a la divulgación a personas físicas que interactúan con la IA. Un agente que renueva
  certificados TLS no es un caso de manual del Art. 50, y CertMate es una herramienta, no un
  sistema de IA. Nos alineamos solo con el espíritu de transparencia; CertMate **no** satisface
  el Art. 50 en nombre de nadie.

### ISO/IEC 42001 (Sistema de gestión de la IA) — registros operacionales

- **En qué ayuda.** Los registros atribuidos y a prueba de manipulaciones son evidencia
  objetiva de que un agente IA realizó acciones concretas sobre certificados — utilizables para los
  controles de registros operacionales y trazabilidad del propio AIMS del operador.
- **Límite.** ISO 42001 certifica el sistema de gestión de una organización, no una herramienta.
  CertMate no está certificado con ISO 42001 y no puede certificar al operador;
  produce registros que el operador puede presentar como evidencia para sus propios controles.

## Límites honestos (no sobreinterprete estos puntos)

- **La clave de firma no vincula al operador.** Un bundle de exportación firmado (y
  los puntos de control firmados periódicos) permiten a un tercero verificar, fuera de la máquina, qué
  instancia produjo el registro y que no fue modificado — para cualquiera que
  **no** posea la clave de firma. Pero el operador posee la clave y podría re-firmar
  una cadena reescrita. Restringir completamente al operador requiere enviar los
  puntos de control firmados a un destino externo de solo anexado (**anclaje externo opcional — una
  funcionalidad planificada, aún no disponible**). Trate la garantía actual como
  «autenticidad, ordenación y atribución a la instancia de las entradas registradas»,
  verificable de forma independiente por un tercero que posea una copia firmada exportada.
- **Autenticidad, no exhaustividad.** Las escrituras de auditoría son de mejor esfuerzo y nunca
  bloquean una operación sobre certificados; la cadena prueba que las entradas registradas son
  auténticas y están ordenadas, y un `seq` interior faltante prueba una eliminación, pero una
  escritura que falló antes de ser registrada no deja ninguna entrada que verificar.
- **El truncado de cola se detecta hasta el último punto de control firmado.** Eliminar
  entradas del **final** de la cadena deja una cadena más corta pero internamente
  coherente. `GET /api/audit/verify` contrasta ahora la cadena con
  el punto de control firmado más reciente que se verifica con la clave de la instancia, de modo que cualquier
  truncado, retroceso o reescritura **en ese punto de control o por debajo de él** no supera la
  verificación — los puntos de control, que antes solo se escribían, ahora se vuelven a leer. La
  cola **se sella en un apagado limpio**: todo lo escrito desde el último
  punto de control se firma al salir, de modo que un contenedor que se detiene con normalidad
  no deja nada sin atestar. Quedan dos huecos: (a) un **crash**, un `SIGKILL` o un
  corte de alimentación se detienen antes de eso, y las entradas desde el último punto de control pueden
  entonces seguir siendo eliminadas sin ser detectadas hasta que el siguiente las selle — el hueco se ha reducido
  de «cada parada» a «una parada no limpia», no se ha cerrado; y (b) un operador que
  posea la clave de firma puede re-firmar un punto de control nuevo sobre una cadena reescrita.
  Conserve exportaciones firmadas sucesivas, o espere al anclaje externo opcional, si
  necesita cerrar esos huecos.
- **La cabecera de sesión del agente es una declaración.** Se registra para correlación, pero la
  suministra el cliente; la identidad de confianza es la clave de API autenticada.
- **Las acciones de arranque se atribuyen a `setup_user`.** Hasta que la configuración inicial se completa,
  una instancia atiende cada petición como admin, por lo que no hay ninguna identidad real que
  registrar y la cadena lo dice claramente. Una entrada como `create` / `user` /
  `setup_user` significa que ese usuario se creó mientras cualquiera que pudiera alcanzar la
  instancia era admin. En una versión actual solo el primer admin se puede
  crear de esa forma — un segundo usuario o una clave de API se rechazan — así que se espera exactamente una
  entrada de ese tipo. Más de una significa que la instancia se inicializó
  con una versión anterior, y conviene confirmar o eliminar cada usuario después del primero.
  Las claves de API emitidas en esa ventana aparecen marcadas en la página de claves de API
  y esperan a un operador; los usuarios no se marcan, y es en la cadena donde está la
  respuesta para ellos.
- **Límite histórico.** La cadena comienza cuando la funcionalidad se activa por primera vez;
  el historial de `.log` anterior no forma parte de la cadena verificable.
- **Una cadena podada prueba menos, y lo dice.** Si ha ejecutado
  `audit_prune` (más abajo), la verificación cubre las entradas a partir del ancla
  en adelante. El prefijo archivado lo atestiguan el ancla firmada y el
  bundle exportado que usted conserva fuera de la máquina — no el archivo de la cadena. `verify` informa
  `anchored` y el seq del ancla precisamente por este motivo; trate una afirmación de «íntegra»
  sin más sobre una instancia podada como una exageración.

## Retención: archivar parte de la cadena

La cadena crece una línea por cada operación auditada — del orden de cientos de
kilobytes al año en una instancia con mucha actividad — así que la mayoría de los operadores nunca necesitarán esto. Existe
para el caso en que una política de retención exige que los registros más antiguos salgan de la
máquina.

No hay poda automática, ni hay ningún endpoint de API para ello. Borrar
el historial de auditoría es exactamente lo que querría hacer alguien que acaba de comprometer una cuenta de
administrador, y un operador con una obligación de retención legítima
tiene acceso a la shell de todos modos — tiene que guardar el archivo en algún sitio. Así que es un único
comando explícito, que se ejecuta con CertMate detenido:

```bash
# 1. Exporte el prefijo que pretende archivar (token admin).
curl -H "Authorization: Bearer $TOKEN" \
     "https://certmate.example.com/api/audit/export?to_seq=1199" > archive-0-1199.json

# 2. Verifíquelo FUERA de esta máquina, vinculando la clave de la instancia.
python -m modules.core.audit_verify --bundle archive-0-1199.json --pubkey instance.pem

# 3. Guárdelo donde indique su política. Después, con CertMate detenido:
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit
python -m modules.core.audit_prune --bundle archive-0-1199.json --data-dir data/audit --yes
```

El comando sin `--yes` es una ejecución en seco. Se niega, y no elimina nada, si
el bundle no se verifica, no está firmado, está vacío, no es un prefijo de *esta*
cadena o discrepa de la cadena en algún seq, o si la poda dejaría la
cadena sin entradas después del prefijo archivado — nunca se borran registros
cuya única copia restante no está verificada, y nunca se acaba con una cadena a la que
no le queda nada que verificar.

También se niega si `--key-dir` no contiene ninguna clave de firma, o contiene una que pertenece a
una instancia distinta de la que exportó el bundle. Ambas cosas se comprueban
**antes** de eliminar nada: un ancla firmada con la clave equivocada es una que el propio
`verify` de la instancia rechaza, y descubrirlo cuando los registros ya han
desaparecido es demasiado tarde para que sirva de algo.

Apunte `--key-dir` a la clave de la instancia. Por defecto es `data` (relativo al
directorio desde el que ejecuta el comando) y debe contener la
`.audit_signing_key` de la instancia, salvo que `AUDIT_SIGNING_KEY_FILE` esté definida del mismo modo en que la
define la instancia. La herramienta nunca crea una clave aquí: una clave nueva sería una nueva
identidad de instancia, no la de esta instancia.

Lo que hace a continuación es la parte que importa para el cumplimiento:

- **La eliminación queda registrada en la cadena que la sobrevive.** Se añade una entrada `archive`
  que indica el rango de seq, el número de entradas, su hash de cabeza y
  el SHA-256 del fichero archivado. Quien lea la cadena podada puede ver que
  se eliminaron entradas, cuándo y qué archivo las contiene.
- **El resto se verifica a partir de un ancla firmada.** `certificate_audit.anchor.json`
  indica dónde empieza ahora la cadena y de qué es continuación, firmado con la
  clave de la instancia, de modo que una cadena simplemente truncada no puede hacerse pasar por una
  podada — el ancla no se puede falsificar sin la clave.
- **Sigue siendo honesta después.** La verificación de una cadena podada nunca informa un
  «íntegra» sin más: tanto la API como el verificador autónomo indican en qué seq
  empieza la garantía.

Dos límites que conviene indicar. El ancla describe el archivo **más reciente**; el
historial completo es la secuencia de bundles exportados, por lo que deben
conservarse y por lo que el digest de cada uno queda registrado en la cadena. Y, como en el resto
de esta página, la clave de la instancia no vincula al operador: quien la posea puede
firmar un ancla sobre una cadena que haya reescrito. Pode solo hasta donde
alcancen realmente sus archivos.

Las exportaciones firmadas que un auditor externo vincula a una clave publicada están disponibles
hoy. Si sus obligaciones requieren vincular al operador *en sí mismo* — de modo que
incluso el titular de la clave no pueda reescribir el historial sin ser detectado — eso necesita el anclaje
externo opcional de los puntos de control firmados a un destino de solo anexado fuera de la máquina,
que está planificado pero aún no disponible. Siga su estado antes de depender de él.
