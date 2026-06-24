# Cumplimiento normativo y pista de auditoría

Esta página relaciona la pista de auditoría de CertMate con los regímenes que los operadores consultan con mayor frecuencia — el AI Act de la UE, NIS2 y la ISO/IEC 42001 — cuando permiten que un agente IA/MCP gestione certificados de forma programada.

> **Lea esto primero.** CertMate es una herramienta MIT auto-alojada mono-instancia. **No** es un sistema de IA, **no** es un sistema de IA de alto riesgo, **no** es una entidad regulada, y no «cumple» ni «certifica» nada. Las obligaciones de cumplimiento recaen sobre el **operador** que lo ejecuta. Lo que CertMate proporciona son **artefactos de evidencia** que un operador puede utilizar para *sus propias* obligaciones. Cada afirmación a continuación significa «permite al operador evidenciar X», con los límites indicados de forma explícita.

---

## Qué proporciona la pista de auditoría hoy

- **Atribución.** Cada acción del ciclo de vida de los certificados — creación, renovación, reemisión, deploy, activación/desactivación de la renovación automática y renovaciones programadas no supervisadas — queda registrada con un `actor` estructurado (humano vs token de API vs agente IA, hasta el ID de la clave de API) y un `trigger` (manual, API, agente o job del planificador). Las acciones de un agente IA son distinguibles de las de un humano, siempre que el agente utilice una clave marcada como `is_agent`. Véase [API: Audit Logging](./api.md#audit-logging) y la [guía MCP](./mcp.md#audit-attribution).
- **Prueba de integridad.** Las entradas se escriben en una cadena de hash SHA-256 de solo anexado (`data/audit/certificate_audit.chain.jsonl`). Cualquier modificación, eliminación o reordenamiento por parte de alguien que no pueda recalcular la cadena es detectable y localizable.
- **Verificación independiente.** Un verificador autónomo (`python -m modules.core.audit_verify`) recalcula la cadena y devuelve PASS/FAIL sin necesidad de ejecutar ni confiar en CertMate; `GET /api/audit/verify` expone la misma comprobación a través de la API.
- **Exportación firmada verificable por terceros.** La instancia firma el head de la cadena (puntos de control periódicos) y `GET /api/audit/export` produce un bundle firmado con Ed25519. Un auditor lo verifica fuera de la máquina, vinculando la clave pública de la instancia (`GET /api/audit/public-key`) fuera de banda — demostrando tanto que el registro no fue modificado como qué instancia lo produjo.

---

## Correspondencia con los regímenes

### NIS2 (Directiva (UE) 2022/2555) — la mejor adecuación

- **En qué ayuda.** Las operaciones sobre certificados modifican la postura de confianza de los servicios, por lo que son eventos relevantes para la seguridad. CertMate produce un registro infalsificable, atribuido y con marca de tiempo de cada operación, más una verificación independiente — utilizable como parte de las prácticas de registro (Art. 21) y de evidencia de incidentes (Art. 23) del operador.
- **Límite.** NIS2 obliga a **entidades** esenciales/importantes, no a herramientas de software. CertMate proporciona registros y un verificador que el operador puede usar; no evalúa, monitoriza ni notifica incidentes, y ser una entidad en el ámbito de aplicación (y cumplir NIS2 en su totalidad) es responsabilidad del operador.

### AI Act de la UE — Artículo 50 transparencia (solo en espíritu; la peor adecuación)

- **En qué ayuda.** Cuando un agente IA opera la PKI de forma autónoma, el registro lleva un marcador explícito `actor.kind="agent"` más la sesión del agente, de modo que el operador puede demostrar a posteriori qué cambios realizó un agente IA frente a un humano, bajo qué identidad y qué los desencadenó — respaldando el espíritu de transparencia y supervisión humana del Acto.
- **Límite.** Las obligaciones del Art. 50 recaen sobre los **proveedores/desplegadores de sistemas de IA** y se refieren a la divulgación a personas físicas que interactúan con la IA. Un agente que renueva certificados TLS no es un caso de manual del Art. 50, y CertMate es una herramienta, no un sistema de IA. Nos alineamos solo con el espíritu de transparencia; CertMate **no** satisface el Art. 50 en nombre de nadie.

### ISO/IEC 42001 (Sistema de gestión de la IA) — registros operacionales

- **En qué ayuda.** Los registros atribuidos e infalsificables son evidencia objetiva de que un agente IA realizó acciones concretas sobre certificados — utilizables para los controles de registros operacionales y trazabilidad del propio AIMS del operador.
- **Límite.** ISO 42001 certifica el sistema de gestión de una organización, no una herramienta. CertMate no está certificado con ISO 42001 y no puede certificar al operador; produce registros que el operador puede presentar como evidencia para sus propios controles.

---

## Límites honestos (no sobreinterprete estos puntos)

- **La clave de firma no vincula al operador.** Un bundle de exportación firmado (y los puntos de control firmados periódicos) permiten a un tercero verificar, fuera de la máquina, qué instancia produjo el registro y que no fue modificado — para cualquiera que **no** posea la clave de firma. Pero el operador posee la clave y podría re-firmar una cadena reescrita. Restringir completamente al operador requiere enviar los puntos de control firmados a un almacén externo de solo anexado (**anclaje externo opcional — una funcionalidad planificada, aún no disponible**). Trate la garantía actual como «autenticidad, ordenación y atribución a la instancia de las entradas registradas», verificable de forma independiente por un tercero que posea una copia firmada exportada.
- **Autenticidad, no exhaustividad.** Las escrituras de auditoría son de mejor esfuerzo y nunca bloquean una operación de certificado; la cadena prueba que las entradas registradas son auténticas y están ordenadas, y un `seq` interior faltante prueba una eliminación, pero una escritura que falló antes de ser registrada no deja ninguna entrada que verificar.
- **El truncado de cola necesita una referencia externa.** La eliminación de entradas del **final** de una sola cadena deja una cadena más corta pero internamente coherente que sigue verificándose como íntegra. Los puntos de control firmados y los bundles de exportación son los anclajes para detectar esto: una exportación firmada posterior con menos entradas que una anterior (o que un punto de control que posea un auditor) revela el truncado. Una exportación única no puede, por sí sola, probar que nada fue eliminado del final — conserve exportaciones firmadas sucesivas, o espere al anclaje externo opcional, si necesita esa garantía.
- **La cabecera de sesión del agente es una declaración del cliente.** Se registra para correlación, pero la suministra el cliente; la identidad de confianza es la clave de API autenticada.
- **Límite histórico.** La cadena comienza cuando la funcionalidad se activa por primera vez; el historial de `.log` anterior no forma parte de la cadena verificable.

Las exportaciones firmadas que un auditor externo puede vincular a una clave publicada están disponibles hoy. Si sus obligaciones requieren vincular al operador *en sí mismo* — de modo que incluso el titular de la clave no pueda reescribir el historial sin ser detectado — eso necesita el anclaje externo opcional de los puntos de control firmados a un almacén de solo anexado fuera de la máquina, que está planificado pero aún no disponible. Compruebe su estado antes de depender de él.

---

<div align="center">

[← Volver a la documentación](./README.md)

</div>
