# Compliance und Audit-Trail

Diese Seite ordnet den Audit-Trail von CertMate den Regelwerken zu, nach denen Betreiber am häufigsten fragen — dem EU AI Act, NIS2 und ISO/IEC 42001 — wenn sie einen KI/MCP-Agenten Zertifikate nach einem Zeitplan verwalten lassen.

> **Zuerst lesen.** CertMate ist ein selbst gehostetes MIT-Tool für Einzelinstanzen. Es ist **kein** KI-System, **kein** KI-System mit hohem Risiko und **keine** regulierte Einheit, und es „erfüllt" oder „zertifiziert" nichts. Die Compliance-Pflichten liegen beim **Betreiber**, der es einsetzt. Was CertMate bereitstellt, sind **Nachweisartefakte**, die ein Betreiber für *seine eigenen* Verpflichtungen nutzen kann. Jede Aussage unten bedeutet „versetzt den Betreiber in die Lage, X nachzuweisen", mit den ausdrücklich genannten Einschränkungen.

---

## Was der Audit-Trail heute bietet

- **Attribution.** Jede Aktion im Zertifikatslebenszyklus — Erstellen, Erneuern, Neuausstellen, Deploy, Umschalten der automatischen Erneuerung und unbeaufsichtigte geplante Erneuerungen — wird mit einem strukturierten `actor` (Mensch vs. API-Token vs. KI-Agent, bis zur API-Key-ID) und einem `trigger` (manuell, API, Agent oder Scheduler-Job) aufgezeichnet. Die Aktionen eines KI-Agenten sind von denen eines Menschen unterscheidbar, sofern der Agent einen mit `is_agent` gekennzeichneten Schlüssel verwendet. Siehe [API: Audit Logging](./api.md#audit-logging) und den [MCP-Leitfaden](./mcp.md#audit-attribution).
- **Manipulationsnachweis.** Einträge werden in eine append-only SHA-256-Hash-Kette geschrieben (`data/audit/certificate_audit.chain.jsonl`). Jede Änderung, Löschung oder Umordnung durch jemanden, der die Kette nicht neu berechnen kann, ist erkennbar und lokalisierbar.
- **Unabhängige Verifizierung.** Ein eigenständiger Verifier (`python -m modules.core.audit_verify`) berechnet die Kette neu und liefert PASS/FAIL, ohne CertMate ausführen oder ihm vertrauen zu müssen; `GET /api/audit/verify` stellt dieselbe Prüfung über die API bereit.
- **Signierter, durch Dritte verifizierbarer Export.** Die Instanz signiert den Kettenanfang (periodische Checkpoints), und `GET /api/audit/export` erzeugt ein Ed25519-signiertes Bundle. Ein Auditor verifiziert es außerhalb der Maschine und pinnt dabei den öffentlichen Schlüssel der Instanz (`GET /api/audit/public-key`) out-of-band — was beweist, dass der Eintrag nicht bearbeitet wurde und welche Instanz ihn erzeugt hat.

---

## Zuordnung zu Regelwerken

### NIS2 (Richtlinie (EU) 2022/2555) — die stärkste Übereinstimmung

- **Wobei es hilft.** Zertifikatsoperationen verändern die Vertrauensposition von Diensten und sind daher sicherheitsrelevante Ereignisse. CertMate erzeugt einen manipulationssicheren, attribuierten, zeitgestempelten Nachweis jeder solchen Operation sowie eine unabhängig verifizierbare Prüfung — nutzbar als Teil der Protokollierungs- (Art. 21) und Vorfallsnachweispraktiken (Art. 23) des Betreibers.
- **Einschränkung.** NIS2 verpflichtet wesentliche/wichtige **Einrichtungen**, nicht Software-Tools. CertMate liefert Protokolle und einen Verifier, den der Betreiber nutzen kann; es bewertet, überwacht oder meldet keine Vorfälle, und die Eigenschaft, eine einbezogene Einrichtung zu sein (und NIS2 vollständig zu erfüllen), liegt in der Verantwortung des Betreibers.

### EU AI Act — Artikel 50 Transparenz (nur im Geiste; die schwächste Übereinstimmung)

- **Wobei es hilft.** Wenn ein KI-Agent autonom PKI-Aufgaben übernimmt, trägt der Eintrag einen expliziten `actor.kind="agent"`-Marker sowie die Agent-Session, sodass der Betreiber im Nachhinein nachweisen kann, welche Änderungen von einem KI-Agenten gegenüber einem Menschen vorgenommen wurden, unter welcher Identität und was sie ausgelöst hat — was den Transparenz- und Menschenaufsichtsgeist des Gesetzes unterstützt.
- **Einschränkung.** Die Pflichten aus Art. 50 liegen bei **Anbietern/Betreibern von KI-Systemen** und betreffen die Offenlegung gegenüber natürlichen Personen, die mit KI interagieren. Ein Agent, der TLS-Zertifikate erneuert, ist kein Lehrbuchfall von Art. 50, und CertMate ist ein Tool, kein KI-System. Wir beziehen uns nur auf den Transparenzgeist; CertMate erfüllt Art. 50 **nicht** für irgendjemanden.

### ISO/IEC 42001 (KI-Managementsystem) — operative Aufzeichnungen

- **Wobei es hilft.** Die attribuierten, manipulationssicheren Aufzeichnungen sind objektive Nachweise, dass ein KI-Agent bestimmte Zertifikatsaktionen durchgeführt hat — nutzbar für die operativen Aufzeichnungs- und Rückverfolgbarkeitskontrollen des eigenen AIMS des Betreibers.
- **Einschränkung.** ISO 42001 zertifiziert das Managementsystem einer Organisation, nicht ein Tool. CertMate ist nicht nach ISO 42001 zertifiziert und kann den Betreiber nicht zertifizieren; es erzeugt Aufzeichnungen, die der Betreiber als Nachweis für seine eigenen Kontrollen vorlegen kann.

---

## Ehrliche Einschränkungen (nicht überinterpretieren)

- **Der Signierschlüssel bindet den Betreiber nicht.** Ein signiertes Export-Bundle (und die periodischen signierten Checkpoints) ermöglichen es einem Dritten, außerhalb der Maschine zu verifizieren, welche Instanz den Eintrag erzeugt hat und dass er nicht bearbeitet wurde — für jeden, der den Signierschlüssel **nicht** besitzt. Aber der Betreiber besitzt den Schlüssel und könnte eine neu geschriebene Kette erneut signieren. Die vollständige Bindung des Betreibers erfordert das Versenden der signierten Checkpoints an eine externe append-only-Senke (**opt-in-externes Anchoring — eine geplante Folgefunktion, noch nicht ausgeliefert**). Betrachten Sie die aktuelle Garantie als „Authentizität, Reihenfolge und Instanzattribution der aufgezeichneten Einträge", unabhängig verifizierbar durch einen Dritten, der eine exportierte, signierte Kopie besitzt.
- **Authentizität, nicht Vollständigkeit.** Audit-Schreibvorgänge erfolgen nach bestem Bemühen und blockieren niemals eine Zertifikatsoperation; die Kette beweist, dass die aufgezeichneten Einträge authentisch und geordnet sind, und ein fehlendes inneres `seq` beweist eine Löschung, aber ein Schreibvorgang, der fehlgeschlagen ist, bevor er aufgezeichnet wurde, hinterlässt keinen Eintrag zur Verifizierung.
- **Tail-Trunkierung erfordert eine externe Referenz.** Das Entfernen von Einträgen am **Ende** einer einzelnen Kette hinterlässt eine kürzere, aber intern konsistente Kette, die weiterhin als intakt verifiziert wird. Die signierten Checkpoints und Export-Bundles sind die Ankerpunkte, um dies zu erkennen: ein späterer signierter Export mit weniger Einträgen als ein früherer (oder als ein Checkpoint, den ein Auditor besitzt) enthüllt die Trunkierung. Ein einzelner In-place-Export kann allein nicht beweisen, dass am Ende nichts entfernt wurde — bewahren Sie aufeinanderfolgende signierte Exporte auf, oder warten Sie auf das opt-in externe Anchoring, wenn Sie diese Garantie benötigen.
- **Der Agent-Session-Header ist eine Angabe des Clients.** Er wird zur Korrelation aufgezeichnet, wird aber vom Client geliefert; die vertrauenswürdige Identität ist der authentifizierte API-Schlüssel.
- **Historische Grenze.** Die Kette beginnt, wenn die Funktion erstmals aktiviert wird; älterer `.log`-Verlauf ist nicht Teil der verifizierbaren Kette.

Signierte Exporte, die ein externer Auditor an einen veröffentlichten Schlüssel pinnen kann, sind heute verfügbar. Wenn Ihre Verpflichtungen erfordern, den Betreiber *selbst* zu binden — sodass auch der Schlüsselinhaber die Geschichte nicht unentdeckt umschreiben kann — ist dafür das opt-in externe Anchoring der signierten Checkpoints an eine append-only-Senke außerhalb der Maschine erforderlich, das geplant, aber noch nicht ausgeliefert ist. Verfolgen Sie dessen Entwicklung, bevor Sie sich darauf verlassen.

---

<div align="center">

[← Zurück zur Dokumentation](./README.md)

</div>
