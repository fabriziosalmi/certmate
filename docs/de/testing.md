# Testhandbuch

<!-- CERTMATE-TRANSLATED-FROM e04070da6afc6acb -->

Dieses Handbuch beschreibt das Test-Framework von CertMate, einschließlich Unit-Tests, Integrationstests und der Validierung von API-Endpoints.

---

## Schnellstart

```bash
# Virtuelle Umgebung aktivieren
source .venv/bin/activate

# Testabhängigkeiten installieren
pip install -r requirements-test.txt

# Alle Tests ausführen. Der Marker-Ausdruck ist nicht optional: ein bloßes
# `pytest` führt in diesem Prozess auch die Playwright-`ui`-Suite und die
# `network`-Tests gegen echte CAs aus. CONTRIBUTING.md erklärt, warum.
pytest -m "not ui and not network"

# Tests mit Coverage ausführen
pytest --cov=modules --cov-report=html
```

---

## Teststruktur

```
Root directory:
  conftest.py                              # Richtet die Sammlung auf tests/ aus
  pytest.ini                               # Testkonfiguration und Marker
  tests/
    conftest.py                            # Gemeinsame Fixtures
    test_*.py                              # Eine Datei pro Verhalten, nach ihm benannt
```

---

## Tests ausführen

### Häufige Befehle

```bash
# Alle Tests ausführen. Der Marker-Ausdruck ist nicht optional: ein bloßes
# `pytest` führt in diesem Prozess auch die Playwright-`ui`-Suite und die
# `network`-Tests gegen echte CAs aus. CONTRIBUTING.md erklärt, warum.
pytest -m "not ui and not network"

# Mit ausführlicher Ausgabe ausführen
pytest -v

# Eine bestimmte Testdatei ausführen
pytest tests/test_domain_alias.py

# Eine bestimmte Testfunktion ausführen
pytest tests/test_domain_alias.py::test_domain_alias_all_core_providers_use_manual_hook -v -s

# Tests ausführen, die einem Muster entsprechen
pytest -k "dns_provider"

# Mit Coverage-Bericht ausführen
pytest --cov=modules --cov-report=html
open htmlcov/index.html
```

### Mit Make

```bash
make test              # Alles außer der ui- und der e2e-Suite
make test-unit         # Nur Unit-Tests
make test-integration  # Nur Integrationstests
make test-coverage     # Tests mit Coverage
make check             # Alle Qualitätsprüfungen
```

---

## Testkategorien

Tests sind mit pytest-Markern organisiert:

```bash
# Unit-Tests (schnell, ohne externe Dienste)
pytest -m "not integration and not slow"

# Integrationstests
pytest -m integration

# API-Tests
pytest -m api

# DNS-Provider-Tests
pytest -m dns

# End-to-End-Tests (erfordern einen laufenden Server)
pytest -m e2e
```

### E2E ohne Docker

Standardmäßig bauen die E2E-Fixtures das Docker-Image und verwalten einen Container
für die gesamte Sitzung. Wenn Docker nicht verfügbar ist (CI-Sandboxes,
eingeschränkte Netzwerke), richten Sie die Suite auf eine bereits laufende Instanz aus:

```bash
# Terminal 1: CertMate beliebig starten
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 --timeout 300 app:app

# Terminal 2: diese Instanz als Ziel verwenden (überspringt die gesamte Docker-Lifecycle-Verwaltung)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

Die Tests mit echter Zertifikatsausstellung benötigen zusätzlich `CLOUDFLARE_API_TOKEN` und eine
`CERTMATE_TEST_DOMAIN`, die Sie kontrollieren, und verbrauchen echte Let's-Encrypt-Zertifikate —
sie werden automatisch übersprungen, wenn der Token fehlt. Die
Zielinstanz muss mit einem sauberen Datenverzeichnis starten: E2E-Tests setzen
den Zustand beim ersten Start voraus, sodass eine Wiederverwendung über mehrere Läufe hinweg zu
authentifizierungsabhängigen Fehlern führt.

---

## API-Endpoint-Tests

### Test-Suite ausführen

Die Suite basiert auf pytest und ist nach Markern aufgeteilt (siehe `pytest.ini`): `unit`,
`integration`, `api`, `dns`, `e2e` (benötigt einen laufenden Server), `ui`
(Playwright, benötigt einen Browser und einen Container).

```bash
make test                # alles außer der ui- und der e2e-Suite
make test-unit
make test-coverage       # --cov=modules, HTML- und XML-Berichte

# Oder direkt, z. B. alles, was keinen Browser braucht:
pytest -m "not ui"
pytest -m "not ui and not e2e" -q
```

Die CI führt `pytest -m "not ui and not network"` mit einer Coverage-Untergrenze aus; die UI-Suite
läuft in einem eigenen Workflow, die CA-Erreichbarkeitsprüfungen laufen nach einem wöchentlichen
Zeitplan (als Pflichtprüfung würden sie jeden PR wegen des Ausfalls eines Dritten rot färben),
und das End-to-End-Gate mit echten Zertifikaten läuft vor einem Release gegen Let's Encrypt Staging.

### Getestete Endpoints

| Kategorie | Endpoints |
|-----------|-----------|
| **Health** | `GET /api/health`, `GET /health` |
| **Einstellungen** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Zertifikate** | `GET /api/certificates`, `POST /api/certificates/create`, Download, Erneuerung |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Backup** | `GET /api/backups`, `POST /api/backups/create` |
| **Web-Interface** | `/`, `/settings`, `/help`, `/docs/`, `/api/swagger.json` |

### Erwartete Statuscodes

- **200/201**: Erfolg
- **400/422**: Erwartete Validierungsfehler (normal für Test-Payloads)
- **404**: Erwartet für nicht vorhandene Ressourcen
- **401**: Ungültiger/fehlender API-Token
- **500**: Anwendungsfehler (untersuchen)

---

## Tests schreiben

### Teststruktur

```python
import pytest
from unittest.mock import patch, MagicMock

def test_function_name(client, sample_settings):
    """Test description."""
    # Arrange
    setup_data = {...}

    # Act
    response = client.get('/api/endpoint')

    # Assert
    assert response.status_code == 200
    assert 'expected_key' in response.json()
```

### Fixtures verwenden

```python
def test_with_app_context(app):
    """Test that requires app context."""
    with app.app_context():
        pass

def test_api_endpoint(client):
    """Test API endpoint."""
    response = client.get('/api/test')
    assert response.status_code == 200

def test_with_mock_data(mock_certificate_data):
    """Test with mock data."""
    assert mock_certificate_data['domain'] == 'test.example.com'
```

### Externe Dienste mocken

```python
@patch('app.requests.get')
def test_external_api(mock_get, client):
    """Test external API call."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Kontinuierliche Integration

### GitHub Actions

Die CI-Pipeline läuft bei jedem Push und Pull Request:

1. **Mehrere Python-Versionen**: Tests auf Python 3.12 und 3.14
2. **Codequalität**: Linting mit flake8
3. **Sicherheit**: Scanning mit bandit
4. **Tests**: Vollständige Test-Suite mit Coverage
5. **Docker**: Docker-Build testen
6. **Coverage**: Upload zu Codecov

### Vor dem Push

In diesem Repository gibt es keine Pre-Commit-Konfiguration; führen Sie dieselben Gates aus,
die auch die CI ausführt:

```bash
make lint      # flake8 (die Prüfungen, an denen die CI scheitert) und die Komplexitäts- und Ausnahmebudgets
make security  # bandit, mittlere Schwere und höher
make check     # lint + security + Tests (die Auswahl, die das Release-Gate ausführt)
make ci        # der CI-Testjob: benötigt Docker und Node
```

Ein Release führt deutlich mehr aus — siehe `scripts/release.sh`, das als Gates
flake8, bandit, die Unit- und Integrations-Suites, die Playwright-UI-Suite, ein
echtes gegen Let's Encrypt Staging ausgestelltes Zertifikat und einen Docker-Build verwendet.

---

## Coverage-Anforderungen

- Die CI erzwingt eine Untergrenze von **75%** über `modules/` (`--cov-fail-under`, eine Ratsche
  — anheben, niemals senken, damit ein Build durchgeht). Der aktuelle Wert liegt
  komfortabel darüber.
- Alle neuen Funktionen müssen Tests enthalten.

---

## Best Practices

### Empfohlen

- Tests für alle neuen Funktionen schreiben
- Beschreibende Testnamen verwenden
- Sowohl Erfolgs- als auch Fehlerfälle testen
- Externe Abhängigkeiten mocken
- Passende Test-Marker verwenden
- Tests isoliert und unabhängig halten

### Nicht empfohlen

- Implementierungsdetails testen
- Echte API-Keys in Tests verwenden
- Tests voneinander abhängig machen
- Testfehler ignorieren
- Tests für „einfachen“ Code weglassen

---

## Tests debuggen

```bash
# Ausführlich mit Print-Ausgaben
pytest -v -s

# Bestimmten Test debuggen
pytest test_api.py::test_specific -v -s

# pdb verwenden
def test_debug_example():
    import pdb; pdb.set_trace()
    # Test code here
```

---

## Performance-Tests

```python
import pytest
import concurrent.futures

@pytest.mark.slow
def test_api_load(client):
    """Test API under load."""
    def make_request():
        return client.get('/api/certificates')

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(100)]
        responses = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in responses)
```

---

## Exit-Codes

- **0**: Alle Tests bestanden
- **1**: Einige Tests fehlgeschlagen

---

<div align="center">

[← Zurück zur Dokumentation](./README.md) • [Architektur →](./architecture.md) • [API-Referenz →](./api.md)

</div>
