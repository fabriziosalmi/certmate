# Testhandbuch

Dieses Handbuch beschreibt das Test-Framework von CertMate, einschließlich Unit-Tests, Integrationstests und der Validierung von API-Endpoints.

---

## Schnellstart

```bash
# Virtuelle Umgebung aktivieren
source .venv/bin/activate

# Testabhängigkeiten installieren
pip install -r requirements-test.txt

# Alle Tests ausführen
pytest

# Tests mit Coverage ausführen
pytest --cov=. --cov-report=html
```

---

## Teststruktur

```
Stammverzeichnis:
  conftest.py                              # Sammlungskonfiguration und gemeinsame Fixtures
  pytest.ini                               # Testkonfiguration und Marker
  test_certificate_creation.py             # Tests zur Zertifikatserstellung
  test_certificate_listing.py              # Tests zur Zertifikatsauflistung
  test_client_certificates_comprehensive.py # Lifecycle-Tests für Client-Zertifikate
  test_dns_accounts.py                     # Multi-Account-Operationen
  test_dns_provider.py                     # Grundlegende Provider-Funktionalität
  test_dns_provider_inheritance.py         # Konfigurationsvererbung
  test_domain_alias.py                     # Tests für Domain-Aliase
  test_infisical_backend.py               # Infisical-Storage-Backend
  test_shell_executor.py                   # Tests zur Shell-Ausführung
  test_e2e_complete.py                     # End-to-End-Test-Suite
```

---

## Tests ausführen

### Häufige Befehle

```bash
# Alle Tests ausführen
pytest

# Mit ausführlicher Ausgabe ausführen
pytest -v

# Eine bestimmte Testdatei ausführen
pytest test_certificate_creation.py

# Eine bestimmte Testfunktion ausführen
pytest test_certificate_creation.py::test_specific_function -v -s

# Tests nach einem Muster filtern
pytest -k "dns_provider"

# Mit Coverage-Bericht ausführen
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Mit Make

```bash
make test              # Alle Tests ausführen
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
eingeschränkte Netzwerke), kann die Suite auf eine bereits laufende Instanz gezeigt werden:

```bash
# Terminal 1: CertMate beliebig starten
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 app:app

# Terminal 2: auf diese Instanz zeigen (überspringt die gesamte Docker-Lifecycle-Verwaltung)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

Die Tests zur echten Zertifikatsausstellung benötigen zusätzlich `CLOUDFLARE_API_TOKEN` und eine
`CERTMATE_TEST_DOMAIN`, die Sie kontrollieren, und verbrauchen echte Let's Encrypt-Zertifikate —
sie werden automatisch übersprungen, wenn der Token fehlt. Die
Zielinstanz muss mit einem leeren Datenverzeichnis starten: E2E-Tests setzen
den Erstkonfigurationszustand voraus, sodass eine Wiederverwendung zwischen Läufen zu
authentifizierungsabhängigen Fehlern führt.

---

## API-Endpoint-Tests

### Schnelles Testskript

Verwenden Sie `quick_test.sh` für eine schnelle Endpoint-Validierung vor jedem Commit:

```bash
# Vor jedem Commit ausführen
./quick_test.sh

# Nur öffentliche Endpoints testen
./quick_test.sh --public-only
```

Dieses Skript:
- Prüft, ob der Server läuft
- Lädt den API-Token automatisch aus `data/settings.json`
- Testet alle Endpoint-Kategorien
- Liefert eine eindeutige Erfolg/Fehler-Ausgabe

### Vollständige API-Test-Suite

```bash
# Token automatisch aus den Einstellungen laden
python3 test_all_endpoints.py --auto-token

# Mit benutzerdefinierter Server-URL
python3 test_all_endpoints.py --url http://192.168.1.100:8000

# Mit manuellem API-Token
python3 test_all_endpoints.py --token your-api-bearer-token

# Schnelltest nur der wesentlichen Endpunkte
python3 test_all_endpoints.py --quick --auto-token

# Nur öffentliche Endpoints (keine Authentifizierung erforderlich)
python3 test_all_endpoints.py --public-only
```

### Getestete Endpoints

| Kategorie | Endpoints |
|-----------|-----------|
| **Health** | `GET /api/health`, `GET /health` |
| **Einstellungen** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Zertifikate** | `GET /api/certificates`, `POST /api/certificates/create`, download, renew |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Backup** | `GET /api/backups`, `POST /api/backups/create`, `POST /api/backups/cleanup` |
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

1. **Mehrere Python-Versionen**: Tests auf Python 3.9, 3.11, 3.12
2. **Codequalität**: Linting mit flake8
3. **Sicherheit**: Scanning mit bandit
4. **Tests**: Vollständige Test-Suite mit Coverage
5. **Docker**: Docker-Build testen
6. **Coverage**: Upload zu Codecov

### Pre-Commit-Hook

```bash
pip install pre-commit
pre-commit install
```

Hooks umfassen: Code-Formatierung (black, isort), Linting (flake8), Sicherheitsprüfungen (bandit).

### CI/CD-API-Tests

```yaml
# GitHub Actions-Beispiel
- name: Test API Endpoints
  run: |
    python app.py &
    sleep 5
    python3 test_all_endpoints.py --auto-token
```

---

## Coverage-Anforderungen

- Mindestens **80%** gesamte Code-Coverage
- Kritische Pfade müssen **95%+** Coverage aufweisen
- Alle neuen Funktionen müssen Tests enthalten

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
- Tests für „einfachen" Code weglassen

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
