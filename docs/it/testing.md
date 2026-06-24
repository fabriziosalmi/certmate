# Guida ai test

Questa guida descrive il framework di test di CertMate, inclusi unit test, test di integrazione e la validazione degli endpoint API.

---

## Avvio rapido

```bash
# Attivare l'ambiente virtuale
source .venv/bin/activate

# Installare le dipendenze di test
pip install -r requirements-test.txt

# Eseguire tutti i test
pytest

# Eseguire i test con la copertura
pytest --cov=. --cov-report=html
```

---

## Struttura dei test

```
Directory radice:
  conftest.py                              # Configurazione della raccolta e fixture condivise
  pytest.ini                               # Configurazione e marcatori di test
  test_certificate_creation.py             # Test di creazione dei certificati
  test_certificate_listing.py              # Test di elenco dei certificati
  test_client_certificates_comprehensive.py # Test del ciclo di vita dei certificati client
  test_dns_accounts.py                     # Operazioni multi-account
  test_dns_provider.py                     # Funzionalità di base dei provider
  test_dns_provider_inheritance.py         # Ereditarietà della configurazione
  test_domain_alias.py                     # Test degli alias di dominio
  test_infisical_backend.py               # Backend di archiviazione Infisical
  test_shell_executor.py                   # Test di esecuzione shell
  test_e2e_complete.py                     # Suite di test end-to-end
```

---

## Esecuzione dei test

### Comandi comuni

```bash
# Eseguire tutti i test
pytest

# Eseguire con output dettagliato
pytest -v

# Eseguire un file di test specifico
pytest test_certificate_creation.py

# Eseguire una funzione di test specifica
pytest test_certificate_creation.py::test_specific_function -v -s

# Eseguire i test corrispondenti a un pattern
pytest -k "dns_provider"

# Eseguire con rapporto di copertura
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Con Make

```bash
make test              # Eseguire tutti i test
make test-unit         # Solo unit test
make test-integration  # Solo test di integrazione
make test-coverage     # Test con copertura
make check             # Tutte le verifiche qualità
```

---

## Categorie di test

I test sono organizzati con i marcatori pytest:

```bash
# Unit test (veloci, senza servizi esterni)
pytest -m "not integration and not slow"

# Test di integrazione
pytest -m integration

# Test API
pytest -m api

# Test dei provider DNS
pytest -m dns

# Test end-to-end (richiedono un server in esecuzione)
pytest -m e2e
```

### E2E senza Docker

Per impostazione predefinita, le fixture e2e costruiscono l'immagine Docker e gestiscono un container
per tutta la sessione. Quando Docker non è disponibile (sandbox CI,
reti con restrizioni), puntare la suite su un'istanza già in esecuzione:

```bash
# Terminale 1: avviare CertMate come si preferisce
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 app:app

# Terminale 2: puntare all'istanza (ignora tutta la gestione del ciclo di vita Docker)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

I test di emissione reale richiedono inoltre `CLOUDFLARE_API_TOKEN` e un
`CERTMATE_TEST_DOMAIN` sotto il proprio controllo, e consumano certificati
Let's Encrypt reali — vengono ignorati automaticamente quando il token è assente.
L'istanza di destinazione deve avviarsi da una directory dati pulita: i test e2e
presuppongono uno stato di primo avvio, quindi il riutilizzo tra esecuzioni provoca
errori legati all'autenticazione.

---

## Test degli endpoint API

### Script di test rapido

Usare `quick_test.sh` per una validazione rapida degli endpoint prima di ogni commit:

```bash
# Eseguire prima di ogni commit
./quick_test.sh

# Testare solo gli endpoint pubblici
./quick_test.sh --public-only
```

Questo script:
- Verifica se il server è in esecuzione
- Carica automaticamente il token API da `data/settings.json`
- Testa tutte le categorie di endpoint
- Fornisce un output chiaro di successo/fallimento

### Suite di test API completa

```bash
# Caricamento automatico del token dalle impostazioni
python3 test_all_endpoints.py --auto-token

# Con URL del server personalizzato
python3 test_all_endpoints.py --url http://192.168.1.100:8000

# Con token API manuale
python3 test_all_endpoints.py --token your-api-bearer-token

# Test rapido degli elementi essenziali soltanto
python3 test_all_endpoints.py --quick --auto-token

# Solo endpoint pubblici (nessuna autenticazione richiesta)
python3 test_all_endpoints.py --public-only
```

### Endpoint testati

| Categoria | Endpoint |
|-----------|----------|
| **Salute** | `GET /api/health`, `GET /health` |
| **Impostazioni** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Certificati** | `GET /api/certificates`, `POST /api/certificates/create`, download, renew |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Backup** | `GET /api/backups`, `POST /api/backups/create`, `POST /api/backups/cleanup` |
| **Interfaccia Web** | `/`, `/settings`, `/help`, `/docs/`, `/api/swagger.json` |

### Codici di stato attesi

- **200/201**: Successo
- **400/422**: Errori di validazione attesi (normali per i payload di test)
- **404**: Atteso per risorse inesistenti
- **401**: Token API non valido o assente
- **500**: Bug dell'applicazione (da investigare)

---

## Scrittura dei test

### Struttura di un test

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

### Utilizzo delle fixture

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

### Simulazione di servizi esterni

```python
@patch('app.requests.get')
def test_external_api(mock_get, client):
    """Test external API call."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Integrazione continua

### GitHub Actions

La pipeline CI viene eseguita ad ogni push e pull request:

1. **Versioni Python multiple**: Test su Python 3.9, 3.11, 3.12
2. **Qualita del codice**: Linting con flake8
3. **Sicurezza**: Scansione con bandit
4. **Test**: Suite completa con copertura
5. **Docker**: Test della build Docker
6. **Copertura**: Caricamento su Codecov

### Hook Pre-Commit

```bash
pip install pre-commit
pre-commit install
```

Gli hook includono: formattazione del codice (black, isort), linting (flake8), verifiche di sicurezza (bandit).

### Test API CI/CD

```yaml
# Esempio GitHub Actions
- name: Test API Endpoints
  run: |
    python app.py &
    sleep 5
    python3 test_all_endpoints.py --auto-token
```

---

## Requisiti di copertura

- Minimo **80%** di copertura del codice complessiva
- I percorsi critici devono avere una copertura **95%+**
- Tutte le nuove funzionalita devono includere test

---

## Buone pratiche

### Da fare

- Scrivere test per tutte le nuove funzionalita
- Usare nomi di test descrittivi
- Testare sia i casi di successo che quelli di fallimento
- Simulare le dipendenze esterne
- Usare i marcatori di test appropriati
- Mantenere i test isolati e indipendenti

### Da non fare

- Non testare i dettagli di implementazione
- Non usare chiavi API reali nei test
- Non rendere i test dipendenti gli uni dagli altri
- Non ignorare i fallimenti dei test
- Non saltare la scrittura di test per il codice "semplice"

---

## Debug dei test

```bash
# Output dettagliato con istruzioni print
pytest -v -s

# Debug di un test specifico
pytest test_api.py::test_specific -v -s

# Utilizzo di pdb
def test_debug_example():
    import pdb; pdb.set_trace()
    # Test code here
```

---

## Test di prestazioni

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

## Codici di uscita

- **0**: Tutti i test superati
- **1**: Alcuni test falliti

---

<div align="center">

[← Torna alla documentazione](./README.md) • [Architettura →](./architecture.md) • [Riferimento API →](./api.md)

</div>
