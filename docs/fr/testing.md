# Guide de test

<!-- CERTMATE-TRANSLATED-FROM e04070da6afc6acb -->

Ce guide couvre le framework de test de CertMate, incluant les tests unitaires, les tests d'intégration et la validation des endpoints API.

---

## Démarrage rapide

```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Installer les dépendances de test
pip install -r requirements-test.txt

# Exécuter tous les tests. L'expression de marqueurs n'est pas optionnelle : un `pytest`
# nu exécute aussi la suite Playwright `ui` dans ce processus et les tests `network`
# contre de vraies CA. CONTRIBUTING.md explique pourquoi.
pytest -m "not ui and not network"

# Exécuter les tests avec couverture
pytest --cov=modules --cov-report=html
```

---

## Structure des tests

```
Root directory:
  conftest.py                              # Oriente la collecte vers tests/
  pytest.ini                               # Configuration et marqueurs de test
  tests/
    conftest.py                            # Fixtures partagées
    test_*.py                              # Un fichier par comportement, nommé d'après lui
```

---

## Exécution des tests

### Commandes courantes

```bash
# Exécuter tous les tests. L'expression de marqueurs n'est pas optionnelle : un `pytest`
# nu exécute aussi la suite Playwright `ui` dans ce processus et les tests `network`
# contre de vraies CA. CONTRIBUTING.md explique pourquoi.
pytest -m "not ui and not network"

# Exécuter avec sortie verbose
pytest -v

# Exécuter un fichier de test spécifique
pytest tests/test_domain_alias.py

# Exécuter une fonction de test spécifique
pytest tests/test_domain_alias.py::test_domain_alias_all_core_providers_use_manual_hook -v -s

# Exécuter les tests correspondant à un motif
pytest -k "dns_provider"

# Exécuter avec rapport de couverture
pytest --cov=modules --cov-report=html
open htmlcov/index.html
```

### Avec Make

```bash
make test              # Tout sauf les suites ui et e2e
make test-unit         # Tests unitaires uniquement
make test-integration  # Tests d'intégration uniquement
make test-coverage     # Tests avec couverture
make check             # Toutes les vérifications qualité
```

---

## Catégories de tests

Les tests sont organisés avec des marqueurs pytest :

```bash
# Tests unitaires (rapides, sans services externes)
pytest -m "not integration and not slow"

# Tests d'intégration
pytest -m integration

# Tests API
pytest -m api

# Tests de fournisseurs DNS
pytest -m dns

# Tests de bout en bout (nécessitent un serveur en cours d'exécution)
pytest -m e2e
```

### E2E sans Docker

Par défaut, les fixtures e2e construisent l'image Docker et gèrent un conteneur
pour toute la session. Quand Docker n'est pas disponible (sandbox CI,
réseaux restreints), pointez la suite vers une instance déjà en cours d'exécution :

```bash
# Terminal 1 : lancez CertMate comme vous le souhaitez
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 --timeout 300 app:app

# Terminal 2 : ciblez cette instance (ignore toute la gestion du cycle de vie Docker)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

Les tests d'émission réelle nécessitent en plus `CLOUDFLARE_API_TOKEN` et un
`CERTMATE_TEST_DOMAIN` que vous contrôlez, et consomment de vrais certificats
Let's Encrypt — ils sont automatiquement ignorés quand le token est absent.
L'instance cible doit démarrer depuis un répertoire de données propre : les
tests e2e supposent un état de premier démarrage, donc une réutilisation entre
exécutions provoque des échecs liés à l'authentification.

---

## Tests des endpoints API

### Exécuter la suite de tests

La suite est pytest, répartie par marqueurs (voir `pytest.ini`) : `unit`,
`integration`, `api`, `dns`, `e2e` (nécessite un serveur en cours d'exécution), `ui`
(Playwright, nécessite un navigateur et un conteneur).

```bash
make test                # tout sauf les suites ui et e2e
make test-unit
make test-coverage       # --cov=modules, rapports HTML + XML

# Ou directement, par ex. tout ce qui n'a pas besoin d'un navigateur :
pytest -m "not ui"
pytest -m "not ui and not e2e" -q
```

La CI exécute `pytest -m "not ui and not network"` avec un plancher de couverture ; la suite
UI s'exécute dans son propre workflow, les vérifications d'accessibilité des CA s'exécutent
chaque semaine (en contrôle obligatoire, elles feraient passer chaque PR au rouge à cause de
la panne d'un tiers), et la porte de bout en bout avec de vrais certificats s'exécute contre
Let's Encrypt staging avant une release.

### Endpoints testés

| Catégorie | Endpoints |
|-----------|-----------|
| **Santé** | `GET /api/health`, `GET /health` |
| **Paramètres** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Certificats** | `GET /api/certificates`, `POST /api/certificates/create`, téléchargement, renouvellement |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Sauvegarde** | `GET /api/backups`, `POST /api/backups/create` |
| **Interface Web** | `/`, `/settings`, `/help`, `/docs/`, `/api/swagger.json` |

### Codes de statut attendus

- **200/201** : Succès
- **400/422** : Erreurs de validation attendues (normales pour les charges de test)
- **404** : Attendu pour les ressources inexistantes
- **401** : Token API invalide/manquant
- **500** : Bogue applicatif (à investiguer)

---

## Écrire des tests

### Structure de test

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

### Utilisation des fixtures

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

### Simulation de services externes

```python
@patch('app.requests.get')
def test_external_api(mock_get, client):
    """Test external API call."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Intégration continue

### GitHub Actions

Le pipeline CI s'exécute sur chaque push et pull request :

1. **Multiples versions Python** : Tests sur Python 3.12 et 3.14
2. **Qualité du code** : Linting avec flake8
3. **Sécurité** : Scan avec bandit
4. **Tests** : Suite complète avec couverture
5. **Docker** : Test de la construction Docker
6. **Couverture** : Envoi vers Codecov

### Avant de pousser

Ce dépôt n'a pas de configuration pre-commit ; exécutez les mêmes contrôles que la CI
exécute :

```bash
make lint      # flake8 (l'ensemble sur lequel la CI échoue) et les budgets de complexité et d'exceptions
make security  # bandit, sévérité moyenne et supérieure
make check     # lint + security + tests (la sélection exécutée par la porte de release)
make ci        # le job de tests de la CI : nécessite Docker et Node
```

Une release exécute bien davantage — voir `scripts/release.sh`, qui exige
flake8, bandit, les suites unitaires et d'intégration, la suite UI Playwright, un
vrai certificat émis contre Let's Encrypt staging et un build Docker.

---

## Exigences de couverture

- La CI impose un plancher de **75%** sur `modules/` (`--cov-fail-under`, un
  cliquet : à relever, jamais à abaisser pour faire passer un build). Le
  chiffre actuel est confortablement au-dessus.
- Toutes les nouvelles fonctionnalités doivent inclure des tests.

---

## Bonnes pratiques

### À faire

- Écrivez des tests pour toutes les nouvelles fonctionnalités
- Utilisez des noms de tests descriptifs
- Testez les cas de succès et d'échec
- Simulez les dépendances externes
- Utilisez les marqueurs de test appropriés
- Gardez les tests isolés et indépendants

### À ne pas faire

- Tester les détails d'implémentation
- Utiliser de vraies clés API dans les tests
- Rendre les tests dépendants les uns des autres
- Ignorer les échecs de test
- Se dispenser d'écrire des tests pour du code "simple"

---

## Débogage des tests

```bash
# Verbose avec affichage des print
pytest -v -s

# Déboguer un test spécifique
pytest test_api.py::test_specific -v -s

# Utiliser pdb
def test_debug_example():
    import pdb; pdb.set_trace()
    # Code de test ici
```

---

## Tests de performance

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

## Codes de sortie

- **0** : Tous les tests ont réussi
- **1** : Certains tests ont échoué

---

<div align="center">

[← Retour à la documentation](./README.md) • [Architecture →](./architecture.md) • [Référence API →](./api.md)

</div>
