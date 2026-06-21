# Guide de test

Ce guide couvre le framework de test de CertMate, incluant les tests unitaires, les tests d'intégration et la validation des endpoints API.

---

## Démarrage rapide

```bash
# Activer l'environnement virtuel
source .venv/bin/activate

# Installer les dépendances de test
pip install -r requirements-test.txt

# Exécuter tous les tests
pytest

# Exécuter les tests avec couverture
pytest --cov=. --cov-report=html
```

---

## Structure des tests

```
Répertoire racine :
  conftest.py                              # Configuration de collecte et fixtures partagées
  pytest.ini                               # Configuration et marqueurs de test
  test_certificate_creation.py             # Tests de création de certificats
  test_certificate_listing.py              # Tests de listage de certificats
  test_client_certificates_comprehensive.py # Tests de cycle de vie des certificats clients
  test_dns_accounts.py                     # Opérations multi-comptes
  test_dns_provider.py                     # Fonctionnalité de base des fournisseurs
  test_dns_provider_inheritance.py         # Héritage de configuration
  test_domain_alias.py                     # Tests d'alias de domaine
  test_infisical_backend.py               # Backend de stockage Infisical
  test_shell_executor.py                   # Tests d'exécution shell
  test_e2e_complete.py                     # Suite de tests de bout en bout
```

---

## Exécution des tests

### Commandes courantes

```bash
# Exécuter tous les tests
pytest

# Exécuter avec sortie verbose
pytest -v

# Exécuter un fichier de test spécifique
pytest test_certificate_creation.py

# Exécuter une fonction de test spécifique
pytest test_certificate_creation.py::test_specific_function -v -s

# Exécuter les tests correspondant à un motif
pytest -k "dns_provider"

# Exécuter avec rapport de couverture
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Avec Make

```bash
make test              # Exécuter tous les tests
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
réseaux restreints), pointez la suite vers une instance déjà en cours :

```bash
# Terminal 1 : lancez CertMate comme vous le souhaitez
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 app:app

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

### Script de test rapide

Utilisez `quick_test.sh` pour une validation rapide des endpoints avant chaque commit :

```bash
# Exécuter avant chaque commit
./quick_test.sh

# Tester uniquement les endpoints publics
./quick_test.sh --public-only
```

Ce script :
- Vérifie si le serveur est en cours d'exécution
- Charge automatiquement le token API depuis `data/settings.json`
- Teste toutes les catégories d'endpoints
- Fournit une sortie claire succès/échec

### Suite de tests API complète

```bash
# Chargement automatique du token depuis les paramètres
python3 test_all_endpoints.py --auto-token

# Avec URL serveur personnalisée
python3 test_all_endpoints.py --url http://192.168.1.100:8000

# Avec token API manuel
python3 test_all_endpoints.py --token votre-token-bearer-api

# Test rapide des essentiels uniquement
python3 test_all_endpoints.py --quick --auto-token

# Endpoints publics uniquement (aucune authentification requise)
python3 test_all_endpoints.py --public-only
```

### Endpoints testés

| Catégorie | Endpoints |
|-----------|-----------|
| **Santé** | `GET /api/health`, `GET /health` |
| **Paramètres** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Certificats** | `GET /api/certificates`, `POST /api/certificates/create`, download, renew |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Sauvegarde** | `GET /api/backups`, `POST /api/backups/create`, `POST /api/backups/cleanup` |
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

def test_nom_fonction(client, sample_settings):
    """Description du test."""
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
def test_avec_contexte_app(app):
    """Test qui nécessite le contexte de l'application."""
    with app.app_context():
        pass

def test_endpoint_api(client):
    """Test d'endpoint API."""
    response = client.get('/api/test')
    assert response.status_code == 200

def test_avec_donnees_mockees(mock_certificate_data):
    """Test avec des données mockées."""
    assert mock_certificate_data['domain'] == 'test.example.com'
```

### Simulation de services externes

```python
@patch('app.requests.get')
def test_api_externe(mock_get, client):
    """Test d'appel API externe."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Intégration continue

### GitHub Actions

Le pipeline CI s'exécute sur chaque push et pull request :

1. **Multiples versions Python** : Tests sur Python 3.9, 3.11, 3.12
2. **Qualité du code** : Linting avec flake8
3. **Sécurité** : Scan avec bandit
4. **Tests** : Suite complète avec couverture
5. **Docker** : Test de la construction Docker
6. **Couverture** : Envoi vers Codecov

### Hook Pre-Commit

```bash
pip install pre-commit
pre-commit install
```

Les hooks incluent : formatage de code (black, isort), linting (flake8), vérifications de sécurité (bandit).

### Tests API CI/CD

```yaml
# Exemple GitHub Actions
- name: Test des endpoints API
  run: |
    python app.py &
    sleep 5
    python3 test_all_endpoints.py --auto-token
```

---

## Exigences de couverture

- Minimum **80%** de couverture de code globale
- Les chemins critiques doivent avoir **95%+** de couverture
- Toute nouvelle fonctionnalité doit inclure des tests

---

## Bonnes pratiques

### À faire

- Écrivez des tests pour toutes les nouvelles fonctionnalités
- Utilisez des noms de tests descriptifs
- Testez les cas de succès ET d'échec
- Simulez les dépendances externes
- Utilisez les marqueurs de test appropriés
- Gardez les tests isolés et indépendants

### À ne pas faire

- Ne testez pas les détails d'implémentation
- N'utilisez pas de vraies clés API dans les tests
- Ne rendez pas les tests dépendants les uns des autres
- N'ignorez pas les échecs de test
- Ne sautez pas les tests pour du code "simple"

---

## Débogage des tests

```bash
# Verbose avec affichage print
pytest -v -s

# Déboguer un test spécifique
pytest test_api.py::test_specific -v -s

# Utiliser pdb
def test_debug_exemple():
    import pdb; pdb.set_trace()
    # Code de test ici
```

---

## Tests de performance

```python
import pytest
import concurrent.futures

@pytest.mark.slow
def test_charge_api(client):
    """Test de l'API sous charge."""
    def faire_requete():
        return client.get('/api/certificates')

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(faire_requete) for _ in range(100)]
        reponses = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in reponses)
```

---

## Codes de sortie

- **0** : Tous les tests ont réussi
- **1** : Certains tests ont échoué

---

<div align="center">

[← Retour à la documentation](./README.md) • [Architecture →](./architecture.md) • [Référence API →](./api.md)

</div>
