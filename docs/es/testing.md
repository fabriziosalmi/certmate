# Guía de pruebas

Esta guía cubre el framework de pruebas de CertMate, incluyendo pruebas unitarias, pruebas de integración y validación de endpoints API.

---

## Inicio rápido

```bash
# Activar el entorno virtual
source .venv/bin/activate

# Instalar las dependencias de prueba
pip install -r requirements-test.txt

# Ejecutar todas las pruebas
pytest

# Ejecutar las pruebas con cobertura
pytest --cov=. --cov-report=html
```

---

## Estructura de las pruebas

```
Directorio raíz:
  conftest.py                              # Configuración de recolección y fixtures compartidas
  pytest.ini                               # Configuración y marcadores de prueba
  test_certificate_creation.py             # Pruebas de creación de certificados
  test_certificate_listing.py              # Pruebas de listado de certificados
  test_client_certificates_comprehensive.py # Pruebas de ciclo de vida de certificados cliente
  test_dns_accounts.py                     # Operaciones multi-cuenta
  test_dns_provider.py                     # Funcionalidad básica de proveedores
  test_dns_provider_inheritance.py         # Herencia de configuración
  test_domain_alias.py                     # Pruebas de alias de dominio
  test_infisical_backend.py               # Backend de almacenamiento Infisical
  test_shell_executor.py                   # Pruebas de ejecución shell
  test_e2e_complete.py                     # Suite de pruebas de extremo a extremo
```

---

## Ejecución de las pruebas

### Comandos comunes

```bash
# Ejecutar todas las pruebas
pytest

# Ejecutar con salida detallada
pytest -v

# Ejecutar un archivo de prueba específico
pytest test_certificate_creation.py

# Ejecutar una función de prueba específica
pytest test_certificate_creation.py::test_specific_function -v -s

# Ejecutar pruebas que coincidan con un patrón
pytest -k "dns_provider"

# Ejecutar con informe de cobertura
pytest --cov=. --cov-report=html
open htmlcov/index.html
```

### Con Make

```bash
make test              # Ejecutar todas las pruebas
make test-unit         # Solo pruebas unitarias
make test-integration  # Solo pruebas de integración
make test-coverage     # Pruebas con cobertura
make check             # Todas las verificaciones de calidad
```

---

## Categorías de pruebas

Las pruebas están organizadas con marcadores de pytest:

```bash
# Pruebas unitarias (rápidas, sin servicios externos)
pytest -m "not integration and not slow"

# Pruebas de integración
pytest -m integration

# Pruebas de API
pytest -m api

# Pruebas de proveedores DNS
pytest -m dns

# Pruebas de extremo a extremo (requieren servidor en ejecución)
pytest -m e2e
```

### E2E sin Docker

Por defecto, las fixtures e2e construyen la imagen Docker y gestionan un contenedor
para toda la sesión. Cuando Docker no está disponible (sandbox de CI,
redes restringidas), apunte la suite a una instancia ya en ejecución:

```bash
# Terminal 1: ejecute CertMate como prefiera
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 app:app

# Terminal 2: apunte a esa instancia (omite toda la gestión del ciclo de vida Docker)
CERTMATE_E2E_BASE_URL=http://localhost:18888 pytest -m "e2e and not ui"
```

Las pruebas de emisión real necesitan además `CLOUDFLARE_API_TOKEN` y un
`CERTMATE_TEST_DOMAIN` que usted controle, y consumen certificados reales de
Let's Encrypt — se omiten automáticamente cuando el token no está presente. La
instancia destino debe arrancar desde un directorio de datos limpio: las pruebas
e2e asumen un estado de primer arranque, por lo que reutilizarla entre ejecuciones
provoca fallos relacionados con la autenticación.

---

## Pruebas de endpoints API

### Script de prueba rápida

Use `quick_test.sh` para una validación rápida de endpoints antes de cada commit:

```bash
# Ejecutar antes de cada commit
./quick_test.sh

# Probar solo los endpoints públicos
./quick_test.sh --public-only
```

Este script:
- Comprueba si el servidor está en ejecución
- Carga automáticamente el token API desde `data/settings.json`
- Prueba todas las categorías de endpoints
- Proporciona una salida clara de éxito/fallo

### Suite de pruebas API completa

```bash
# Carga automática del token desde los ajustes
python3 test_all_endpoints.py --auto-token

# Con URL de servidor personalizada
python3 test_all_endpoints.py --url http://192.168.1.100:8000

# Con token API manual
python3 test_all_endpoints.py --token your-api-bearer-token

# Prueba rápida solo de lo esencial
python3 test_all_endpoints.py --quick --auto-token

# Solo endpoints públicos (sin autenticación requerida)
python3 test_all_endpoints.py --public-only
```

### Endpoints probados

| Categoría | Endpoints |
|-----------|-----------|
| **Salud** | `GET /api/health`, `GET /health` |
| **Ajustes** | `GET /api/settings`, `GET /api/settings/dns-providers`, `POST /api/settings` |
| **Certificados** | `GET /api/certificates`, `POST /api/certificates/create`, download, renew |
| **Cache** | `GET /api/cache/stats`, `POST /api/cache/clear` |
| **Copia de seguridad** | `GET /api/backups`, `POST /api/backups/create`, `POST /api/backups/cleanup` |
| **Interfaz web** | `/`, `/settings`, `/help`, `/docs/`, `/api/swagger.json` |

### Códigos de estado esperados

- **200/201**: Éxito
- **400/422**: Errores de validación esperados (normales para payloads de prueba)
- **404**: Esperado para recursos inexistentes
- **401**: Token API inválido o ausente
- **500**: Error de la aplicación (investigar)

---

## Escritura de pruebas

### Estructura de prueba

```python
import pytest
from unittest.mock import patch, MagicMock

def test_function_name(client, sample_settings):
    """Descripción del test."""
    # Arrange
    setup_data = {...}

    # Act
    response = client.get('/api/endpoint')

    # Assert
    assert response.status_code == 200
    assert 'expected_key' in response.json()
```

### Uso de fixtures

```python
def test_with_app_context(app):
    """Prueba que requiere contexto de la aplicación."""
    with app.app_context():
        pass

def test_api_endpoint(client):
    """Prueba de endpoint API."""
    response = client.get('/api/test')
    assert response.status_code == 200

def test_with_mock_data(mock_certificate_data):
    """Prueba con datos simulados."""
    assert mock_certificate_data['domain'] == 'test.example.com'
```

### Simulación de servicios externos

```python
@patch('app.requests.get')
def test_external_api(mock_get, client):
    """Prueba de llamada a API externa."""
    mock_get.return_value.json.return_value = {'status': 'success'}
    response = client.post('/api/certificate/request')
    assert response.status_code == 200
```

---

## Integración continua

### GitHub Actions

El pipeline de CI se ejecuta en cada push y pull request:

1. **Múltiples versiones de Python**: Pruebas en Python 3.9, 3.11, 3.12
2. **Calidad de código**: Linting con flake8
3. **Seguridad**: Escaneo con bandit
4. **Pruebas**: Suite completa con cobertura
5. **Docker**: Prueba del build de Docker
6. **Cobertura**: Envío a Codecov

### Hook Pre-Commit

```bash
pip install pre-commit
pre-commit install
```

Los hooks incluyen: formateo de código (black, isort), linting (flake8), verificaciones de seguridad (bandit).

### Pruebas de API en CI/CD

```yaml
# Ejemplo de GitHub Actions
- name: Test API Endpoints
  run: |
    python app.py &
    sleep 5
    python3 test_all_endpoints.py --auto-token
```

---

## Requisitos de cobertura

- Mínimo **80%** de cobertura de código global
- Las rutas críticas deben tener **95%+** de cobertura
- Toda nueva funcionalidad debe incluir pruebas

---

## Buenas prácticas

### Hacer

- Escribir pruebas para todas las nuevas funcionalidades
- Usar nombres de prueba descriptivos
- Probar tanto los casos de éxito como los de fallo
- Simular las dependencias externas
- Usar los marcadores de prueba adecuados
- Mantener las pruebas aisladas e independientes

### No hacer

- Probar detalles de implementación
- Usar claves API reales en las pruebas
- Hacer que las pruebas dependan unas de otras
- Ignorar los fallos de prueba
- Omitir pruebas para código "simple"

---

## Depuración de pruebas

```bash
# Detallado con sentencias print
pytest -v -s

# Depurar una prueba específica
pytest test_api.py::test_specific -v -s

# Usar pdb
def test_debug_example():
    import pdb; pdb.set_trace()
    # Código de prueba aquí
```

---

## Pruebas de rendimiento

```python
import pytest
import concurrent.futures

@pytest.mark.slow
def test_api_load(client):
    """Prueba de la API bajo carga."""
    def make_request():
        return client.get('/api/certificates')

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_request) for _ in range(100)]
        responses = [f.result() for f in futures]

    assert all(r.status_code == 200 for r in responses)
```

---

## Códigos de salida

- **0**: Todas las pruebas superadas
- **1**: Algunas pruebas han fallado

---

<div align="center">

[← Volver a la documentación](./README.md) • [Arquitectura →](./architecture.md) • [Referencia de API →](./api.md)

</div>
