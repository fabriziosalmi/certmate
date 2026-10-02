# Guía de pruebas

<!-- CERTMATE-TRANSLATED-FROM 7cc7e1b319fd54bc -->

Esta guía cubre el framework de pruebas de CertMate, incluyendo pruebas unitarias, pruebas de integración y validación de endpoints API.

---

## Inicio rápido

```bash
# Activar el entorno virtual
source .venv/bin/activate

# Instalar las dependencias de prueba
pip install -r requirements-test.txt

# Ejecutar todas las pruebas. La expresión de marcadores no es opcional:
# un `pytest` a secas ejecuta también la suite Playwright `ui` en este
# proceso y las pruebas `network` contra CA reales.
pytest -m "not ui and not network"

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
# Ejecutar todas las pruebas. La expresión de marcadores no es opcional:
# un `pytest` a secas ejecuta también la suite Playwright `ui` en este
# proceso y las pruebas `network` contra CA reales.
pytest -m "not ui and not network"

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
gunicorn --bind 127.0.0.1:18888 --workers 1 --threads 8 --timeout 300 app:app

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

### Ejecutar la suite de pruebas

La suite es pytest, dividida por marcadores (véase `pytest.ini`): `unit`, `integration`, `api`, `dns`, `e2e` (requiere un servidor en ejecución), `ui` (Playwright, requiere un navegador y un contenedor).

```bash
make test                # unitarias + integración
make test-unit
make test-coverage       # --cov=modules, informes HTML y XML

# O directamente, p. ej. todo lo que no necesita navegador:
pytest -m "not ui"
pytest -m "not ui and not e2e" -q
```

La CI ejecuta `pytest -m "not ui and not network"` con un mínimo de cobertura; la suite de UI se ejecuta en su propio workflow, las comprobaciones de accesibilidad de las CA se ejecutan cada semana (como comprobación obligatoria pondrían en rojo cada PR por la caída de un tercero), y la puerta de extremo a extremo con certificados reales se ejecuta contra Let's Encrypt staging antes de una release.

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

1. **Múltiples versiones de Python**: Pruebas en Python 3.12
2. **Calidad de código**: Linting con flake8
3. **Seguridad**: Escaneo con bandit
4. **Pruebas**: Suite completa con cobertura
5. **Docker**: Prueba del build de Docker
6. **Cobertura**: Envío a Codecov

### Antes de hacer push

Este repositorio no tiene configuración de pre-commit; ejecute las mismas puertas que la CI:

```bash
make lint      # flake8 (el conjunto con el que falla la CI) y los presupuestos de complejidad y de excepciones
make security  # bandit, severidad media y superior
make check     # lint + security + pruebas (la selección de la puerta de release)
make ci        # el job de pruebas de la CI: requiere Docker y Node
```

Una release ejecuta bastante más: véase `scripts/release.sh`, que exige flake8, bandit, las suites unitaria y de integración, la suite de UI con Playwright, un certificado real emitido contra Let's Encrypt staging y una build de Docker.

---

## Requisitos de cobertura

- CI impone un mínimo del **75%** sobre `modules/` (`--cov-fail-under`, un
  trinquete: súbalo, nunca lo baje para que pase una build). El número actual
  está cómodamente por encima.
- Todas las funcionalidades nuevas deben incluir tests.

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
