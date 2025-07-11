"""
API module for CertMate
Contains API models and resources for the REST API
"""

from .models import create_api_models
from .resources import create_api_resources

__all__ = [
    'create_api_models',
    'create_api_resources'
]
