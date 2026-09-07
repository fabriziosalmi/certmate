"""Cache inspection and invalidation endpoints.

Extracted from the `create_api_resources` closure (#667). The classes are
unchanged; what used to be captured from the enclosing scope now arrives as an
explicit `ApiContext`, which is what makes them importable — and therefore
testable — without constructing the whole manager graph.
"""
from flask import request
from flask_restx import Resource

import logging

from .resource_context import ApiContext

logger = logging.getLogger(__name__)


def create_cache_resources(api, models, ctx: ApiContext) -> dict:
    """Build the cache resources against *ctx*."""

    class CacheStats(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_stats_model'])
        @ctx.auth.require_role('viewer')
        def get(self):
            """Get cache statistics"""
            try:
                stats = ctx.cache.get_cache_stats()
                return stats
            except Exception as e:
                logger.error(f"Error getting cache stats: {e}")
                return {'error': 'Failed to get cache statistics'}, 500

    class CacheClear(Resource):
        @api.doc(security='Bearer')
        @api.marshal_with(models['cache_clear_response_model'])
        @ctx.auth.require_role('admin')
        def post(self):
            """Clear deployment cache"""
            try:
                cleared_count = ctx.cache.clear_cache()
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='clear',
                        resource_type='cache',
                        resource_id='deployment_cache',
                        status='success',
                        details={
                            'cleared_entries': cleared_count
                        },
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                    )
                return {
                    'success': True,
                    'message': 'Cache cleared successfully',
                    'cleared_entries': cleared_count
                }
            except Exception as e:
                logger.error(f"Error clearing cache: {e}")
                if ctx.audit:
                    user = getattr(request, 'current_user', None) or {}
                    ctx.audit.log_operation(
                        operation='clear',
                        resource_type='cache',
                        resource_id='deployment_cache',
                        status='failure',
                        user=user.get('username'),
                        ip_address=request.remote_addr,
                        error=str(e)
                    )
                return {
                    'success': False,
                    'message': 'Failed to clear cache',
                    'cleared_entries': 0
                }, 500

    return {
        'CacheStats': CacheStats,
        'CacheClear': CacheClear,
    }
