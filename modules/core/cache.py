"""
Cache management module for CertMate
Handles deployment status caching and cache operations
"""

import logging
from .utils import DeploymentStatusCache

logger = logging.getLogger(__name__)


class CacheManager:
    """Class to handle cache management operations"""
    
    def __init__(self, settings_manager):
        self.settings_manager = settings_manager
        self.deployment_cache = DeploymentStatusCache()
        self.update_cache_settings()

    def update_cache_settings(self):
        """Update cache settings from configuration"""
        try:
            settings = self.settings_manager.load_settings()
            cache_ttl = settings.get('cache_ttl', 300)
            self.deployment_cache.set_ttl(cache_ttl)
            logger.info(f"Updated deployment cache TTL to {cache_ttl} seconds")
        except Exception as e:
            logger.error(f"Error updating cache settings: {e}")

    def get_cache_stats(self):
        """Get cache statistics"""
        try:
            return self.deployment_cache.get_stats()
        except Exception as e:
            logger.error(f"Error getting cache stats: {e}")
            return {
                'total_entries': 0,
                'current_ttl': 300,
                'entries': []
            }

    def clear_cache(self):
        """Clear all cache entries"""
        try:
            cleared_count = self.deployment_cache.clear()
            logger.info(f"Cleared {cleared_count} cache entries")
            return cleared_count
        except Exception as e:
            logger.error(f"Error clearing cache: {e}")
            return 0

    def get_deployment_status(self, domain):
        """Get deployment status from cache"""
        try:
            return self.deployment_cache.get(domain)
        except Exception as e:
            logger.error(f"Error getting deployment status for {domain}: {e}")
            return None

    def set_deployment_status(self, domain, status):
        """Set deployment status in cache"""
        try:
            self.deployment_cache.set(domain, status)
            logger.debug(f"Set deployment status for {domain}: {status}")
        except Exception as e:
            logger.error(f"Error setting deployment status for {domain}: {e}")

    def remove_from_cache(self, domain):
        """Remove specific domain from cache"""
        try:
            self.deployment_cache.remove(domain)
            logger.debug(f"Removed {domain} from cache")
        except Exception as e:
            logger.error(f"Error removing {domain} from cache: {e}")

    def on_certificate_event(self, event, data):
        """EventBus listener: drop a domain's cached deployment-status verdict
        when its certificate is (re)issued or renewed.

        Without this the dashboard keeps serving a stale "deployed &
        certificate matches" verdict for up to cache_ttl after a renewal,
        even though the load balancer may still be serving the OLD cert
        because the deploy hook has not run yet. Subscribing to the events
        covers the manual/API, async, web, and scheduled renewal paths in one
        place: they all publish certificate_created / certificate_renewed on
        the bus (create and reissue map onto these two events too — see
        cert_jobs.py: reissue -> certificate_renewed).

        Never raises — remove_from_cache swallows its own errors, so a
        cache-eviction failure cannot turn a successful issuance into a
        reported error.
        """
        if event not in ('certificate_created', 'certificate_renewed'):
            return
        domain = (data or {}).get('domain')
        if not domain:
            return
        self.remove_from_cache(domain)

    def get_cache_instance(self):
        """Get the deployment cache instance for direct access"""
        return self.deployment_cache
