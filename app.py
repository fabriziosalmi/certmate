"""
CertMate - Modular SSL Certificate Management Application
Main application entry point with modular architecture
"""
import os
import sys
import logging
from modules import __version__

# Import new modular components
from modules.core import configure_structured_logging, get_certmate_logger
from modules.core.factory import create_app

# Configure structured JSON logging
json_logging = os.getenv('CERTMATE_LOG_JSON', 'true').lower() == 'true'
log_level_name = os.getenv('CERTMATE_LOG_LEVEL', 'INFO').upper()
log_level = getattr(logging, log_level_name, logging.INFO)
configure_structured_logging(level=log_level, json_output=json_logging)
logger = get_certmate_logger('app')

# Global app instance for WSGI servers
try:
    app, container = create_app()
except Exception as e:
    logger.error(f"Failed to initialize CertMate app: {e}")
    sys.exit(1)

# COMPATIBILITY LAYER FOR TESTS & DIRECTORIES
CERT_DIR = container.cert_dir
DATA_DIR = container.data_dir
BACKUP_DIR = container.backup_dir
LOGS_DIR = container.logs_dir
SETTINGS_FILE = DATA_DIR / "settings.json"

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='CertMate SSL Certificate Management')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to (default: 8000)')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO',
                        help='Set logging level')

    args = parser.parse_args()

    if args.debug and os.getenv('FLASK_ENV') == 'production':
        print("ERROR: Debug mode cannot be enabled in production")
        sys.exit(1)

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    try:
        print(f"🚀 Starting CertMate v{__version__} on {args.host}:{args.port}")
        print(f"📊 Debug mode: {'enabled' if args.debug else 'disabled'}")
        app.run(
            host=args.host,
            port=args.port,
            debug=args.debug,
            threaded=True,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\n🛑 Shutting down CertMate...")
        if container.scheduler:
            try:
                container.scheduler.shutdown()
                print("📅 Background scheduler stopped")
            except Exception:
                pass
        sys.exit(0)
