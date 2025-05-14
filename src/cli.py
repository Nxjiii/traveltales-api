import click
from flask import current_app
from .services.cleanup import cleanup_blacklist

def register_cli_commands(app):
    @app.cli.command("cleanup-tokens")
    def cleanup_tokens():
        """Manually clean up expired tokens from the blacklist."""
        with app.app_context():
            cleanup_blacklist()
