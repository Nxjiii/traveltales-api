from datetime import datetime, timezone
from ..models import TokenBlacklist, db
from flask import current_app


def cleanup_blacklist():
    """Remove expired tokens from the blacklist."""
    expired_tokens = TokenBlacklist.query.filter(TokenBlacklist.expires_at < datetime.now(timezone.utc)).all()
    
    for token in expired_tokens:
        db.session.delete(token)
    
    db.session.commit()
    current_app.logger.info(f"Removed {len(expired_tokens)} expired tokens from the blacklist.")
