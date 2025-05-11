from datetime import datetime, timezone
from ..models import TokenBlacklist, db
from flask import current_app


#Run the blacklist cleanup function every 24 hours, initialised in init.py
def cleanup_blacklist():
    """Remove expired tokens from the blacklist."""
    expired_tokens = TokenBlacklist.query.filter(TokenBlacklist.expires_at < datetime.now(timezone.utc)).all()
    
    # Delete expired tokens from blacklist
    for token in expired_tokens:
        db.session.delete(token)
    
    db.session.commit()
    current_app.logger.info(f"Removed {len(expired_tokens)} expired tokens from the blacklist.")
