import base64
import hashlib
import logging
import secrets

import bcrypt
from cryptography.fernet import Fernet
from app.core.config import settings

logger = logging.getLogger(__name__)

# 1. Initialize Fernet with the secure key from your .env file
# The key must be in bytes
key = settings.SECRET_KEY.encode()
fernet = Fernet(key)

def encrypt_password(password: str) -> str:
    """
    Encrypts a password using Fernet symmetric encryption.
    """
    if not password:
        return ""
    
    password_bytes = password.encode('utf-8')
    encrypted_bytes = fernet.encrypt(password_bytes)
    
    # The result is a token that is safe to store
    return encrypted_bytes.decode('utf-8')

def decrypt_password(encrypted_token: str) -> str:
    """
    Decrypts a Fernet token back to the original password.
    """
    if not encrypted_token:
        return ""
        
    token_bytes = encrypted_token.encode('utf-8')
    try:
        decrypted_bytes = fernet.decrypt(token_bytes)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        # This can happen if the key is wrong or the token is corrupt
        logger.exception("Error decrypting password")
        return ""  # Return empty string on failure


# ── Auth: password hashing + refresh tokens (Phase 20.1) ─────────────────────
# bcrypt is separate from the Fernet helpers above: Fernet is reversible
# (server credentials must be decrypted to connect); passwords are one-way.

def _prehash(password: str) -> bytes:
    """SHA-256 → base64 of the password. bcrypt silently truncates input at 72
    bytes; pre-hashing removes that limit so the full password is always used."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    """One-way bcrypt hash, safe to store in the `users` collection."""
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Constant-time compare of a plaintext password against a stored bcrypt hash."""
    if not password or not password_hash:
        return False
    try:
        return bcrypt.checkpw(_prehash(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def make_refresh_token() -> str:
    """Opaque, URL-safe random refresh token. The raw value is returned to the
    client (as a cookie) exactly once; only its hash is persisted."""
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    """SHA-256 of a refresh token for storage — the raw token is never persisted."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()