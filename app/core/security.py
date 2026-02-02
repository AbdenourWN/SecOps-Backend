from cryptography.fernet import Fernet
from app.core.config import settings

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
    except Exception as e:
        # This can happen if the key is wrong or the token is corrupt
        print(f"Error decrypting password: {e}")
        return "" # Return empty string on failure