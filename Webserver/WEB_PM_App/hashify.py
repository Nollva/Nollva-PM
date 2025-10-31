import hashlib
import os

# Define the constants for the hashing algorithm
# Ensure this iteration count matches the one you set for KDF in passwordManager.py
KDF_ITERATIONS = 250_000
HASH_ALGORITHM = 'sha256'
SALT_LENGTH = 16


def hashify(password:bytes, auth_salt:bytes = b'', enc_salt:bytes = b''):
    '''
    Derives a secure password hash using PBKDF2-HMAC-SHA256. 
    This hash serves as the secure, slow-to-crack version of the master password.
    
    If auth_salt is empty, it generates a new authentication salt (for new accounts).
    If enc_salt is empty, it generates a new encryption salt (for new accounts).
    
    Returns: (auth_salt, hashed_password_digest, enc_salt)
    '''

    # --- 1. Ensure all salts are defined ---
    # The salt argument is renamed to auth_salt to be explicit.
    # If auth_salt is empty, generate a new one for password hashing (Auth Salt)
    if auth_salt == b'':
        auth_salt = os.urandom(SALT_LENGTH)

    # If enc_salt is empty, generate a new one for key derivation (Encryption Salt)
    if enc_salt == b'':
        enc_salt = os.urandom(SALT_LENGTH)


    # --- 2. Calculate the Hashed Password (Authentication Hash) ---
    # Use PBKDF2-HMAC-SHA256 for secure, iterative password hashing.
    hashed_password_digest = hashlib.pbkdf2_hmac(
        hash_name=HASH_ALGORITHM,
        password=password,
        salt=auth_salt, # Use the distinct AUTHENTICATION salt here
        iterations=KDF_ITERATIONS,
        # The output length is set to 32 bytes (256 bits) to match SHA256 output size.
        dklen=32 
    )

    # Return the authentication salt, the hash, and the encryption salt.
    return auth_salt, hashed_password_digest, enc_salt