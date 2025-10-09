import hashlib
import os

# Define the constants for the hashing algorithm
# Ensure this iteration count matches the one you set for KDF in passwordManager.py
KDF_ITERATIONS = 250_000
HASH_ALGORITHM = 'sha256'
SALT_LENGTH = 16


def hashify(password:bytes, salt:bytes = b''):
    '''
    Derives a secure password hash using PBKDF2-HMAC-SHA256. 
    This hash serves as the secure, slow-to-crack version of the master password.
    '''

    # Generate the salt using a cryptographically secure random method if no salt is provided.
    if salt == b'':
        salt = os.urandom(SALT_LENGTH)

    # Use PBKDF2-HMAC-SHA256 for secure, iterative password hashing.
    # This ensures the stored master password hash is just as strong as the KDF.
    hashed_password_digest = hashlib.pbkdf2_hmac(
        hash_name=HASH_ALGORITHM,
        password=password,
        salt=salt,
        iterations=KDF_ITERATIONS,
        # The output length is set to 32 bytes (256 bits) to match SHA256 output size.
        dklen=32 
    )

    # Return the generated salt and the secure hash digest.
    return salt, hashed_password_digest