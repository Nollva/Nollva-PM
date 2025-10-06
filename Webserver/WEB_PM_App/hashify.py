import hashlib
import os


def hashify(password:bytes, salt=b''):
    '''Takes a password input, assigns a random generated salt, hashes the two together, and returns the hash digest in bytes format.'''

    # Generate the salt using a cryptographically secure random method if there is no salt provided.
    if salt == b'':
        salt = os.urandom(16)

    # Combine the salt bytes and the utf-8 input bytes.
    saltedInput = password + salt

    # Run hashlib and input the string as data. I chose SHA3-256 simply due to it's high security while maintaining efficiency. (SHA-512 was another i was looking into)
    hashed = hashlib.sha3_256(data=saltedInput)

    # Hashlib provides a python object that contains useful information. I wanted the hash in a bytes format to ensure data integrity, so I performed this.
    hash = hashed.digest()

    return salt, hash