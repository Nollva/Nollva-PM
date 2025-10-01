import string
import secrets

def generate_secure_password(length=20):
    # What characters should this function use?
    characters = string.ascii_letters + string.punctuation + string.digits


    # Constructs a password by using the secrets library to randomly choose a character from the stringset.
    password = ''.join(secrets.choice(characters) for i in range(length))

    return password