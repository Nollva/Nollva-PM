from typing import Optional, Dict, Any
import datetime

class User:
    '''
    A user object that can be created with the required inputs of a username string, a password string, and a salt string.
    Use the class method User.from_mongo_document(mongodoc) to create a user object from the database.
    '''

    def __init__(self, username:str, salt:bytes, hashed_password:bytes, encryption_salt:bytes, passwords=None, created_at=None): # <-- MODIFIED: Added encryption_salt
        self.username = username
        self.salt = salt # This is the AUTHENTICATION salt
        self.hashed_password = hashed_password
        self.encryption_salt = encryption_salt # <-- NEW: The salt for key derivation

        if passwords:
            self.passwords = passwords

        else:
            self.passwords = {}
            

        if created_at:
            self.created_at = created_at
        else:
            self.created_at = datetime.datetime.now(datetime.timezone.utc)


    @classmethod
    def from_mongo_document(cls, doc):
        '''Factory method to reconstructy a User object from a MongoDB document.'''
        username = doc.get("username")
        user_data = doc.get("user_data", {})
        salt = user_data.get("auth_salt", b"")
        hashed_password = user_data.get("hashed_master_password", b"")
        encryption_salt = user_data.get("encryption_salt", b"") # <-- NEW: Retrieve enc_salt
        passwords = doc.get("stored_passwords", {})
        created_at = doc.get("created_at")

        return cls(
            username=username,
            salt=salt,
            hashed_password=hashed_password,
            encryption_salt=encryption_salt, # <-- NEW
            # Note: We pass 'passwords' to a new parameter in __init__
            # Note: We pass 'created_at' to the optional parameter in __init__
            created_at=created_at,
            passwords=passwords # Requires adding a 'passwords' parameter to __init__
        )


    # ... (new_save, delete_save, get_save methods remain the same) ...


    def new_save(self, service_name: str, service_username:bytes ,encrypted_password: bytes):
        '''Adds an username and encrypted password to the user's data.'''
        self.passwords[service_name] = {
            "username" : service_username,
            "encrypted_password" : encrypted_password
        }

    def delete_save(self, service_name: str):
        '''Adds an username and encrypted password to the user's data.'''
        deleted_save = self.passwords.pop(service_name)


    def get_save(self, service: str):
        '''Retrieves an username and encrypted password from the user's data.'''
        temp_dict = self.passwords.get(service, {})
        service_username = temp_dict.get("username", b"")
        encrypted_password = temp_dict.get("encrypted_password", b"")
        return service_username, encrypted_password

    def to_mongo_document(self) -> Dict[str, Any]:
        """
        Tells PyMongo how to serialize this object into a MongoDB document.
        """
        return {
            "username": self.username,
            "user_data": {
                "auth_salt": self.salt,
                "hashed_master_password": self.hashed_password,
                "encryption_salt": self.encryption_salt, # <-- NEW: Save enc_salt
            },
            "stored_passwords": self.passwords,
            "created_at": self.created_at
        }