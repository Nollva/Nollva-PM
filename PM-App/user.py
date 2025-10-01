from hashify import hashify
from typing import Optional

class User:
    '''
    A user object that can be created with the required inputs of a username string, a password string, and a salt string.
    The __init__ method now allows for optional parameters or a data dictionary to reconstruct the object from the database.
    '''

    def __init__(self, username: Optional[str] = None, salt: Optional[str] = None, hashed_password: Optional[str] = None, data: Optional[dict] = None):
        if data:
            # If a data dictionary is provided, extract all the necessary values from it.
            self.username = username
            self.salt = data.get("auth_salt")
            self.hashed_password = data.get("hashed_master_password")
            self.passwords = data.get("stored_passwords", {})
            
        else:
            # Otherwise, use the individual parameters.
            self.username = username
            self.salt = salt
            self.hashed_password = hashed_password
            self.passwords = {}


    def new_save(self, service_name: str, service_username:str ,encrypted_password: str):
        '''Adds an username and encrypted password to the user's data.'''
        self.passwords[service_name] = {
            "username" : service_username,
            "encrypted_password" : encrypted_password
        }

    def get_save(self, service: str):
        '''Retrieves an username and encrypted password from the user's data.'''
        temp_dict = self.passwords[service]
        service_username = temp_dict["username"]
        encrypted_password = temp_dict["encrypted_password"]
        return service_username, encrypted_password

    def write_out(self):
        '''Writes out a user object's current data into a json format for saving.'''
        json_output = {
            "auth_salt" : self.salt,
            "hashed_master_password" : self.hashed_password,
            "stored_passwords" : self.passwords

        }

        return json_output