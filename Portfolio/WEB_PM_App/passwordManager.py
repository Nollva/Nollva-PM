import hashlib
from .user import User
from .hashify import hashify
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from cryptography.fernet import Fernet
import base64


class PasswordManager:
    '''Runs the main Password Manager operations, logging in decrypting all of the keys, and such.'''


    def __init__(self):
        # 1. Get the URI from the .env environment variable.
        #    (The .env file is loaded in server.py, so we can access os.environ here)
        uri = os.environ.get("DB_URI") 
        
        # 2. Start the Database connection and attach it to the instance
        self.dbclient = MongoClient(uri, server_api=ServerApi('1'))
        
        # 3. Locate the collection and attach it to the instance
        self.database = self.dbclient.get_database("Users")
        self.users = self.database.get_collection("users")



    def _check_user_(self, username:str):
        '''Checks the DB for a user document.'''
        query = {"username": username.lower()}
        user = self.users.find_one(filter=query)
        
        if user:
            return User.from_mongo_document(user)
        
        else:
            return False

    def save_data(self, user_object:User):
        '''Saves the in-memory dduser's document in the database'''
        try:

            # Prepare the document data and the filter
            document_data = user_object.to_mongo_document()
            query_filter = {"username": user_object.username}
            
            # 2. Wrap the document data in the $set operator
            update_operation = {"$set": document_data}


            # Attempt to insert or update a database document for the user.
            self.users.update_one(filter=query_filter, update=update_operation, upsert=True)

            return "Data saved successfully."
        except:
            return "Error saving data:"


    def create_account (self, username:str, password1:str, password2:str):
            # Convert the username to the global setting of all lowercase.
            lower_username = username.lower()

            # If the username entered is already an account, return.
            if self._check_user_(lower_username):
                return "Account creation failed: Please check your inputs and try again."
                

            # Else, continue with account creation.
            else:

                # If both passwords are the same.
                if password1 == password2:

                    # Convert the password string to bytes at the earliest possible moment. 
                    bytes_password = password1.encode(encoding="utf-8")

                    # Create the salt and hashed password. 
                    salt, hashed_password = hashify(password=bytes_password)

                    # Create the user object.
                    user_object = User(username=lower_username, salt=salt, hashed_password=hashed_password)
                    # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                    encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_password, salt=salt, iterations=100_000))

                    self.save_data(user_object)
                    
                    return lower_username, encryption_key 
                    


                else:
                    return "Account creation failed: Your passwords do not match."






    def login(self, username:str, password:str):
        # Convert the password string to bytes at the earliest possible moment. 
        bytes_password = password.encode(encoding="utf-8")

        # Convert the given username to all lowercase as that is the global setting for the manager.
        lower_username = username.lower()

        # If there is a user by that username
        user = self._check_user_(lower_username)
        if user:

            # Find the Salt and Hashed Master Password
            salt = user.salt
            
            hashed_password = user.hashed_password

            # Confirm that the entered password hash matches the hashed password.
            if hashify(password=bytes_password, salt=salt)[1] == hashed_password:
                
                # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_password, salt=salt, iterations=100_000))
                
                return lower_username, encryption_key

            else: 
                return "Login failed: Please check your inputs and try again."

        # If user is not found, do this.
        else:
            return "Login failed: Please check your inputs and try again."

    def new_save(self, service_name:str, service_username:str, service_password:str, user_username:str, encryption_key:bytes, save_data:bool = True, original_service_name=None):
        '''Creates a saved entry in the in-memory user using the in-memory encryption_key to encrypt the file.'''

        user_object = self._check_user_(user_username)
        if user_object:


            # Sets the encryption key in Fernet.
            f = Fernet(encryption_key)

            # Converts the password from readable text to UTF-8 bytes, then encrypts the password using Fernet.
            encrypted_password = f.encrypt(service_password.encode(encoding="utf-8"))
            
            # Activates the new_save function in the User class so that the save_data will save everything properly.
            user_object.new_save(service_name, service_username, encrypted_password)


            if save_data:
                # Saves the Data
                self.save_data(user_object)
                if original_service_name != None:
                    confirm = self.delete_save(user_username=user_username, service_name=original_service_name)
                    if confirm == "Login successfully deleted.":
                        print("The delete part worked my bro.")

                return "Login Saved"

        else:
            return "Could not find a user by the username."


    def get_save(self, user_username:str, service_name, encryption_key:bytes, user_object=None):
        '''Gets a saved entry from the in-memory user using the in-memory encryption_key to decrypt the file.'''
        if user_object == None:
            user_object = self._check_user_(user_username)

        if user_object:
            if service_name in user_object.passwords:
                # Gets the service username and encrypted password from the db if the service_name is in the database.
                service_username, encrypted_password = user_object.get_save(service=service_name)

                # Sets the encryption key in Fernet
                f = Fernet(encryption_key)
                
                # Decrypts the encrypted password and converts the UTF-8 bytes to readable text.
                decrypted_password = f.decrypt(encrypted_password).decode(encoding="utf-8")

                return service_username, decrypted_password
            
            else:
                return "There is no password saved for that service."
        else:
            return "Could not find a user by the username."
        

    def delete_save(self, user_username:str, service_name):
        '''Deletes a saved entry from the in-memory user.'''
        user_object = self._check_user_(user_username)

        if user_object:
            if service_name in user_object.passwords:
                user_object.delete_save(service_name)
                self.save_data(user_object)
                return "Login successfully deleted."

                
            
            else:
                return "There is no password saved for that service."
        else:
            return "Could not find a user by the username."
    

    def list_saved_logins(self, user_username:str, encryption_key:bytes):
        '''Prints out or returns a list of service names to look up.'''
        user_object = self._check_user_(user_username)
        if user_object:

            if user_object.passwords == {}:
                return "No passwords"


            else:
                empty_list = [] 
                count = 0
                # For each service in the passwords, print the service names.

                for service_name in user_object.passwords.keys():
                    count += 1
                    service_username, service_password = self.get_save(user_username=user_username, service_name=service_name, encryption_key=encryption_key, user_object=user_object)
                    empty_list.append({"id": count, "service_name": service_name, "service_username": service_username, "service_password": service_password})

                return empty_list




    def change_master_password(self, old_password:str, new_password:str, new_password1:str, user_username:str, old_encryption_key:bytes):
        '''Undergoes an intense cryptographic process to create a new password hash, confirm the old password's hash = the saved one, grab the old encryption key, craft a new one. 
        Decrypt every single password, and immediatly re-encrypt it using the new encryption key.'''
        user_object = self._check_user_(user_username)
        if user_object:

            bytes_old_password = old_password.encode(encoding="utf-8")
            bytes_salt = user_object.salt # type: ignore

            # If the old password hash matches the user account's master password hash.
            if hashify(password=bytes_old_password, salt=bytes_salt)[1] == user_object.hashed_password: # type: ignore

                # If the new passwords entered are the same.
                if new_password == new_password1:

                    # Convert the new password to bytes.
                    bytes_new_password = new_password.encode(encoding="utf-8")

                    # Generate a new password hash and a new salt.
                    new_salt, new_password_hash = hashify(password=bytes_new_password)

                    # Generate a brand new encryption key from the bytes password.
                    new_encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_new_password, salt=new_salt, iterations=100_000))

                    for service_name, credentials in user_object.passwords.items():
                        service_username, service_password = self.get_save(user_username=user_object.username, service_name=service_name, encryption_key=old_encryption_key) # type: ignore
                        self.new_save(service_name, service_username, service_password, encryption_key=new_encryption_key, save_data=False, user_username=user_username)

                    user_object.hashed_password = new_password_hash
                    user_object.salt = new_salt
                    self.save_data(user_object)
                    return "Master Password Changed.", new_encryption_key




                else:
                    return "Master Password Reset Failed: Please check your inputs and try again.", ""

            else:
                return "Master Password Reset Failed: Please check your inputs and try again.", ""


        else:
            return "Could not find a user by the username."


# jeff.change_master_password("Cut3D0g3", "Test", "Test")
# jeff.get_save("google.com")
# jeff.get_save("youtube.com")
# jeff.get_save("hackermans.com")
# jeff.list_saved_logins(return_list=False, print_list=True)

