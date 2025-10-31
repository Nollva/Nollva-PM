import hashlib
from .user import User
from .hashify import hashify
import os
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from cryptography.fernet import Fernet
import base64
from typing import Optional # <-- ADDED for type hinting
from .hashify import KDF_ITERATIONS # <-- NEW: Import KDF_ITERATIONS

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


    # ... (_check_user_ and save_data methods remain the same) ...
    def _check_user_(self, username:str) -> Optional[User]: # <-- UPDATED Type Hint
        '''Checks the DB for a user document.'''
        query = {"username": username.lower()}
        user = self.users.find_one(filter=query)
        
        if user:
            return User.from_mongo_document(user)
        
        else:
            return None # <-- CHANGED from False to None to resolve Pylance error

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
            user_object = self._check_user_(lower_username) # Check returns User or None
            if user_object is not None: # <-- UPDATED check
                return "Account creation failed: Please check your inputs and try again."
                

            # Else, continue with account creation.
            else:

                # If both passwords are the same.
                if password1 == password2:

                    # Convert the password string to bytes at the earliest possible moment. 
                    bytes_password = password1.encode(encoding="utf-8")

                    # Create the AUTH salt, hashed password, AND the ENCRYPTION salt. 
                    auth_salt, hashed_password, encryption_salt = hashify(password=bytes_password) # <-- MODIFIED: capture all 3 returns

                    # Create the user object.
                    user_object = User(username=lower_username, salt=auth_salt, hashed_password=hashed_password, encryption_salt=encryption_salt) # <-- MODIFIED: pass encryption_salt
                    
                    # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                    # CRITICAL FIX: Use the new, SEPARATE encryption_salt for key derivation
                    encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
                        hash_name="sha256", 
                        password=bytes_password, 
                        salt=encryption_salt, 
                        iterations=KDF_ITERATIONS))

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
        if user is not None: # <-- UPDATED check

            # Find the Authentication Salt and Hashed Master Password
            auth_salt = user.salt 
            encryption_salt = user.encryption_salt # <-- NEW: Get the ENCRYPTION salt
            hashed_password = user.hashed_password

            # Confirm that the entered password hash matches the hashed password.
            # We pass the existing auth_salt, but no enc_salt since we don't need to generate a new one.
            if hashify(password=bytes_password, auth_salt=auth_salt)[1] == hashed_password:
                
                # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                # CRITICAL FIX: Use the stored encryption_salt for key derivation
                encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
                    hash_name="sha256", 
                    password=bytes_password, 
                    salt=encryption_salt, 
                    iterations=KDF_ITERATIONS))
                
                return lower_username, encryption_key

            else: 
                return "Login failed: Please check your inputs and try again."

        # If user is not found, do this.
        else:
            return "Login failed: Please check your inputs and try again."

    # ... (new_save, get_save, delete_save, list_saved_logins methods remain the same) ...
    def new_save(self, service_name:str, service_username:str, service_password:str, user_username:str, encryption_key:bytes, save_data:bool = True, original_service_name=None, user_object:Optional[User]=None): # <-- Updated with Optional
        '''Creates a saved entry in the in-memory user using the in-memory encryption_key to encrypt the file.'''

        # Use the passed object if available, otherwise load a fresh one.
        if user_object is None:
            user_object = self._check_user_(user_username)

        if user_object is not None: # <-- UPDATED check


            # Sets the encryption key in Fernet.
            f = Fernet(encryption_key)

            # Converts the password from readable text to UTF-8 bytes, then encrypts the password using Fernet.
            encrypted_username = f.encrypt(service_username.encode(encoding="utf-8"))


            # Converts the password from readable text to UTF-8 bytes, then encrypts the password using Fernet.
            encrypted_password = f.encrypt(service_password.encode(encoding="utf-8"))
            
            # Activates the new_save function in the User class so that the save_data will save everything properly.
            user_object.new_save(service_name, encrypted_username, encrypted_password)


            if save_data:
                # Saves the Data
                self.save_data(user_object)
                if original_service_name != None and original_service_name != service_name:
                    confirm = self.delete_save(user_username=user_username, service_name=original_service_name)
                    if confirm == "Login successfully deleted.":
                        print("The delete part worked my bro.")

                return "Login Saved"

        else:
            return "Could not find a user by the username."


    def get_save(self, user_username:str, service_name, encryption_key:bytes, user_object:Optional[User]=None): # <-- Updated with Optional
        '''Gets a saved entry from the in-memory user using the in-memory encryption_key to decrypt the file.'''
        if user_object == None:
            user_object = self._check_user_(user_username)

        if user_object is not None: # <-- UPDATED check
            if service_name in user_object.passwords:
                # Gets the service username and encrypted password from the db if the service_name is in the database.
                encrypted_username, encrypted_password = user_object.get_save(service=service_name)

                # Sets the encryption key in Fernet
                f = Fernet(encryption_key)
                
                # Decrypts the encrypted username and converts the UTF-8 bytes to readable text.
                decrypted_username = f.decrypt(encrypted_username).decode(encoding="utf-8")


                # Decrypts the encrypted password and converts the UTF-8 bytes to readable text.
                decrypted_password = f.decrypt(encrypted_password).decode(encoding="utf-8")

                return decrypted_username, decrypted_password
            
            else:
                return "There is no password saved for that service."
        else:
            return "Could not find a user by the username."
        

    def delete_save(self, user_username:str, service_name):
        '''Deletes a saved entry from the in-memory user.'''
        user_object = self._check_user_(user_username)

        if user_object is not None: # <-- UPDATED check
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
        if user_object is not None: # <-- UPDATED check

            if user_object.passwords == {}:
                return "No passwords"


            else:
                empty_list = [] 
                count = 0
                # For each service in the passwords, print the service names.

                for service_name in user_object.passwords.keys():
                    count += 1
                    # user_object is passed here to ensure the in-memory object is used
                    service_username, service_password = self.get_save(user_username=user_username, service_name=service_name, encryption_key=encryption_key, user_object=user_object)
                    empty_list.append({"id": count, "service_name": service_name, "service_username": service_username, "service_password": service_password})

                return empty_list



    def change_master_password(self, old_password:str, new_password:str, new_password1:str, user_username:str, old_encryption_key:bytes):
        '''Undergoes an intense cryptographic process to create a new password hash, confirm the old password's hash = the saved one, grab the old encryption key, craft a new one. 
        Decrypt every single password, and immediatly re-encrypt it using the new encryption key.'''
        user_object = self._check_user_(user_username)
        if user_object is not None: # <-- UPDATED check

            bytes_old_password = old_password.encode(encoding="utf-8")
            auth_salt = user_object.salt # type: ignore
            # Note: We get the old encryption_salt but it's not strictly necessary here, 
            # as the new key will be generated with a brand new salt.

            # If the old password hash matches the user account's master password hash.
            # Use the stored auth_salt to verify the old password
            if hashify(password=bytes_old_password, auth_salt=auth_salt)[1] == user_object.hashed_password: # type: ignore

                # If the new passwords entered are the same.
                if new_password == new_password1:

                    # Convert the new password to bytes.
                    bytes_new_password = new_password.encode(encoding="utf-8")

                    # Generate a new authentication salt, new hash, and a brand NEW encryption salt.
                    new_auth_salt, new_password_hash, new_encryption_salt = hashify(password=bytes_new_password) # <-- MODIFIED: Call hashify without salts to generate new ones

                    # Generate a brand new encryption key from the bytes password.
                    # CRITICAL FIX: Use the new_encryption_salt for key derivation
                    new_encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(
                        hash_name="sha256", 
                        password=bytes_new_password, 
                        salt=new_encryption_salt, # <-- CRITICAL FIX: Use new_encryption_salt
                        iterations=KDF_ITERATIONS))

                    # Re-encryption loop:
                    for service_name, credentials in user_object.passwords.items():
                        # 1. Use the old key to decrypt (get_save uses the in-memory user_object)
                        service_username, service_password = self.get_save(user_username=user_object.username, service_name=service_name, encryption_key=old_encryption_key, user_object=user_object) # type: ignore
                        
                        # 2. Use the new key to re-encrypt and update the *in-memory* user_object.
                        self.new_save(
                            service_name=service_name, 
                            service_username=service_username, 
                            service_password=service_password, 
                            user_username=user_object.username,
                            encryption_key=new_encryption_key, 
                            save_data=False, # Don't save to DB until the loop is done
                            user_object=user_object # <-- CRITICAL FIX: Pass the in-memory object
                        )

                    # 3. Update the user object's credentials
                    user_object.hashed_password = new_password_hash
                    user_object.salt = new_auth_salt # <-- CRITICAL FIX: Update the user's AUTHENTICATION salt
                    user_object.encryption_salt = new_encryption_salt # <-- NEW: Update the user's ENCRYPTION salt

                    # 4. Save the final, fully updated object to the database
                    self.save_data(user_object)
                    return "Master Password Changed.", new_encryption_key


                else:
                    return "Master Password Reset Failed: Your new passwords do not match.", "" # Clarified error message

            else:
                return "Master Password Reset Failed: Incorrect old password.", "" # Clarified error message


        else:
            return "Could not find a user by the username.", "" # Added missing empty string return