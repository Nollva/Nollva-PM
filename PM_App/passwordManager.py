import hashlib
from user import User
from hashify import hashify
import os
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from cryptography.fernet import Fernet
import base64

# Load the .env file.
load_dotenv()

# Get the URI from the .env environment variable.
uri = os.environ.get("DB_URI")

# Start the Database connection.
dbclient = MongoClient(uri, server_api=ServerApi('1'))

# locate the database inside of the organization.
database = dbclient.get_database("Users")

# Locate the database collection the app is using.
users = database.get_collection("users")


class PasswordManager:
    '''Runs the main Password Manager operations, logging in decrypting all of the keys, and such.'''


    def __init__(self):
        self.logged_in = False



    def save_data(self):
        '''Saves the in-memory dduser's document in the database'''
        try:
            # Prepare the document data and the filter
            document_data = self.user_object.to_mongo_document()
            query_filter = {"user": self.user_object.username}
            
            # 2. Wrap the document data in the $set operator
            update_operation = {"$set": document_data}


            # Attempt to insert or update a database document for the user.
            users.update_one(filter=query_filter, update=update_operation, upsert=True)

            print("Data saved successfully.")
        except:
            print(f"Error saving data:")

    def _check_user_(self, username:str):
        '''Checks the DB for a user document.'''
        query = {"username": username}
        user = users.find_one(filter=query)
        
        if user:
            return User.from_mongo_document(user)
        
        else:
            return False

    def create_account (self, username:str, password1:str, password2:str):
            # Convert the username to the global setting of all lowercase.
            lower_username = username.lower()

            # If the username entered is already an account, return.
            if self._check_user_(lower_username):
                return "Username already in use."
                

            # Else, continue with account creation.
            else:

                # If both passwords are the same.
                if password1 == password2:

                    # Convert the password string to bytes at the earliest possible moment. 
                    bytes_password = password1.encode(encoding="utf-8")

                    # Create the salt and hashed password. 
                    salt, hashed_password = hashify(password=bytes_password)

                    # Create the user object.
                    self.user_object = User(username=lower_username, salt=salt, hashed_password=hashed_password)
                    self.logged_in = True
                    # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                    self.encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_password, salt=salt, iterations=100_000))

                    self.save_data()
                    


                else:
                    return "The passwords do not match."






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

            salt2, hashpass2 = hashify(password=bytes_password, salt=salt)

            # Confirm that the entered password hash matches the hashed password.
            if hashify(password=bytes_password, salt=salt)[1] == hashed_password:
                self.user_object = user
                self.logged_in = True   
                print("You are logged in")
                
                # Perform a KDF Key Dirrivitive Function to derive the special key that encrypts all of the passwords.
                self.encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_password, salt=salt, iterations=100_000))

            else: 
                return "The entered password does not match the hashed password."

        # If user is not found, do this.
        else:
            return "Unable to locate the given user."

    def new_save(self, service_name:str, service_username:str, service_password:str, new_encryption_key:bytes = b'', save_data:bool = True):
        '''Creates a saved entry in the in-memory user using the in-memory encryption_key to encrypt the file.'''

        if self.logged_in:

            # Sets the encryption key in Fernet.
            if new_encryption_key == b'':
                f = Fernet(self.encryption_key)

            else:
                f = Fernet(new_encryption_key)

            # Converts the password from readable text to UTF-8 bytes, then encrypts the password using Fernet.
            encrypted_password = f.encrypt(service_password.encode(encoding="utf-8"))
            
            # Activates the new_save function in the User class so that the save_data will save everything properly.
            self.user_object.new_save(service_name, service_username, encrypted_password)


            if save_data:
                # Saves the Data
                self.save_data()

        else:
            print("You must be logged in to create a save.")


    def get_save(self, service_name, print_out:bool = True):
        '''Gets a saved entry from the in-memory user using the in-memory encryption_key to decrypt the file.'''
        if self.logged_in:
            if service_name in self.user_object.passwords:
                # Gets the service username and encrypted password from the db if the service_name is in the database.
                service_username, encrypted_password = self.user_object.get_save(service=service_name)

                # Sets the encryption key in Fernet
                f = Fernet(self.encryption_key)
                
                # Decrypts the encrypted password and converts the UTF-8 bytes to readable text.
                decrypted_password = f.decrypt(encrypted_password).decode(encoding="utf-8")

                # Prints the information out and returns it as usable variables.
                if print_out:
                    print(f"Username: {service_username}\nPassword: {decrypted_password}")
                return service_username, decrypted_password
            
            else:
                return "Sorry, could not locate that save set."
        else:
            return "You must be logged in to get a save."

    def list_saved_logins(self, return_list:bool = True, print_list:bool = False):
        '''Prints out or returns a list of service names to look up.'''


        # If the user is logged in.
        if self.logged_in:

            if self.user_object.passwords == {}:
                return "There are no saved logins yet."


            else:
                empty_list = [] 
                # For each service in the passwords, print the service names.

                for service_name in self.user_object.passwords.keys():
                    empty_list.append(service_name)
                    if print_list:
                        print(f"{service_name}\n")

                if return_list:
                    return empty_list




    def change_master_password(self, old_password:str, new_password:str, new_password1:str):
        '''Undergoes an intense cryptographic process to create a new password hash, confirm the old password's hash = the saved one, grab the old encryption key, craft a new one. 
        Decrypt every single password, and immediatly re-encrypt it using the new encryption key.'''

        if self.logged_in:

            bytes_old_password = old_password.encode(encoding="utf-8")
            bytes_salt = self.user_object.salt # type: ignore

            # If the old password hash matches the user account's master password hash.
            if hashify(password=bytes_old_password, salt=bytes_salt)[1] == self.user_object.hashed_password: # type: ignore

                # If the new passwords entered are the same.
                if new_password == new_password1:

                    # Convert the new password to bytes.
                    bytes_new_password = new_password.encode(encoding="utf-8")

                    # Generate a new password hash and a new salt.
                    new_salt, new_password_hash = hashify(password=bytes_new_password)

                    # Generate a brand new encryption key from the bytes password.
                    new_encryption_key = base64.urlsafe_b64encode(hashlib.pbkdf2_hmac(hash_name="sha256", password=bytes_new_password, salt=new_salt, iterations=100_000))

                    for service_name, credentials in self.user_object.passwords.items():
                        service_username, service_password = self.get_save(service_name, print_out=False) # type: ignore
                        self.new_save(service_name, service_username, service_password, new_encryption_key, save_data=False)

                    self.user_object.hashed_password = new_password_hash
                    self.user_object.salt = new_salt
                    self.encryption_key = new_encryption_key
                    self.save_data()




                else:
                    return "The new passwords do not match. Please try again."

            else:
                return "Your entered password does not match the one in our system."


        else:
            return("You must be logged in to undergo this process.")



    def logout(self):
        '''Logs out, performs a save data, and wipes the user_object and encryption keys.'''
        self.save_data()
        self.user_object = User(username="", salt=b"", hashed_password=b"")
        self.encryption_key = b""
        self.logged_in = False




# jeff = PasswordManager()
# jeff.create_account("Test", "Test", "Test")
# jeff.login("test", "Test")
# jeff.new_save("hackermans.com", "test@hacker.com", "IM A HACKER")
# jeff.change_master_password("Cut3D0g3", "Test", "Test")
# jeff.get_save("google.com")
# jeff.get_save("youtube.com")
# jeff.get_save("hackermans.com")
# jeff.list_saved_logins(return_list=False, print_list=True)

