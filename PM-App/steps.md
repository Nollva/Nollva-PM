Secure Password Manager Project Checklist

Phase 1: Foundation (Master Password & Authentication)

    Objective: Securely handle the master password without storing it in plaintext.

    Concepts: Hashing, Salting, Key Derivation Functions (KDFs).

Tasks

    Task 1: Choose a Language

        Notes & Advice: Python is recommended due to its clear syntax and powerful cryptography libraries.

        Status: ☑️

    Task 2: Select a Hashing Algorithm

        Notes & Advice: Use a modern, strong algorithm like SHA-256 from Python's hashlib library. Avoid older algorithms like MD5 or SHA-1, which are considered insecure.

        Status: ☑️

    Task 3: Implement a Salt Generator

        Notes & Advice: Use os.urandom(16) to generate a 16-byte random salt. This should be a unique salt for each user.

        Status: ☑️

    Task 4: Implement a Key Derivation Function

        Notes & Advice: Use a KDF like PBKDF2HMAC with a high number of iterations (e.g., 100,000+). This will make brute-force attacks extremely difficult. You'll find this in the cryptography library.

        Status: ☑️

    Task 5: Create a Registration Function

        Notes & Advice: This function should prompt the user for a master password, generate a salt, and use the salt and password to compute a hash for authentication.

        Status: ☑️

    Task 6: Create a Login Function

        Notes & Advice: This function should load the stored hash and salt, prompt the user for their password, and re-compute the hash to verify a match.

        Status: ☑️

Phase 2: Core Functionality (Encryption & Storage)

    Objective: Encrypt and store the user's passwords securely.

    Concepts: Symmetric Encryption, JSON file storage.

Tasks

    Task 7: Generate a Symmetric Key

        Notes & Advice: Use the KDF you implemented in Phase 1 to generate a unique encryption key from the master password and salt. This key will be used to encrypt all the other passwords.

        Status: ☑️

    Task 8: Select an Encryption Algorithm

        Notes & Advice: Use a strong symmetric encryption algorithm like AES-256. The cryptography.fernet library provides an easy-to-use, high-level API for authenticated symmetric encryption, which is perfect for this task.

        Status: ☑️

    Task 9: Implement an add_password function

        Notes & Advice: This function should prompt for the service name, username, and password. Use the key from Task 7 to encrypt the password before saving it.

        Status: ☑️

    Task 10: Implement a get_password function

        Notes & Advice: This function should prompt for a service name, retrieve the encrypted password from the storage file, and use the same key to decrypt it.

        Status: ☑️

    Task 11: Choose a Storage Format

        Notes & Advice: Use a structured file format like JSON to store the encrypted passwords and usernames. This makes it easy to read and write data. For example: {"website_name": {"username": "...", "password": "..."}}.

        Status: ☑️

Phase 3: User Experience & Polish

    Objective: Make the application easy and safe to use.

    Concepts: User Interface, Error Handling, Best Practices.

Tasks

    Task 12: Use getpass for input

        Notes & Advice: Always use from getpass import getpass to prompt for passwords. This will hide the user's input from the console, preventing shoulder surfing.

        Status: ☑️

    Task 13: Implement a Main Menu

        Notes & Advice: Create a simple command-line interface with options to add a password, get a password, or quit. This makes the application easy to navigate.

        Status: ☑️

    Task 14: Add Error Handling

        Notes & Advice: Use try...except blocks to handle potential errors, such as file-not-found, incorrect master password, or invalid user input. This makes your program more robust.

        Status: ☑️

    Task 15: Provide Clear Feedback

        Notes & Advice: When a task is completed, print a message like [+] Password added successfully. If an error occurs, use [-] to indicate failure. This keeps the user informed about the program's status.

        Status: ☑️

    Task 16: Add a Password Generator (Bonus)

        Notes & Advice: For an extra challenge, implement a function that generates a strong, random password with a mix of letters, numbers, and symbols. This adds a great feature to your project.

        Status: ☐