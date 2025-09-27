from passwordManager import PasswordManager
from passwordGenerator import generate_secure_password
from getpass import getpass
import pyperclip
import ascii_art
import os


def clear_console():
    if os.name == 'nt':  # For Windows
        os.system('cls')
    else:  # For Unix/Linux/Mac
        os.system('clear')

def logged_out(passwordmanager):
    # Print the basic welcome screen and base options.
    clear_console()
    print(ascii_art.logo)
    print("Welcome to the Nollva Password Manager.")
    print("Would you like to: (Enter the number of the option you wish to choose.)")
    print("1 - Log In")
    print("2 - Create an Account")

    # Present the prompt.
    prompt_1 = input(ascii_art.prompt)

    # If Prompt = login. run login stuff.
    if prompt_1 == "1":
        log_in(passwordmanager)
        

    # If Prompt = Create Account. run registration stuff.
    elif prompt_1 == "2":
        register(passwordmanager)



    else:
        input("\nYou did not input a possible option.\nPress <Enter> to confirm you understand.")


def logged_in(passwordmanager):
    '''The central hub CLI brain after logging in.'''

    # Clear the Console.
    clear_console()

    # Print the hub information.
    print(ascii_art.logged_in)
    print(f"Welcome to the Nollva Password Manager {passwordmanager.user_object.username}.")
    print("Would you like to: (Enter the number of the option you wish to choose.)")
    print("1 - Add or Update a Login")
    print("2 - Lookup a Login")
    print("3 - List saved Logins")
    print("4 - Password Generator")
    print("5 - Change the Master Password")
    print("6 - Log Out")

    # Present the prompt.
    prompt_1 = input(ascii_art.prompt)


    # If prompt = add login.
    if prompt_1 == "1":
        continue_prompt = True

        while continue_prompt:

            # Clear the console.
            clear_console()
            print(ascii_art.new_login)
            print("Press <Enter> at any point to go back.")

            # Get the necessary information.
            print("What is the name of the service? (testsite.com)")
            service_name = input(ascii_art.prompt)

            # Basic check for exit.
            if service_name == "":
                break

            print("What is the username for the service? (test@gmail.com)")
            service_username = input(ascii_art.prompt)

            # Basic check for exit.
            if service_username == "":
                break

            print("What is the password you used for the service?")
            service_password = getpass(ascii_art.prompt)

            # Basic check for exit.
            if service_password == "":
                break
            
            # Save the password.
            passwordmanager.new_save(service_name, service_username, service_password)

            # Clear the console and flash the confirmation screen.
            clear_console()
            print(ascii_art.login_added)
            print("Press <Enter> to return to the menu screen.")
            input(ascii_art.prompt)
            
            # Continue = FaLSE.
            continue_prompt = False



    # If prompt = view login.
    if prompt_1 == "2":
        continue_prompt = True

        while continue_prompt:

            # Clear the console.
            clear_console()
            print(ascii_art.view_login)
            print("Press <Enter> at any point to go back.")

            # Get the necessary information.
            print("What is the name of the service? (testsite.com)")
            service_name = input(ascii_art.prompt)

            # Basic check for exit.
            if service_name == "":
                break
            
            # Save the password.
            gs = passwordmanager.get_save(service_name)
            print("\n")
            if gs == "Sorry, could not locate that save set.":
                print("\nYou have no saved login by that service name.\nPress <Enter> to try again.")
                input(ascii_art.prompt)

            else:
                print("Once finished viewing your saved login.\nPress <Enter> to go back to the menu.")
                input(ascii_art.prompt)

                # Continue = FaLSE.
                continue_prompt = False

    # If prompt = list logins.
    if prompt_1 == "3":
        continue_prompt = True

        while continue_prompt:

            # Clear the console.
            clear_console()
            print(ascii_art.saved_logins)
            
            # Get the saved passwords:
            lp = passwordmanager.list_saved_logins()

            if lp == "There are no saved logins yet.":
                print("\nYou have no saved logins.\nPress <Enter> to go back to the menu.")
                input(ascii_art.prompt)

            else:
                for each_login in lp:
                    print(f"\n{each_login}")


                print("\nOnce finished viewing your your saved logins.\nPress <Enter> to go back to the menu.")
                input(ascii_art.prompt)

            
            # Continue = FaLSE.
            continue_prompt = False


    # If prompt = generate password.
    if prompt_1 == "4":
        '''Generates a random password.'''
        continue_prompt = True

        while continue_prompt:
            
            # Generate a random password.

            # Clear the console.
            clear_console()
            print(ascii_art.generate_password)

            # Generate the random password.
            random_password = generate_secure_password()

            # Copy it to the user's clipboard.
            pyperclip.copy(random_password)

            # Print the random password.
            print(f"\nYour random password is in your clipboard and is:\n{random_password}")

            # Give options.
            print("\nWould you like to: (Enter the number of the option you wish to choose.)")
            print("1 - Add or Update a login using your new password.")
            print("2 - Return to the menu.")
            save_it = input(ascii_art.prompt)

            if save_it == "1":
                # Perform an add login with the random password.
                continue_prompt2 = True

                while continue_prompt2:

                    # Clear the console.
                    clear_console()
                    print(ascii_art.new_login)
                    print("Press <Enter> at any point to go back.")

                    # Get the necessary information.
                    print("What is the name of the service? (testsite.com)")
                    service_name = input(ascii_art.prompt)

                    # Basic check for exit.
                    if service_name == "":
                        break

                    print("What is the username for the service? (test@gmail.com)")
                    service_username = input(ascii_art.prompt)

                    # Basic check for exit.
                    if service_username == "":
                        break

                    print("The password has been set to the previously generated password")
                    did_want_to_do = input("\nIf you did not wish to do this, type 'undo'.").lower()
                    if did_want_to_do == "undo":
                        break
                    
                    else:
                        # Save the password.
                        passwordmanager.new_save(service_name, service_username, random_password)

                        # Clear the console and flash the confirmation screen.
                        clear_console()
                        print(ascii_art.login_added)
                        print("Press <Enter> to return to the menu screen.")
                        input(ascii_art.prompt)
                        
                        # Continue = FaLSE.
                        continue_prompt2 = False

        
            # Continue = FaLSE.
            continue_prompt = False

                






    # If prompt = change master password.
    if prompt_1 == "5":
        continue_prompt = True

        while continue_prompt:

            # Clear the console.
            clear_console()
            print(ascii_art.change_master_password)
            print("Press <Enter> at any point to go back.")

            # Get the necessary information.
            print("What is your current master password?")
            master_pass = getpass(ascii_art.prompt)

            # Basic check for exit.
            if master_pass == "":
                break


            print("What is your new master password?")
            new_master_pass = getpass(ascii_art.prompt)

            # Basic check for exit.
            if new_master_pass == "":
                break


            print("Confirm your new master password.")
            new_master_pass_2 = getpass(ascii_art.prompt)

            # Basic check for exit.
            if new_master_pass_2 == "":
                break
            
            
            # Save the password.
            cmp = passwordmanager.change_master_password(old_password=master_pass, new_password=new_master_pass, new_password1=new_master_pass_2)

            if cmp == "Your entered password does not match the one in our system.":
                print("\nYou entered the incorrect master password.\nPress <Enter> to try again.")
                input(ascii_art.prompt)
            
            
            elif cmp == "The new passwords do not match. Please try again.":
                print("\nThe new passwords did not match.\nPress <Enter> to try again.")
                input(ascii_art.prompt)


            else:
                clear_console()
                print(ascii_art.password_changed)
                print("Press <Enter> to return to the menu screen.")
                input(ascii_art.prompt)

            
                # Continue = FaLSE.
                continue_prompt = False



    # If prompt = log out.
    if prompt_1 == "6":
        '''Logs out the user.'''
        continue_prompt = True

        while continue_prompt:
            
            # Perform the logout.
            passwordmanager.logout()

            # Clear the console.
            clear_console()
            print(ascii_art.logged_out)

            print("Press <Enter> to go back to the home.")
            input(ascii_art.prompt)

            
            # Continue = FaLSE.
            continue_prompt = False




def log_in(passwordmanager):
    '''The login CLI brain.'''
    while not passwordmanager.logged_in:

        # Clear the console and print the login screen.
        clear_console()
        print(ascii_art.login)
        print("Press <Enter> at any point to go back.")

        # Request the username.
        print("Please input your username:")
        username = input(ascii_art.prompt)
        
        # Basic check for exit.
        if username == "":
            break

        # Request the Password.
        print("\nPlease input your master password:")
        master_password = getpass(prompt=ascii_art.prompt)
        # Basic check for exit.
        if master_password == "":
            break

        # Attempt a login.
        login = passwordmanager.login(username, master_password)

        # Check for Errors.
        if login == "The entered password does not match the hashed password." or login == "Unable to locate the given user.":
            print("\nLogin details incorrect. Confirm your username and password.\nPress <Enter> to try again.")
            input(ascii_art.prompt)


def register(passwordmanager):
    '''The create account CLI brain.'''
    while not passwordmanager.logged_in:
        # Clear the console and print the create account screen.
        clear_console()
        print(ascii_art.create_account)
        print("Press <Enter> at any point to go back.")
        
        # Request the desired username.
        print("Please input your desired username:")
        username = input(ascii_art.prompt)

        # Basic check for exit.
        if username == "":
            break

        # Input your desired password twice.
        print("\nPlease input your master password:")
        master_password = getpass(prompt=ascii_art.prompt)
        
        # Basic check for exit.
        if master_password == "":
            break

        print("\nPlease input your master password again:")
        master_password2 = getpass(prompt=ascii_art.prompt)
        
        # Basic check for exit.
        if master_password2 == "":
            break

        # Attempt a registration.
        register = passwordmanager.create_account(username, master_password, master_password2)

        # Perform error checks
        if register == "Username already in use.":
            print("\nThat username is unavailable, please try again. (Hint: case does not matter in usernames.)\nPress <Enter> to confirm you understand.")
            input(ascii_art.prompt)

        elif register == "The passwords do not match.":
            print("\nThe passwords you entered did not match.\nPress <Enter> to confirm you understand.")
            input(ascii_art.prompt)


def start_pm_app():
    '''The home screen CLI brain.'''
    shutdown = False

    # Start the Password Manager application.
    pm = PasswordManager()

    # While the application is not shutdown.
    while not shutdown:

        # If the user is not logged in...
        if pm.logged_in:
            logged_in(pm)


        else:
            logged_out(pm)


    pm.save_data()



start_pm_app()