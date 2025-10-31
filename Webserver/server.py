from flask import Flask, render_template, url_for, request, session, redirect, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
import os
from WEB_PM_App.passwordManager import PasswordManager
from WEB_PM_App.passwordGenerator import generate_secure_password # <-- RE-ADDED
from functools import wraps
from datetime import timedelta


# Create the login_required function to properly check if certain functions are logged in or not.
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check if the user is NOT logged in
        if session.get("logged_in") != True:
            
            # 2. Check if the request is an AJAX request (using your custom header)
            if request.headers.get('X-Requested-Content') == 'true':
                
                # For AJAX requests, return a 401 status code.
                return jsonify({"error": "Unauthorized"}), 401 
            
            else:
                # For full page requests, perform a standard server-side redirect
                return redirect(url_for("login"))
                
        # If logged in, proceed to the original function
        return f(*args, **kwargs)

    return decorated_function

# Create the Password Manager Instance.
pm = PasswordManager()

# Create a new flask app.
app = Flask(__name__)

# read the variable from the OS environment.
app.secret_key = os.environ.get("SECRET_KEY")

# Configure some Flask settings for security.
app.permanent_session_lifetime = timedelta(minutes=30)
app.config.update(
    # SESSION_COOKIE_SECURE=True,      # Requires HTTPS.
    PERMANENT_SESSION=True,  # Enables lifespan timer.
    SESSION_COOKIE_HTTPONLY=True,  # Protects from XSS.
    SESSION_COOKIE_SAMESITE="Lax",  # Protects from CSRF.
)

# Load the Limiter to assist in rate limiting.
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[
        "1000 per day",
        "200 per hour",
    ],  # Applies these limits to all routes by default
    storage_uri="memory://",
)


# Define and render the home page template.
@app.route("/")
def home():
    if session.get("logged_in"):
        return render_template("dashboard.html")

    else:
        return render_template("index.html")


# Define and render the login template.
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10/5minutes")
def login():

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        result = pm.login(username, password)

        if isinstance(result, tuple):
            # If the data is recieved Log the user in and REDIRECT
            username, encryption_key_bytes = result
            session["logged_in"] = True
            session["username"] = username
            session["encryption_key_b64"] = encryption_key_bytes.decode("utf-8")

            return redirect(url_for("home"))
        else:
            # if no data, Re-render the login page with an error.
            error_message = result  # result contains the error string.
            return render_template("login.html", error=error_message)

    else:
        return render_template("login.html")


# Define and render the signup template.
@app.route("/signup", methods=["GET", "POST"])
@limiter.limit("5/5minutes")
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password1 = request.form.get("password1", "").strip()
        password2 = request.form.get("password2", "").strip()

        result = pm.create_account(username, password1, password2)

        if isinstance(result, tuple):
            # If the data is recieved Log the user in and REDIRECT
            username, encryption_key_bytes = result
            session["logged_in"] = True
            session["username"] = username
            session["encryption_key_b64"] = encryption_key_bytes.decode("utf-8")

            return redirect(url_for("home"))
        else:
            # if no data, Re-render the login page with an error.
            error_message = result  # result contains the error string.
            return render_template("signup.html", error=error_message)

    # if len(username) < 3 or len(username) > 20:
    #     return render_template("signup.html", error="Username must be 3-20 characters.")

    # if len(password) < 8:
    #     return render_template("signup.html", error="Password must be at least 8 characters.")
    else:
        return render_template("signup.html")



@app.route("/logout")
@login_required
def logout():
    session.clear()  # This invalidates all session data immediately
    return redirect(url_for("home"))




# Dashboard loads.
@app.route('/list_passwords')
@login_required
def list_passwords():
    if request.headers.get('X-Requested-Content') == 'true' and session.get("logged_in") == True:
        username = session.get("username", 0)
        encryption_key = session.get("encryption_key_b64", 0)

        password_list = pm.list_saved_logins(user_username=username, encryption_key=encryption_key)

        return render_template('passwords_content.html', password_list=password_list)
    else:
        return redirect(url_for('home'))

@app.route('/settings')
@login_required
def settings():
    if request.headers.get('X-Requested-Content') == 'true' and session.get("logged_in") == True:
        return render_template('settings_content.html')
    else:
        return redirect(url_for('home'))








@app.route('/api/manage-login', methods=['POST'])
@login_required
def manage_login():
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    data = request.get_json()
    service_name = data.get('service_name')
    action = data.get('action') # Will be 'delete' or 'edit'
    
    username = session.get("username", "")
    encryption_key = session.get("encryption_key_b64", "")

    if not service_name or not action:
        return jsonify({"success": False, "message": "Missing ID or Action"}), 400

    try:
        if action == 'delete':
            # Call the specific manager function for deletion
            success = pm.delete_save(user_username=username, service_name=service_name)
            message = "Login successfully deleted."


        elif action == 'update':
            original_service_name = data.get('original_service_name')
            new_service_name = data.get('service_name')
            new_username = data.get('username')
            new_password = data.get('password')
            login_id = data.get('id') # Don't forget the ID from the hidden input!

            # --- Input Validation ---
            if not all([login_id, original_service_name, new_service_name, new_username, new_password]):
                return jsonify({"success": False, "message": "Missing required data for update."}), 400

            # --- Call the Password Manager Function ---
            try:
                if new_service_name == original_service_name:
                    success = pm.new_save(service_username=new_username, service_name=new_service_name, service_password=new_password, user_username=username, encryption_key=encryption_key)

                else:
                    success = pm.new_save(service_username=new_username, service_name=new_service_name, service_password=new_password, user_username=username, encryption_key=encryption_key, original_service_name=original_service_name)
 
            except Exception as e:
                print(f"Password Manager Update Error: {e}")
                return jsonify({"success": False, "message": "Manager failed to update record."}), 500

            # --- Send Response ---
            if success == "Login Saved":
                return jsonify({"success": True, "action": "update", "message": "Login updated."})
            else:
                return jsonify({"success": False, "message": "Update failed in manager (record not found?)."}), 404

        elif action == 'create':
            # --- HANDLE NEW LOGIN CREATION ---
            
            new_service_name = data.get('service_name')
            new_username = data.get('username')
            new_password = data.get('password')
            
            if not all([new_service_name, new_username, new_password]):
                return jsonify({"success": False, "message": "Missing fields for new login."}), 400

            success = pm.new_save(new_service_name, new_username, new_password, user_username=username, encryption_key=encryption_key)
            
            if success:
                # Triggers the client-side refresh to show the new record
                return jsonify({"success": True, "action": "create", "message": "Login successfully created."})
            else:
                return jsonify({"success": False, "message": "Creation failed in manager."}), 500
        
        else:
            return jsonify({"success": False, "message": "Invalid action specified."}), 400



        # Handle the success response for delete
        if success:
            return jsonify({"success": True, "action": action, "message": message})
        else:
            return jsonify({"success": False, "message": "Operation failed in manager."}), 500

    except Exception as e:
        print(f"Error during login management ({action}): {e}")
        return jsonify({"success": False, "message": "Server error."}), 500


@app.route('/api/generate-password', methods=['GET'])
@login_required
def generate_password_route():
    # Only authenticated users should be able to generate passwords
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        # Call the generator function (Using a default length of 16)
        new_password = generate_secure_password(length=20) 
        
        # Return the generated password as a JSON response
        return jsonify({"success": True, "password": new_password})

    except Exception as e:
        print(f"Password Generation Error: {e}")
        return jsonify({"success": False, "message": "Failed to generate password due to server issue."}), 500


@app.route('/api/change-master-password', methods=['POST'])
@login_required
def change_master_password_route():
    # 1. Authentication Check (login_required handles this for access)
    if not session.get("logged_in"):
        return jsonify({"success": False, "message": "Unauthorized"}), 401
    
    data = request.get_json()
    
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    confirm_new_password = data.get('confirm_new_password')
    
    username = session.get("username", "")
    encryption_key = session.get("encryption_key_b64", "")

    # 3. Call Core Manager Logic
    try:
        success, new_encryption_key = pm.change_master_password(user_username=username, old_password=old_password, new_password=new_password, new_password1=confirm_new_password, old_encryption_key=encryption_key)
        
        # 4. Return Final Response
        if success == "Master Password Changed.":
            # Update the session with the new encryption key for future operations
            session["encryption_key_b64"] = new_encryption_key
            return jsonify({"success": True, "message": "Master Password Changed Successfully."})
        
        # If the manager returned a specific error message string
        elif isinstance(success, str):
            # This handles incorrect password, passwords not matching, or user not found errors
            return jsonify({"success": False, "message": success}), 400
        
        else:
            # Catch-all for unexpected manager failure
            return jsonify({"success": False, "message": "An unknown error occurred during password change."}), 500
            
    except Exception as e:
        print(f"Master Password Update Error: {e}")
        return jsonify({"success": False, "message": "Internal server error. Check logs."}), 500


# Handle rate limiting.
@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    # 1. Determine the endpoint that was limited
    endpoint = request.endpoint  # Get the name of the view function being executed

    # 2. Check for the login route (specific handling)
    if endpoint == "login":
        # For the login page, return to login.html with a clear error
        return (
            render_template(
                "login.html",
                error="Too many failed login attempts. Please wait 5 minutes before trying again.",
            ),
            429,
        )
    

    elif endpoint == "signup":
        # For the Signup page, return to login.html with a clear error
        return (
            render_template(
                "signup.html",
                error="Too many failed sign up attempts. Please wait 5 minutes before trying again.",
            ),
            429,
        )

    # 3. Check for other protected routes (general application handling)
    elif endpoint in ["dashboard", "list_saves", "new_save"]:
        # For general browsing, return a less aggressive message to an error template
        # Assume you have an 'error.html' template
        return (
            render_template(
                "error.html",
                message=f"You have exceeded your usage limit for this feature. Please try again in {e.retry_after}.",
            ),
            429,
        )

    # 4. CATCH-ALL DEFAULT (Resolves the Pylance 'None' issue)
    # This path handles any other rate-limited endpoint (like an API route)
    else:
        # Return a simple JSON response or a generic message
        return (
            jsonify(message=f"Rate limit exceeded. Try again in {e.retry_after}."),
            429,
        )


# If running in the code editor, run the application.
if __name__ == "__main__":
   app.run(debug=True)