from flask import Flask, render_template, url_for, request
from dotenv import load_dotenv
import os

# Load variables from the .env file
load_dotenv()


# Create a new flask app.
app = Flask(__name__)

# read the variable from the OS environment.
app.secret_key = os.environ.get('SECRET_KEY')

# Configure some Flask settings for security.
app.config.update(
    # SESSION_COOKIE_SECURE=True,      # Requires HTTPS
    SESSION_COOKIE_HTTPONLY=True,    # Protects from XSS
    SESSION_COOKIE_SAMESITE='Lax'    # Protects from CSRF
)

# Define and render the home page template.
@app.route("/")
def home():

    return render_template("index.html")


# Define and render the login template.
@app.route("/login")
def login():

    return render_template("login.html")



# Define and render the signup template.
@app.route("/signup")
def signup():

    return render_template("signup.html")


# If running in the code editor, run the application.
if __name__ == '__main__':
    app.run(debug=True)