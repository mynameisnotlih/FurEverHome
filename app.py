"""
                FurEverHome Main Flask Application

This is the core backend file for the FurEverHome pet adoption web application.

It:
- Initialises the Flask app with CSRF, session, and file upload configurations.
- Manages routes for user authentication (signup, login, logout).
- Handles password reset functionality using token-based email-like links.
- Provides routes to add, edit, delete, and list pets for adoption.
- Allows users to submit, edit, or delete adoption requests.
- Enables pet owners to manage incoming requests and approve/deny them.
- Supports real-time chat between the pet owner and adopter when a request is approved.
- Implements a search system to find pets by name, species, or breed.
- Ensures security via hashed passwords, CSRF protection, and secure file handling.

This file also sets up and initialises the SQLite database (Users, Pets, AdoptionRequests, ChatMessages).

All routes are protected and structured with decorators and security mechanisms,
making it suitable for a beginner-friendly secure web application.

"""

# -----------------------------
# Core Framework & Database
# -----------------------------
from flask import Flask, render_template, redirect, url_for, request, session, flash  # Core Flask functions
from functools import wraps  # Used for decorators like login_required
import sqlite3  # Database engine: lightweight, serverless SQL

# -----------------------------
# Security & Utility Helpers
# -----------------------------
from werkzeug.security import generate_password_hash, check_password_hash  # Secure password hashing and validation
from werkzeug.utils import secure_filename  # Ensures uploaded filenames are safe
from datetime import timedelta  # Used to set session lifetime
import os  # Handles paths and directories

# -----------------------------
# CSRF Protection
# -----------------------------
from flask_wtf.csrf import CSRFProtect, CSRFError  # Protects against Cross-Site Request Forgery attacks

# -----------------------------
# Token-based Password Reset
# -----------------------------
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature  # Securely signs tokens with expiry
import uuid  # Generates unique IDs for files and other use

# -----------------------------
# Flask App Configuration
# -----------------------------
app = Flask(__name__)  # Initialise the Flask application
app.secret_key = "Furever_this_Key"  # Secret key used for sessions and CSRF protection

# -----------------------------
# Secure Session Settings
# -----------------------------
app.config["SESSION_COOKIE_HTTPONLY"] = True  # Prevent JS from accessing session cookie
app.config["SESSION_COOKIE_SECURE"] = False  # Should be True in production (HTTPS)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"  # Helps mitigate CSRF via browser rules
app.permanent_session_lifetime = timedelta(minutes=30)  # Session lifetime set to 30 minutes

# -----------------------------
# Enable CSRF Protection Globally
# -----------------------------
csrf = CSRFProtect(app)  # Enable CSRF protection on all forms

# -----------------------------
# CSRF Error Handler
# -----------------------------
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    # Handles form errors caused by expired/missing CSRF tokens
    flash("Security error: your form has expired or is invalid. Please try again.", "error")
    return redirect(request.referrer or url_for('login'))

# -----------------------------
# Initialise Database and Create Tables
# -----------------------------
def init_db():
    conn = sqlite3.connect('database.db')  # Connect to database
    cur = conn.cursor()

    # Users table: stores login credentials and user info
    cur.execute("""CREATE TABLE IF NOT EXISTS Users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name TEXT NOT NULL
                   )""")

    # Pets table: stores information about pets available for adoption
    cur.execute("""CREATE TABLE IF NOT EXISTS Pets (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        species TEXT NOT NULL,
                        breed TEXT,
                        age_years INTEGER,
                        age_months INTEGER,
                        description TEXT,
                        owner_id INTEGER,
                        photo TEXT,
                        FOREIGN KEY(owner_id) REFERENCES Users(id)
                   )""")

    # AdoptionRequests table: links users to pet requests, approval status, and messages
    cur.execute("""CREATE TABLE IF NOT EXISTS AdoptionRequests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pet_id INTEGER,
                        user_id INTEGER,
                        message TEXT,
                        status TEXT,
                        response_message TEXT,
                        chat_enable INTEGER DEFAULT 0,
                        FOREIGN KEY(pet_id) REFERENCES Pets(id),
                        FOREIGN KEY(user_id) REFERENCES Users(id)
                   )""")

    conn.commit()
    conn.close()

# Automatically create tables when app starts
init_db()

# -----------------------------
# Update Cookie Settings for Security
# -----------------------------
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,   # Re-confirmed: block JS from cookie access
    SESSION_COOKIE_SECURE=True,     # Re-confirmed: only send over HTTPS
    SESSION_COOKIE_SAMESITE='Lax'   # Re-confirmed: same-site protection
)

# -----------------------------
# File Upload Configuration
# -----------------------------
app.config['UPLOAD_FOLDER'] = os.path.join("static", "uploads")  # Folder to store uploaded images
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)  # Create folder if it doesn't exist
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}  # Allowed file types for uploads

# -----------------------------
# Setup Token Serializer
# -----------------------------
serializer = URLSafeTimedSerializer(app.secret_key)  # Used to generate and verify secure tokens

# -----------------------------
# File Extension Validation Function
# -----------------------------
def allowed_file(filename):
    # Check if file has an extension and is one of the allowed types
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# -----------------------------
# Login Required Decorator
# -----------------------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("You must be logged in to view this page.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

# -----------------------------
# Extract Form Data for Pets
# -----------------------------
def extract_pet_form_data():
    # Helper function to clean and extract data from pet form
    return {
        "name": request.form.get("name", "").strip(),
        "species": request.form.get("species", "").strip(),
        "breed": request.form.get("breed", "").strip(),
        "age_years": request.form.get("age_years", "").strip(),
        "age_months": request.form.get("age_months", "").strip(),
        "description": request.form.get("description", "").strip(),
    }

# Routes
# -----------------------------
# Forgot Password Route
# -----------------------------
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        # Show the "forgot password" form
        return render_template("forgot_password.html")

    # Get and validate the email from form input
    email = request.form.get("email", "").strip()

    if not email:
        flash("Please enter your email address.", "error")
        return render_template("forgot_password.html")

    # Check if user exists in the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT id FROM Users WHERE email = ?", (email,))
    user = cur.fetchone()
    conn.close()

    if not user:
        flash("No account found with that email address.", "error")
        return render_template("forgot_password.html")

    # Generate a token to be used in the reset URL (valid for 30 minutes)
    user_id = user[0]
    token = serializer.dumps(str(user_id), salt="password-reset-salt")

    # Generate the reset URL and display it on a separate page (simulating email)
    reset_url = url_for("reset_password", token=token, _external=True)
    return render_template("reset_link_display.html", reset_url=reset_url)

# -----------------------------
# Password Reset Route
# -----------------------------
@app.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    # Extract the token from the query or form data
    token = request.args.get("token") or request.form.get("token")

    try:
        # Validate the token (with max age of 30 mins)
        user_id = serializer.loads(token, salt="password-reset-salt", max_age=1800)
    except SignatureExpired:
        flash("The reset link has expired.", "error")
        return redirect(url_for("forgot_password"))
    except BadSignature:
        flash("The reset link is invalid.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "GET":
        # Show reset password form if token is valid
        return render_template("reset_password.html", token=token)

    # POST - handle the form submission
    password = request.form.get("password", "").strip()
    confirm = request.form.get("confirm_password", "").strip()

    if password != confirm:
        flash("Passwords don't match. Please try again.", "error")
        return redirect(url_for("reset_password", token=token))

    # Enforce password policy: length between 10–20 characters
    if len(password) < 10 or len(password) > 20:
        flash("Password must be between 10 and 20 characters long.", "error")
        return render_template("reset_password.html", token=token)

    # Enforce complexity: 1 uppercase, 1 lowercase, 1 number, 1 special character
    import re
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'
    if not re.match(pattern, password):
        flash("Password must include uppercase, lowercase, numbers, and special characters.", "error")
        return redirect(url_for("reset_password", token=token))

    # Check if new password is same as the old one
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT password_hash FROM Users WHERE id = ?", (user_id,))
    row = cur.fetchone()

    if row:
        current_hash = row[0]
        if check_password_hash(current_hash, password):
            flash("Your new password must be different from your current password.", "error")
            conn.close()
            return render_template("reset_password.html", token=token)

    # Update the user password securely
    hashed = generate_password_hash(password)
    cur.execute("UPDATE Users SET password_hash = ? WHERE id = ?", (hashed, user_id))
    conn.commit()
    conn.close()

    flash("Your password has been changed.", "success")
    return redirect(url_for("login"))

# -----------------------------
# User Registration (Signup)
# -----------------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        # Show the signup form
        return render_template("signup.html")

    # Gather form data
    username = request.form.get("username", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()
    full_name = request.form.get("full_name", "").strip()

    # Validate password confirmation
    if password != confirm_password:
        flash("Passwords do not match.", "error")
        return render_template("signup.html")

    # Validate all required fields
    if not username or not email or not password or not full_name:
        flash("All fields are required.", "error")
        return render_template("signup.html")

    # Enforce password length policy
    if len(password) < 10 or len(password) > 20:
        flash("Password must be between 10 and 20 characters.", "error")
        return render_template("signup.html")

    # Enforce password complexity policy
    import re
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$'
    if not re.match(pattern, password):
        flash("Password must include uppercase, lowercase, numbers, and special characters.", "error")
        return render_template("signup.html")

    # Check for duplicate username/email
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT id FROM Users WHERE username = ? OR email = ?", (username, email))
    existing = cur.fetchone()
    if existing:
        flash("Username or email already exists.", "error")
        conn.close()
        return render_template("signup.html")

    # Hash password and insert user into the database
    hashed_password = generate_password_hash(password)
    cur.execute("INSERT INTO Users (username, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
                (username, email, hashed_password, full_name))
    conn.commit()
    conn.close()

    flash("Account created successfully. Please, log in", "success")
    return redirect(url_for("login"))

# -----------------------------
# User Login
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Show the login form
        return render_template("login.html")

    # Get form input
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("Both username and password are required", "error")
        return render_template("login.html")

    # Authenticate user from the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash FROM Users WHERE username = ?", (username,))
    user = cur.fetchone()
    conn.close()

    # Invalid username
    if not user:
        flash("Invalid credentials", "error")
        return render_template("login.html")

    # Invalid password
    if not check_password_hash(user[2], password):
        flash("Invalid credentials.", "error")
        return render_template("login.html")

    # Successful login - set session
    session.clear()
    session["user_id"] = user[0]
    session["username"] = user[1]

    flash(f"Welcome back, {user[1]}!", "success")
    return redirect(url_for("list_pets"))

# -----------------------------
# User Logout
# -----------------------------
@app.route("/logout")
def logout():
    # Clear user session and redirect to login
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))

# -----------------------------
# Add a New Pet for Adoption
# -----------------------------
@app.route("/add_pet", methods=["GET", "POST"])
@login_required  # Ensure only logged-in users can add pets
def add_pet():
    if request.method == "GET":
        return render_template("add_pet.html")  # Display the pet form

    # Extract pet data from the form submission
    data = extract_pet_form_data()
    name = data["name"]
    species = data["species"]
    breed = data["breed"]
    age_years = data["age_years"]
    age_months = data["age_months"]
    description = data["description"]

    # Validate required fields
    if not name or not species or not breed:
        flash("Name, species, and breed are required.", "error")
        return render_template("add_pet.html")

    # Convert age fields to integers and validate they are not negative
    try:
        years = int(age_years) if age_years else 0
        months = int(age_months) if age_months else 0
        if years < 0 or months < 0:
            raise ValueError
    except ValueError:
        flash("Age must be a positive number.", "error")
        return render_template("add_pet.html")

    # Validate photo upload
    if 'photo' not in request.files:
        flash("Pet photo is required.", "error")
        return render_template("add_pet.html")

    photo = request.files['photo']
    if photo.filename == '':
        flash("Please select a photo.", "error")
        return render_template("add_pet.html")

    # Save photo securely if valid
    if photo and allowed_file(photo.filename):
        filename = secure_filename(photo.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        photo.save(upload_path)
        photo_path = f"uploads/{filename}"
    else:
        flash("Invalid photo format. Only PNG, JPG, JPEG, GIF allowed.", "error")
        return render_template("add_pet.html")

    # Insert new pet into the database
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()
    cur.execute("""INSERT INTO Pets (name, species, breed, age_years, age_months, description, owner_id, photo)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (name, species, breed, years, months, description, session["user_id"], photo_path))
    conn.commit()
    conn.close()

    flash("Pet added successfully!", "success")
    return redirect(url_for("list_pets"))

# -----------------------------
# View All Pets
# -----------------------------
@app.route("/list_pets")
@login_required
def list_pets():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM Pets")
    pets = cur.fetchall()

    # Get pet_ids this user requested
    cur.execute("SELECT pet_id FROM AdoptionRequests WHERE user_id = ?", (session["user_id"],))
    requested_pet_ids = [row["pet_id"] for row in cur.fetchall()]

    # Get approved adoption requests
    cur.execute("SELECT pet_id, user_id FROM AdoptionRequests WHERE status = 'Approved'")
    approved = cur.fetchall()
    approved_pet_ids = [row["pet_id"] for row in approved]
    pet_adopters = {row["pet_id"]: row["user_id"] for row in approved}

    # Get denied adoption requests
    cur.execute("SELECT pet_id, user_id FROM AdoptionRequests WHERE status = 'Deny'")
    denied = cur.fetchall()
    denied_pet_ids = [row["pet_id"] for row in denied]
    pet_denied_users = {row["pet_id"]: row["user_id"] for row in denied}

    conn.close()

    return render_template("list_pets.html", pets=pets,
                           requested_pet_ids=requested_pet_ids,
                           approved_pet_ids=approved_pet_ids,
                           pet_adopters=pet_adopters,
                           denied_pet_ids=denied_pet_ids,
                           pet_denied_users=pet_denied_users)

# -----------------------------
# Edit Pet Details
# -----------------------------
@app.route("/edit_pet/<int:pet_id>", methods=["GET", "POST"])
@login_required
def edit_pet(pet_id):
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Retrieve pet record
    cur.execute("SELECT * FROM Pets WHERE id = ?", (pet_id,))
    pet = cur.fetchone()

    if not pet:
        return render_template("404.html"), 404
    if pet["owner_id"] != session["user_id"]:
        return render_template("403.html"), 403

    if request.method == "POST":
        # Fetch updated values
        name = request.form.get("name", "").strip()
        species = request.form.get("species", "").strip()
        breed = request.form.get("breed", "").strip()
        age_years = request.form.get("age_years", "").strip()
        age_months = request.form.get("age_months", "").strip()
        description = request.form.get("description", "").strip()

        # Default to existing photo
        photo_path = pet["photo"]

        # Check for new photo
        if "photo" in request.files:
            photo = request.files["photo"]
            if photo and photo.filename != "":
                if allowed_file(photo.filename):
                    filename = f"{uuid.uuid4().hex}_{secure_filename(photo.filename)}"
                    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                    photo.save(upload_path)
                    photo_path = f"uploads/{filename}"
                else:
                    flash("Invalid image format. Only JPG, PNG, JPEG, GIF allowed.", "error")
                    return render_template("edit_pet.html", pet=pet)

        if not name or not species or not breed:
            flash("Name, species, and breed are required.", "error")

        # Update pet in the database
        cur.execute("""
                    UPDATE Pets 
                    SET name        = ?,
                        species     = ?,
                        breed       = ?,
                        age_years   = ?,
                        age_months  = ?,
                        description = ?,
                        photo       = ?
                    WHERE id = ?""",
                    (name, species, breed, age_years, age_months, description, photo_path, pet_id))
        conn.commit()
        conn.close()
        flash("Pet updated successfully!", "success")
        return redirect(url_for("list_pets"))

    conn.close()
    return render_template("edit_pet.html", pet=pet)

# -----------------------------
# Delete Pet
# -----------------------------
@app.route("/delete_pet/<int:pet_id>", methods=["POST"])
@login_required
def delete_pet(pet_id):
    conn = sqlite3.connect('database.db')
    cur = conn.cursor()

    # Check if pet exists and belongs to the current user
    cur.execute("SELECT owner_id FROM Pets WHERE id = ?", (pet_id,))
    pet = cur.fetchone()
    if not pet:
        return render_template("404.html"), 404
    if pet[0] != session["user_id"]:
        return render_template("403.html"), 403

    # Delete the pet
    cur.execute("DELETE FROM Pets WHERE id = ?", (pet_id,))
    conn.commit()
    conn.close()

    flash("Pet deleted successfully!", "info")
    return redirect(url_for("list_pets"))

# -----------------------------
# Send Adoption Request
# -----------------------------
@app.route("/adopt_pet/<int:pet_id>", methods=["POST"])
@login_required
def adopt_pet(pet_id):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # Confirm pet exists
    cur.execute("SELECT id FROM Pets WHERE id = ?", (pet_id,))
    if not cur.fetchone():
        return render_template("404.html"), 404

    # Prevent duplicate request
    cur.execute("SELECT id FROM AdoptionRequests WHERE pet_id = ? AND user_id = ?", (pet_id, session["user_id"]))
    if cur.fetchone():
        flash("You have already adopted this pet.", "warning")
        return redirect(url_for("list_pets"))

    # Create adoption request
    cur.execute("INSERT INTO AdoptionRequests (pet_id, user_id, message, status) VALUES (?, ?, ?, ?)",
                (pet_id, session["user_id"], "Interested in adopting", "Pending"))
    conn.commit()
    conn.close()

    flash("Adoption request sent!", "success")
    return redirect(url_for("my_requests"))

# -----------------------------
# View My Adoption Requests
# -----------------------------
@app.route("/my_requests")
@login_required
def my_requests():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Fetch all adoption requests made by the current user
    cur.execute("""
        SELECT ar.id,
               ar.pet_id,
               ar.status,
               ar.message,
               ar.response_message,
               ar.chat_enable,
               p.name AS pet_name
        FROM AdoptionRequests ar
        JOIN Pets p ON ar.pet_id = p.id
        WHERE ar.user_id = ?
    """, (session["user_id"],))

    requests = cur.fetchall()
    conn.close()

    return render_template("my_requests.html", requests=requests)

# -----------------------------
# Delete Adoption Request
# -----------------------------
@app.route("/delete_request/<int:request_id>", methods=["POST"])
@login_required
def delete_request(request_id):
    conn = sqlite3.connect("database.db")
    cur = conn.cursor()

    # Verify the request exists and belongs to the current user
    cur.execute("SELECT user_id FROM AdoptionRequests WHERE id = ?", (request_id,))
    req = cur.fetchone()
    if not req:
        return render_template("404.html"), 404
    if req[0] != session["user_id"]:
        return render_template("403.html"), 403

    # Delete the request
    cur.execute("DELETE FROM AdoptionRequests WHERE id = ?", (request_id,))
    conn.commit()
    conn.close()

    flash("Request deleted successfully!", "info")
    return redirect(url_for("my_requests"))

# -----------------------------
# Edit Adoption Request
# -----------------------------
@app.route("/edit_request/<int:request_id>", methods=["GET", "POST"])
@login_required
def edit_request(request_id):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Verify request exists and belongs to user
    cur.execute("""
        SELECT ar.*, p.name AS pet_name 
        FROM AdoptionRequests ar 
        JOIN Pets p ON ar.pet_id = p.id 
        WHERE ar.id = ? AND ar.user_id = ?
    """, (request_id, session["user_id"]))
    req = cur.fetchone()

    if not req:
        conn.close()
        return render_template("404.html"), 404

    # Handle form submission
    if request.method == "POST":
        new_message = request.form.get("message", "").strip()
        new_status = request.form.get("status", "").strip()

        if not new_message or not new_status:
            flash("Message and status can't be empty!", "error")
            return render_template("edit_request.html", req=req)

        cur.execute("UPDATE AdoptionRequests SET message = ?, status = ? WHERE id = ?",
                    (new_message, new_status, request_id))
        conn.commit()
        conn.close()

        flash("Request updated successfully!", "success")
        return redirect(url_for("my_requests"))

    conn.close()
    return render_template("edit_request.html", req=req)

# -----------------------------
# View Requests Received (Pet Owners)
# -----------------------------
@app.route("/owner_requests")
@login_required
def owner_requests():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Get all adoption requests for pets owned by the current user
    cur.execute("""
        SELECT ar.id, ar.pet_id, ar.user_id, ar.message, ar.status, 
               ar.response_message, u.username, p.name AS pet_name
        FROM AdoptionRequests ar
        JOIN Pets p ON ar.pet_id = p.id
        JOIN Users u ON ar.user_id = u.id
        WHERE p.owner_id = ?
    """, (session["user_id"],))

    requests = cur.fetchall()
    conn.close()

    return render_template("owner_requests.html", requests=requests)

# -----------------------------
# Handle Approval or Denial of Request (Pet Owner)
# -----------------------------
@app.route("/handle_request/<int:request_id>", methods=["GET", "POST"])
@login_required
def handle_request(request_id):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check if the request exists and the logged-in user owns the pet
    cur.execute("""
        SELECT ar.id,
               ar.pet_id,
               ar.user_id,
               ar.message,
               ar.status,
               ar.response_message,
               ar.chat_enable,
               p.name AS pet_name,
               u.username AS requester_name
        FROM AdoptionRequests ar
        JOIN Pets p ON ar.pet_id = p.id
        JOIN Users u ON ar.user_id = u.id
        WHERE ar.id = ? AND p.owner_id = ?
    """, (request_id, session["user_id"]))
    request_data = cur.fetchone()

    if not request_data:
        conn.close()
        return render_template("404.html"), 404

    # If form is submitted
    if request.method == "POST":
        decision = request.form.get("action")
        response_message = request.form.get("reason", "").strip() if decision == "Deny" else ""
        chat_enable = 1 if decision == "Approved" else 0

        # Update the request status, optional denial reason, and chat activation
        cur.execute("""
            UPDATE AdoptionRequests
            SET status = ?, response_message = ?, chat_enable = ?
            WHERE id = ?
        """, (decision, response_message, chat_enable, request_id))

        conn.commit()
        conn.close()

        flash(f"Request {decision.lower()}ed successfully.", "success")
        return redirect(url_for("owner_requests"))

    conn.close()
    return render_template("handle_request.html", request_data=request_data)

# -----------------------------
# Chat Between Owner and Adopter (If Approved)
# -----------------------------
@app.route("/chat/<int:request_id>", methods=["GET", "POST"])
@login_required
def chat(request_id):
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # Check if the user is either the adopter or the pet owner, and chat is enabled
    cur.execute("""
        SELECT ar.id, ar.user_id, p.owner_id, ar.chat_enable, p.name AS pet_name
        FROM AdoptionRequests ar
        JOIN Pets p ON ar.pet_id = p.id
        WHERE ar.id = ?
    """, (request_id,))
    chat_info = cur.fetchone()

    if not chat_info:
        flash("Chat request not found.", "error")
        return redirect(url_for("list_pets"))

    if session["user_id"] not in (chat_info["user_id"], chat_info["owner_id"]):
        flash("You are not authorized to view this chat.", "error")
        return redirect(url_for("list_pets"))

    if not chat_info["chat_enable"]:
        flash("Chat is not enabled for this request.", "warning")
        return redirect(url_for("list_pets"))

    # Handle new message submission
    if request.method == "POST":
        message = request.form.get("message", "").strip()
        if message:
            cur.execute("""
                INSERT INTO ChatMessages (request_id, sender_id, message)
                VALUES (?, ?, ?)
            """, (request_id, session["user_id"], message))
            conn.commit()
            flash("Message sent successfully.", "success")

    # Load all chat messages for this request
    cur.execute("""
        SELECT cm.message, cm.timestamp, u.username AS sender
        FROM ChatMessages cm
        JOIN Users u ON cm.sender_id = u.id
        WHERE cm.request_id = ?
        ORDER BY cm.timestamp
    """, (request_id,))
    messages = cur.fetchall()
    conn.close()

    return render_template("chat.html", messages=messages,
                           pet_name=chat_info["pet_name"],
                           request_id=request_id)

# -----------------------------
# Pet Search Feature
# -----------------------------
@app.route("/search")
def search():
    query = request.args.get("q", "").strip()
    results = []

    # If user typed a query, search by pet name, species, or breed
    if query:
        conn = sqlite3.connect("database.db")
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        # Use LIKE operator for partial matches (case-insensitive)
        search_term = f"%{query}%"
        cur.execute("""
            SELECT * FROM Pets 
            WHERE name LIKE ? OR species LIKE ? OR breed LIKE ?
        """, (search_term, search_term, search_term))
        results = cur.fetchall()
        conn.close()

    return render_template("search.html", query=query, results=results)

# -----------------------------
# Run the Flask Application
# -----------------------------
if __name__ == "__main__":
    app.run(debug=True)