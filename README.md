# Fur-Ever Home - Adopt With Care!

Fur-Ever Home is a secure web-based pet adoption platform built with Flask and SQLite. The application allows users to register, list pets for adoption, request to adopt pets, and communicate securely through a built-in chat feature once a request has been approved.

## Features

- 🐾 User registration and login (with password hashing)
- 📸 Add, edit, and delete pets with photo uploads
- 📬 Request to adopt pets
- ✅ Pet owners can approve or deny requests, including a reason for denial
- 💬 Secure chat feature between adopter and owner after approval
- 🔍 Search functionality to find pets by name, species or breed
- 🔐 Forgot password and password reset functionality
- 🛡️ CSRF protection and secure session handling

## 🛠 Technologies Used

- **Python 3**
- **Flask** – Web framework
- **SQLite** – Embedded database
- **Flask-WTF** – For CSRF protection
- **Werkzeug** – For password hashing
- **itsdangerous** – For generating secure tokens
- **HTML/CSS** – For UI structure and styling
- **Jinja2** – Flask's templating engine

---

## 📁 Folder Structure

```bash
FurEverHome/
├── app.py # Main application file
├── alter_table.py # Alter/Modify database
├── database.db # SQLite database (created automatically)
├── requirements.txt # Dependencies file
├── README.md # README file
├── static/
│ └── uploads/ # Folder for uploaded pet photos
│ └── styles.css # CSS style
├── templates/
│ ├── add_pet.html
│ ├── base.html
│ ├── chat.html
│ ├── edit_pet.html
│ ├── edit_request.html
│ ├── forgot_password.html
│ ├── handle_requests.html
│ ├── owner_requests.html
│ ├── reset_link_display.html
│ ├── reset_password.html
│ ├── search.html
│ ├── signup.html
```

## 🧪 How the System Works

### 👥 For General Users
- Register and log in securely
- Browse available pets listed by owners
- Submit adoption requests with a message
- View request statuses (`Pending`, `Denied`, or `Approved`)
- If approved, initiate a chat with the pet owner

### 👤 For Pet Owners
- Add pets for adoption, including photos
- View all adoption requests made for their pets
- Approve or deny requests and include a response message
- Start a chat with adopters after approval

---

## 🔐 Adoption Status Logic

| Situation                               | What the User Sees                            |
|----------------------------------------|-----------------------------------------------|
| Request is Pending                     | Greyed out “Requested” button (disabled)      |
| Request is Denied (for that user only) | Greyed out “Denied” button (disabled)         |
| Request is Approved                    | Greyed out “Adoption Accepted” button         |
| No Request Sent                        | Green “Request Adoption” button (active)      |

---

## 🔒 Security & Best Practices

- Passwords are **hashed** using Werkzeug
- CSRF protection is enabled for all forms via Flask-WTF
- Sessions are secure, HTTPOnly and use `SameSite=Lax`
- Password reset flow uses **signed tokens** via itsdangerous
- Only authenticated users can access pet-related or chat pages
- Users **cannot reuse their previous password** when resetting via the password reset form

---

## Installation & Running the Project

1. **Clone the Repository**

   ```bash
   git clone https://github.com/mynameisnotlih/FurEverHome
   cd FurEverHome
   ```
2. **(Optional) Create a Virtual Environment**
   ```bash
   python -m venv venv
   source venv/bin/activate        # On Windows use `venv\Scripts\activate`
   ```
3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Run the App**
   ```bash
   python app.py
   ```
5. **Access the App in Your Browser**
   ```bash
   http://127.0.0.1:5000
   ```
📜 Licence

This project was created for educational purposes and is not intended for production use. All rights reserved to the original author.

Fur-Ever Home – Helping paws find loving homes ❤️