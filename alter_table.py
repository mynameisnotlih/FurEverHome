"""
alter_table.py — Database Migration Script

This script is used to modify and upgrade the existing database schema without dropping data.
It is useful when you need to introduce new features (like messaging or chat) and require:
- new columns in existing tables (e.g., `response_message`, `chat_enable`, `photo`)
- new tables (e.g., `ChatMessages`, `Messages`)
- updating data to standardize values (e.g., changing `"Approve"` to `"Approved"`)

It uses try-except blocks to ensure the script can be safely re-run without crashing if columns or tables already exist.
"""

import sqlite3  # Used to connect and execute raw SQL queries on SQLite

# Connect to the existing database file (or create one if it doesn't exist)
conn = sqlite3.connect('database.db')
cur = conn.cursor()

# -----------------------------
# Modify AdoptionRequests table
# -----------------------------

# Try to add a 'response_message' column (used for denial messages)
try:
    cur.execute("ALTER TABLE AdoptionRequests ADD COLUMN response_message TEXT;")
except sqlite3.OperationalError:
    print("response_message column already exists in AdoptionRequests table. Skipping this step.")

# Try to add a 'chat_enable' column (used to activate chat after approval)
try:
    cur.execute("ALTER TABLE AdoptionRequests ADD COLUMN chat_enable INTEGER DEFAULT 0;")
except sqlite3.OperationalError:
    print("chat_enable column already exists in AdoptionRequests table. Skipping this step.")

# -----------------------------
# Modify Pets table to add photo support
# -----------------------------

# Try to add a 'photo' column to store the file path of uploaded images
try:
    cur.execute("ALTER TABLE Pets ADD COLUMN photo TEXT")
except sqlite3.OperationalError:
    print("photo column already exists in Pets table. Skipping this step.")

# -----------------------------
# Create ChatMessages table
# -----------------------------

# Table to support live chat between pet owners and adopters after approval
try:
    cur.execute("""
        CREATE TABLE IF NOT EXISTS ChatMessages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique message ID
            request_id INTEGER NOT NULL,                    -- Related adoption request
            sender_id INTEGER NOT NULL,                     -- Sender (owner or adopter)
            message TEXT NOT NULL,                          -- Message content
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,   -- Auto-set message timestamp
            FOREIGN KEY(request_id) REFERENCES AdoptionRequests(id),
            FOREIGN KEY(sender_id) REFERENCES Users(id)
        )
    """)
    print("ChatMessages table created successfully.")
except sqlite3.OperationalError as e:
    print("Error creating ChatMessages table:", e)

# -----------------------------
# Create Fallback Messages Table (Optional General Messaging)
# -----------------------------

# Table to store messages (more generic use, across pets/users)
cur.execute("""
    CREATE TABLE IF NOT EXISTS Messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,           -- Unique message ID
        sender_id INTEGER NOT NULL,                     -- User who sent the message
        receiver_id INTEGER NOT NULL,                   -- Recipient user
        pet_id INTEGER NOT NULL,                        -- Related pet
        message TEXT NOT NULL,                          -- Content of the message
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,   -- Timestamp auto-generated
        FOREIGN KEY(sender_id) REFERENCES Users(id),
        FOREIGN KEY(receiver_id) REFERENCES Users(id),
        FOREIGN KEY(pet_id) REFERENCES Pets(id)
    )
""")

# -----------------------------
# Data Normalization
# -----------------------------

# Update any row with "Approve" status to say "Approved" (for consistency)
cur.execute("""
    UPDATE AdoptionRequests 
    SET status = "Approved" 
    WHERE status = "Approve"; 
""")

# -----------------------------
# Finalise changes and close
# -----------------------------

# Commit all changes to the database file
conn.commit()
conn.close()

# Confirmation message
print("AdoptionRequests table updated successfully, and Messages table created. Exiting script.")