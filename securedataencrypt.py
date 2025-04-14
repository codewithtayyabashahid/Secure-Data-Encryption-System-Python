import streamlit as st
import hashlib
import json
from cryptography.fernet import Fernet
import time
import os

# === Configuration ===
DATA_FILE = "secure_data.json"
FAILED_ATTEMPTS_THRESHOLD = 3
LOCKOUT_DURATION = 60  # seconds
MASTER_PASSWORD = "admin123"  # Replace with a more secure method in production

# === Session State Initialization ===
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

# === Data Loading and Saving ===
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            try:
                st.session_state.stored_data = json.load(f)
            except json.JSONDecodeError:
                st.warning("Warning: Could not decode data file. Starting with empty data.")
                st.session_state.stored_data = {}
    else:
        st.session_state.stored_data = {}

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(st.session_state.stored_data, f)

# Load data on app start
load_data()

# === Security Functions ===
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    key = Fernet.generate_key()  # Generate a unique key for each piece of data
    cipher = Fernet(key)
    encrypted_text = cipher.encrypt(text.encode()).decode()
    hashed_passkey = hash_passkey(passkey)
    return {"encrypted_text": encrypted_text, "passkey": hashed_passkey, "encryption_key": key.decode()}

def decrypt_data(data_item, passkey):
    if st.session_state.logged_in:
        if data_item["passkey"] == hash_passkey(passkey):
            cipher = Fernet(data_item["encryption_key"].encode())
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = 0
            return cipher.decrypt(data_item["encrypted_text"].encode()).decode()
        else:
            st.session_state.failed_attempts += 1
            st.warning(f"⚠️ Incorrect passkey! Attempts remaining: {FAILED_ATTEMPTS_THRESHOLD - st.session_state.failed_attempts}")
            if st.session_state.failed_attempts >= FAILED_ATTEMPTS_THRESHOLD:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.session_state.logged_in = False
                st.info(f"🔒 Too many failed attempts. Please log in again after {LOCKOUT_DURATION} seconds.")
            return None
    else:
        st.info("🔑 Please log in to retrieve data.")
        return None

# === Streamlit UI ===
st.title("🔒 Secure Data Encryption System")

# Check for lockout
if time.time() < st.session_state.lockout_time:
    remaining_time = int(st.session_state.lockout_time - time.time())
    st.error(f"🔒 Account locked. Please try again after {remaining_time} seconds.")
else:
    menu = ["Home", "Store Data", "Retrieve Data"]
    if not st.session_state.logged_in:
        menu.append("Login")
    choice = st.sidebar.selectbox("Navigation", menu)

    if choice == "Home":
        st.subheader("🏠 Welcome to the Secure Data System")
        st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
        st.write(f"Failed Attempts: {st.session_state.failed_attempts}")

    elif choice == "Store Data":
        if st.session_state.logged_in:
            st.subheader("📂 Store Data Securely")
            user_data = st.text_area("Enter Data:")
            passkey = st.text_input("Enter Passkey:", type="password")
            data_id = st.text_input("Enter a unique ID for this data:")

            if st.button("Encrypt & Save"):
                if user_data and passkey and data_id:
                    if data_id in st.session_state.stored_data:
                        st.warning("⚠️ Data ID already exists. Please choose a unique ID.")
                    else:
                        encrypted_info = encrypt_data(user_data, passkey)
                        st.session_state.stored_data[data_id] = encrypted_info
                        save_data()
                        st.success(f"✅ Data stored securely with ID: {data_id}!")
                else:
                    st.error("⚠️ All fields (Data, Passkey, and Data ID) are required!")
        else:
            st.info("🔑 Please log in to store data.")

    elif choice == "Retrieve Data":
        if st.session_state.logged_in:
            st.subheader("🔍 Retrieve Your Data")
            data_id_to_retrieve = st.text_input("Enter the ID of the data to retrieve:")
            passkey_to_decrypt = st.text_input("Enter Passkey:", type="password")

            if st.button("Decrypt"):
                if data_id_to_retrieve and passkey_to_decrypt:
                    if data_id_to_retrieve in st.session_state.stored_data:
                        decrypted_text = decrypt_data(st.session_state.stored_data[data_id_to_retrieve], passkey_to_decrypt)
                        if decrypted_text is not None:
                            st.success(f"✅ Decrypted Data: {decrypted_text}")
                    else:
                        st.error("⚠️ Data ID not found!")
                else:
                    st.error("⚠️ Both Data ID and Passkey are required!")
        else:
            st.info("🔑 Please log in to retrieve data.")

    elif choice == "Login":
        st.subheader("🔑 Reauthorization Required")
        login_pass = st.text_input("Enter Master Password:", type="password")

        if st.button("Login"):
            if login_pass == MASTER_PASSWORD:
                st.session_state.logged_in = True
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = 0
                st.success("✅ Logged in successfully!")
                st.experimental_rerun()
            else:
                st.error("❌ Incorrect password!")