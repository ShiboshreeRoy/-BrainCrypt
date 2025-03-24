import sys
import os
import threading
import secrets
import logging
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Setup Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# AES-GCM Encryption/Decryption Class
class AESGCMCipher:
    def __init__(self, key=None):
        self.key = key if key else secrets.token_bytes(16)  # Generate a 16-byte key
    
    def encrypt(self, plaintext):
        iv = secrets.token_bytes(12)  # 12-byte IV for GCM
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode('utf-8')) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext  # Concatenating IV, tag, and ciphertext

    def decrypt(self, encrypted_data):
        iv = encrypted_data[:12]  # Extract IV
        tag = encrypted_data[12:28]  # Extract authentication tag
        ciphertext = encrypted_data[28:]  # Extract ciphertext
        
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext.decode('utf-8')  # Convert bytes to string


# GUI Wrapper
class BrainCryptGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("BrainCrypt - Secure Encryption Tool")
        self.master.geometry("500x500")
        self.master.config(bg="#f0f0f5")  # Light gray background

        self.cipher = AESGCMCipher()
        
        # Font and Color Styles
        self.font_style = ("Helvetica", 12)
        self.button_style = {'relief': 'flat', 'bg': '#007bff', 'fg': 'white', 'font': ('Helvetica', 10, 'bold')}
        self.button_hover_style = {'relief': 'flat', 'bg': '#0056b3', 'fg': 'white', 'font': ('Helvetica', 10, 'bold')}
        
        # Navbar
        self.create_navbar()

        # Title
        title_label = tk.Label(master, text="BrainCrypt", font=("Helvetica", 18, "bold"), fg="#333", bg="#f0f0f5")
        title_label.pack(pady=10)

        # File Selection
        tk.Label(master, text="Select File to Encrypt/Decrypt:", font=self.font_style, bg="#f0f0f5").pack(pady=5)
        self.file_entry = tk.Entry(master, width=50, font=self.font_style, relief="solid")
        self.file_entry.pack(pady=5)
        tk.Button(master, text="Browse", command=self.browse_file, **self.button_style).pack(pady=10)
        
        # Buttons
        tk.Button(master, text="Encrypt", command=self.start_encrypt, **self.button_style).pack(pady=10)
        tk.Button(master, text="Decrypt", command=self.start_decrypt, **self.button_style).pack(pady=10)

        # Progress Bar
        self.progress_label = tk.Label(master, text="", font=self.font_style, bg="#f0f0f5")
        self.progress_label.pack(pady=5)
        
        self.progress = ttk.Progressbar(master, orient="horizontal", length=300, mode="determinate", style="TProgressbar")
        self.progress.pack(pady=5)

        # Status Label
        self.status_label = tk.Label(master, text="", font=self.font_style, fg="blue", bg="#f0f0f5")
        self.status_label.pack(pady=10)

        # Customizing Progressbar Style
        style = ttk.Style()
        style.configure("TProgressbar",
                        thickness=25,
                        font=("Helvetica", 10),
                        background="#28a745",  # Green progress bar color
                        )

        # Hover effects for buttons
        self.create_button_hover_effects()

    def create_navbar(self):
        navbar = tk.Menu(self.master, bg="#007bff", fg="white", font=("Helvetica", 12, "bold"))
        self.master.config(menu=navbar)

        # File menu with subcategories
        file_menu = tk.Menu(navbar, tearoff=0, bg="#f0f0f5", fg="#333", font=("Helvetica", 12))
        navbar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New File", command=self.new_file)
        file_menu.add_command(label="Open File", command=self.open_file)
        file_menu.add_command(label="Save File", command=self.save_file)
        file_menu.add_separator()
        file_menu.add_command(label="Open Folder", command=self.open_folder)

        # About menu
        about_menu = tk.Menu(navbar, tearoff=0, bg="#f0f0f5", fg="#333", font=("Helvetica", 12))
        navbar.add_cascade(label="About", menu=about_menu)
        about_menu.add_command(label="Developer Info", command=self.show_about)
        about_menu.add_command(label="Version", command=self.show_version)

        # Features menu
        features_menu = tk.Menu(navbar, tearoff=0, bg="#f0f0f5", fg="#333", font=("Helvetica", 12))
        navbar.add_cascade(label="Features", menu=features_menu)
        features_menu.add_command(label="Upcoming Features", command=self.upcoming_features)

    def create_button_hover_effects(self):
        """Create hover effects for buttons."""
        for button in self.master.winfo_children():
            if isinstance(button, tk.Button):
                button.bind("<Enter>", self.on_hover)
                button.bind("<Leave>", self.on_leave)

    def on_hover(self, event):
        """Change button color on hover."""
        event.widget.config(bg="#0056b3")

    def on_leave(self, event):
        """Reset button color after hover."""
        event.widget.config(bg="#007bff")

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def start_encrypt(self):
        file_path = self.file_entry.get()
        if not file_path:
            messagebox.showerror("Error", "No file selected!")
            return
        
        self.progress["value"] = 0
        self.progress_label.config(text="Encrypting...", fg="blue")
        self.status_label.config(text="")
        
        threading.Thread(target=self.encrypt_file, args=(file_path,), daemon=True).start()

    def encrypt_file(self, file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                plaintext = f.read()

            encrypted_data = self.cipher.encrypt(plaintext)
            encrypted_file_path = file_path + ".enc"
            
            with open(encrypted_file_path, "wb") as f:
                f.write(self.cipher.key + encrypted_data)  # Store key with ciphertext
            self.progress["value"] = 100
            self.progress_label.config(text="Encryption Complete", fg="green")
            self.status_label.config(text=f"Encrypted File: {encrypted_file_path}", fg="green")
        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            messagebox.showerror("Error", f"Encryption failed: {e}")

    def start_decrypt(self):
        file_path = self.file_entry.get()
        if not file_path:
            messagebox.showerror("Error", "No file selected!")
            return

        self.progress["value"] = 0
        self.progress_label.config(text="Decrypting...", fg="blue")
        self.status_label.config(text="")

        threading.Thread(target=self.decrypt_file, args=(file_path,), daemon=True).start()

    def decrypt_file(self, file_path):
        try:
            with open(file_path, "rb") as f:
                data = f.read()

            key = data[:16]  # Extract stored key
            encrypted_data = data[16:]  # Rest is encrypted content

            cipher = AESGCMCipher(key)
            decrypted_text = cipher.decrypt(encrypted_data)

            decrypted_file_path = file_path.replace(".enc", "_decrypted.txt")
            
            with open(decrypted_file_path, "w", encoding="utf-8") as f:
                f.write(decrypted_text)
            
            self.progress["value"] = 100
            self.progress_label.config(text="Decryption Complete", fg="green")
            self.status_label.config(text=f"Decrypted File: {decrypted_file_path}", fg="green")
        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            messagebox.showerror("Error", f"Decryption failed: {e}")

    # File Menu Commands
    def new_file(self):
        self.file_entry.delete(0, tk.END)

    def open_file(self):
        file_path = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def save_file(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.file_entry.get())

    def open_folder(self):
        folder_path = filedialog.askdirectory()
        messagebox.showinfo("Open Folder", f"Opened folder: {folder_path}")

    # About Menu Commands
    def show_about(self):
        messagebox.showinfo("Developer Info", "BrainCrypt is developed by SHiboshree Roy. For more details, visit our website.")

    def show_version(self):
        messagebox.showinfo("Version", "Version 1.0.0")

    # Features Menu Commands
    def upcoming_features(self):
        messagebox.showinfo("Upcoming Features", "1. Multi-file encryption support\n2. Cloud sync\n3. Improved encryption algorithms")

# Run GUI
if __name__ == "__main__":
    root = tk.Tk()
    app = BrainCryptGUI(root)
    root.mainloop()
