import os
from tkinter import filedialog, messagebox, simpledialog, Tk, Button, Label
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16  # AES block size
KEY_LEN = 32     # For AES-256

def pad(data):
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

def derive_key(password, salt):
    return PBKDF2(password, salt, dkLen=KEY_LEN)

def encrypt_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return

    password = simpledialog.askstring("Password", "Enter encryption password:", show='*')
    if not password:
        return

    with open(file_path, 'rb') as f:
        plaintext = f.read()

    salt = get_random_bytes(16)
    key = derive_key(password.encode(), salt)
    iv = get_random_bytes(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext))

    encrypted_data = salt + iv + ciphertext
    new_file = file_path + ".enc"
    with open(new_file, 'wb') as f:
        f.write(encrypted_data)

    messagebox.showinfo("Success", f"File encrypted:\n{new_file}")

def decrypt_file():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted Files", "*.enc")])
    if not file_path:
        return

    password = simpledialog.askstring("Password", "Enter decryption password:", show='*')
    if not password:
        return

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]

    key = derive_key(password.encode(), salt)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext))
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file.")
        return

    new_file = file_path.replace(".enc", "_decrypted")
    with open(new_file, 'wb') as f:
        f.write(plaintext)

    messagebox.showinfo("Success", f"File decrypted:\n{new_file}")

# GUI setup
root = Tk()
root.title("AES-256 File Encryptor")
root.geometry("300x150")
Label(root, text="AES-256 File Encryption Tool", font=('Helvetica', 12, 'bold')).pack(pady=10)
Button(root, text="Encrypt File", command=encrypt_file, width=25).pack(pady=5)
Button(root, text="Decrypt File", command=decrypt_file, width=25).pack(pady=5)
root.mainloop()
