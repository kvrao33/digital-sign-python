import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import hashlib
import rsa

def generate_keys():
    try:
        (pubkey, privkey) = rsa.newkeys(2048)
        with open("public_key.pem", "wb") as f:
            f.write(pubkey.save_pkcs1())
        with open("private_key.pem", "wb") as f:
            f.write(privkey.save_pkcs1())
        return True
    except Exception as e:
        print(f"Key generation error: {e}")
        return False

def sign_message(message, private_key):
    try:
        hash_value = hashlib.sha256(message.encode('utf-8')).digest()
        signature = rsa.sign(hash_value, private_key, 'SHA-256')
        return signature
    except Exception as e:
        print(f"Signing error: {e}")
        return None

def verify_signature(message, signature, public_key):
    try:
        hash_value = hashlib.sha256(message.encode('utf-8')).digest()
        try:
            rsa.verify(hash_value, signature, public_key)
            return True
        except rsa.VerificationError:
            return False
    except Exception as e:
        print(f"Verification error: {e}")
        return False

def perform_action():
    action = action_var.get()
    message = message_text.get("1.0", tk.END).strip()

    if not message:
        messagebox.showerror("Error", "Please enter a message.")
        return

    if action == "Sign":
        key_path = private_key_entry.get()
        if not key_path:
            messagebox.showerror("Error", "Please select or enter the private key file path.")
            return
        try:
            with open(key_path, "rb") as f:
                private_key = rsa.PrivateKey.load_pkcs1(f.read())
            signature = sign_message(message, private_key)
            if signature:
                signature_text.delete("1.0", tk.END)
                signature_text.insert(tk.END, signature.hex())
                messagebox.showinfo("Success", "Message signed successfully.")
            else:
                messagebox.showerror("Error", "Signing failed.")
        except FileNotFoundError:
            messagebox.showerror("Error", "Private key file not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    elif action == "Verify":
        key_path = public_key_entry.get()
        if not key_path:
            messagebox.showerror("Error", "Please select or enter the public key file path.")
            return

        try:
            with open(key_path, "rb") as f:
                public_key = rsa.PublicKey.load_pkcs1(f.read())

            try:
                signature = bytes.fromhex(signature_text.get("1.0", tk.END).strip())
            except ValueError:
                messagebox.showerror("Error", "Invalid signature format (must be hex).")
                return

            if verify_signature(message, signature, public_key):
                messagebox.showinfo("Success", "Signature is valid.")
            else:
                messagebox.showerror("Error", "Signature is invalid.")
        except FileNotFoundError:
            messagebox.showerror("Error", "Public key file not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

def browse_key_file(entry):
    filepath = filedialog.askopenfilename(filetypes=[("PEM Files", "*.pem")])
    if filepath:
        entry.delete(0, tk.END)
        entry.insert(0, filepath)

        try:
            with open(filepath, "rb") as f:
                key_data = f.read()
                if "PRIVATE KEY" in key_data.decode():
                    try:
                        rsa.PrivateKey.load_pkcs1(key_data)
                    except:
                        messagebox.showwarning("Warning", "Could not parse the private key file.")

                elif "PUBLIC KEY" in key_data.decode():
                    try:
                        rsa.PublicKey.load_pkcs1(key_data)
                    except:
                       messagebox.showwarning("Warning", "Could not parse the public key file.")
                else:
                    messagebox.showwarning("Warning", "The selected file does not appear to be a valid RSA key file.")
        except FileNotFoundError:
            messagebox.showerror("Error", "Key file not found.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while loading the key: {e}")

def update_key_file_entries(*args):
    action = action_var.get()
    if action == "Sign":
        public_key_label.grid_forget()
        public_key_entry.grid_forget()
        public_key_browse_button.grid_forget()
        private_key_label.grid(row=4, column=0, pady=(10, 0))
        private_key_entry.grid(row=4, column=1)
        private_key_browse_button.grid(row=4, column=2)
    elif action == "Verify":
        private_key_label.grid_forget()
        private_key_entry.grid_forget()
        private_key_browse_button.grid_forget()
        public_key_label.grid(row=4, column=0, pady=(10, 0))
        public_key_entry.grid(row=4, column=1)
        public_key_browse_button.grid(row=4, column=2)

def create_gui():
    global action_var, message_text, signature_text, private_key_entry, public_key_entry, private_key_label, public_key_label, private_key_browse_button, public_key_browse_button

    window = tk.Tk()
    window.title("Digital Signature Tool")
    window.geometry("600x600")
    window.configure(bg="#f0f0f0")

    key_gen_button = tk.Button(window, text="Generate Keys", command=lambda: generate_keys() and messagebox.showinfo("Success", "Keys generated (or already existed)."), bg="#4CAF50", fg="white")
    key_gen_button.grid(row=0, column=0, columnspan=3, pady=(10, 0))

    action_var = tk.StringVar(value="Sign")
    action_var.trace("w", update_key_file_entries)

    action_label = tk.Label(window, text="Choose Action:", bg="#f0f0f0")
    action_label.grid(row=1, column=0, pady=(10, 0))
    action_menu = tk.OptionMenu(window, action_var, "Sign", "Verify")
    action_menu.grid(row=1, column=1)

    message_label = tk.Label(window, text="Enter Message:", bg="#f0f0f0")
    message_label.grid(row=2, column=0, pady=(10, 0))
    message_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=5)
    message_text.grid(row=2, column=1, pady=(10, 0))

    signature_label = tk.Label(window, text="Signature (Hex):", bg="#f0f0f0")
    signature_label.grid(row=3, column=0, pady=(10, 0))
    signature_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, height=5)
    signature_text.grid(row=3, column=1, pady=(10, 0))

    private_key_label = tk.Label(window, text="Private Key File:", bg="#f0f0f0")
    private_key_entry = tk.Entry(window, width=50)
    private_key_browse_button = tk.Button(window, text="Browse", command=lambda: browse_key_file(private_key_entry))

    public_key_label = tk.Label(window, text="Public Key File:", bg="#f0f0f0")
    public_key_entry = tk.Entry(window, width=50)
    public_key_browse_button = tk.Button(window, text="Browse", command=lambda: browse_key_file(public_key_entry))

    perform_button = tk.Button(window, text="Perform Action", command=perform_action, bg="#007bff", fg="white")
    perform_button.grid(row=5, column=0, columnspan=3, pady=(20, 0))

    update_key_file_entries()  # Call this to set up the initial UI state

    window.mainloop()

if __name__ == "__main__":
    create_gui()
