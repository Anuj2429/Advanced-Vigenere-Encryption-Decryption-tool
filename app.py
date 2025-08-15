import tkinter as tk
from tkinter import ttk, messagebox, filedialog

from constants import *
from crypto_core import encrypt_bytes, decrypt_bytes, package_text, unpackage_text
from file_io import read_file, write_file
from validators import sanitize_key, validate_key_or_raise, needs_short_key_warning

# ---------- UI helpers ----------

def copy_to_clipboard(root: tk.Tk, text: str):
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()  # keeps clipboard after app closes

# ---------- Main App ----------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1000x700")
        self.configure(bg=DARK_BG)
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        # Basic dark-ish ttk styling
        self.style.configure("TLabel", foreground=DARK_FG, background=DARK_BG)
        self.style.configure("TButton", padding=6)
        self.style.configure("TFrame", background=DARK_BG)
        self.style.configure("TRadiobutton", foreground=DARK_FG, background=DARK_BG)

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=8, pady=8)

        self.encrypt_tab = EncryptFrame(self)
        self.decrypt_tab = DecryptFrame(self)

        nb.add(self.encrypt_tab, text="Encrypt")
        nb.add(self.decrypt_tab, text="Decrypt")

class EncryptFrame(ttk.Frame):
    def __init__(self, root: App):
        super().__init__(root)
        self.root = root

        # --- Input mode controls ---
        self.mode = tk.StringVar(value="text")  # "text" | "file"
        mode_bar = ttk.Frame(self); mode_bar.pack(fill="x", pady=6)
        ttk.Radiobutton(mode_bar, text="Text Mode", value="text", variable=self.mode).pack(side="left", padx=4)
        ttk.Radiobutton(mode_bar, text="File Mode", value="file", variable=self.mode).pack(side="left", padx=4)

        # --- Text area ---
        self.text_in = tk.Text(self, height=18, wrap="word", bg="#111527", fg=DARK_FG, insertbackground=DARK_FG)
        self.text_in.pack(fill="both", expand=True, padx=4, pady=4)

        # --- File picker ---
        self.file_path = tk.StringVar()
        file_bar = ttk.Frame(self); file_bar.pack(fill="x")
        ttk.Entry(file_bar, textvariable=self.file_path, state="readonly").pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(file_bar, text="Browse…", command=self.browse_file).pack(side="left")

        # --- Key row ---
        key_bar = ttk.Frame(self); key_bar.pack(fill="x", pady=6)
        ttk.Label(key_bar, text="Key:").pack(side="left")
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_bar, textvariable=self.key_var, show="*")
        self.key_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.showing = False
        ttk.Button(key_bar, text="Show", command=self.toggle_key).pack(side="left", padx=4)
        ttk.Button(key_bar, text="Generate Key", command=self.generate_key).pack(side="left", padx=4)
        ttk.Button(key_bar, text="Copy Key", command=self.copy_key).pack(side="left", padx=4)

        # --- Action + Output (for text mode) ---
        action_bar = ttk.Frame(self); action_bar.pack(fill="x", pady=8)
        ttk.Button(action_bar, text="Encrypt", command=self.on_encrypt).pack(side="left")

        ttk.Label(self, text="Output:").pack(anchor="w")
        self.text_out = tk.Text(self, height=12, wrap="word", bg="#0d1222", fg=DARK_FG, insertbackground=DARK_FG)
        self.text_out.pack(fill="both", expand=False, padx=4, pady=4)
        out_bar = ttk.Frame(self); out_bar.pack(fill="x")
        ttk.Button(out_bar, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(out_bar, text="Save Output…", command=self.save_output_text).pack(side="left", padx=4)

        # React to mode change (optional enable/disable widgets)
        self.mode.trace_add("write", lambda *_: self.update_mode_visibility())
        self.update_mode_visibility()

    def update_mode_visibility(self):
        is_text = self.mode.get() == "text"
        self.text_in.configure(state="normal" if is_text else "disabled")

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def toggle_key(self):
        self.showing = not self.showing
        self.key_entry.configure(show="" if self.showing else "*")

    def generate_key(self):
        import secrets, string
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.?"
        rnd = "".join(secrets.choice(alphabet) for _ in range(32))
        self.key_var.set(rnd)

    def copy_key(self):
        copy_to_clipboard(self.root, self.key_var.get())
        messagebox.showinfo("Copied", "Key copied to clipboard.")

    def copy_output(self):
        copy_to_clipboard(self.root, self.text_out.get("1.0", "end-1c"))
        messagebox.showinfo("Copied", "Output copied to clipboard.")

    def save_output_text(self):
        data_text = self.text_out.get("1.0", "end-1c")
        if not data_text.strip():
            messagebox.showwarning("Nothing to save", "Output area is empty.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "wb") as f:
                f.write(data_text.encode("utf-8"))
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def on_encrypt(self):
        key = sanitize_key(self.key_var.get())
        try:
            validate_key_or_raise(key)
        except ValueError as e:
            messagebox.showerror("Invalid key", str(e)); return

        # Short key popup
        if needs_short_key_warning(key):
            if not messagebox.askyesno("Short Key Warning",
                "Your key is shorter than 8 characters.\n"
                "Short keys are easier to break.\n\n"
                "Do you still want to continue?"):
                return

        if self.mode.get() == "text":
            src = self.text_in.get("1.0", "end-1c").encode("utf-8")
            if not src:
                messagebox.showwarning("Missing input", "Please enter text to encrypt.")
                return
            salt, cipher = encrypt_bytes(src, key)
            pkg = package_text(salt, cipher, DELIM)
            self.text_out.delete("1.0", "end")
            self.text_out.insert("1.0", pkg)
            messagebox.showinfo("Done", "Encryption complete.")
        else:
            path = self.file_path.get()
            if not path:
                messagebox.showwarning("Missing file", "Please select a file to encrypt.")
                return
            data = read_file(path)
            salt, cipher = encrypt_bytes(data, key)
            pkg_text = package_text(salt, cipher, DELIM)
            save = filedialog.asksaveasfilename(defaultextension=".enc.txt")
            if save:
                write_file(save, pkg_text.encode("utf-8"))
                messagebox.showinfo("Saved", f"Encrypted file saved to:\n{save}")

class DecryptFrame(ttk.Frame):
    def __init__(self, root: App):
        super().__init__(root)
        self.root = root

        self.mode = tk.StringVar(value="text")
        mode_bar = ttk.Frame(self); mode_bar.pack(fill="x", pady=6)
        ttk.Radiobutton(mode_bar, text="Text Mode", value="text", variable=self.mode).pack(side="left", padx=4)
        ttk.Radiobutton(mode_bar, text="File Mode", value="file", variable=self.mode).pack(side="left", padx=4)

        self.text_in = tk.Text(self, height=18, wrap="word", bg="#111527", fg=DARK_FG, insertbackground=DARK_FG)
        self.text_in.pack(fill="both", expand=True, padx=4, pady=4)

        self.file_path = tk.StringVar()
        file_bar = ttk.Frame(self); file_bar.pack(fill="x")
        ttk.Entry(file_bar, textvariable=self.file_path, state="readonly").pack(side="left", fill="x", expand=True, padx=4)
        ttk.Button(file_bar, text="Browse…", command=self.browse_file).pack(side="left")

        key_bar = ttk.Frame(self); key_bar.pack(fill="x", pady=6)
        ttk.Label(key_bar, text="Key:").pack(side="left")
        self.key_var = tk.StringVar()
        self.key_entry = ttk.Entry(key_bar, textvariable=self.key_var, show="*")
        self.key_entry.pack(side="left", fill="x", expand=True, padx=6)
        self.showing = False
        ttk.Button(key_bar, text="Show", command=self.toggle_key).pack(side="left", padx=4)
        ttk.Button(key_bar, text="Copy Key", command=self.copy_key).pack(side="left", padx=4)

        action_bar = ttk.Frame(self); action_bar.pack(fill="x", pady=8)
        ttk.Button(action_bar, text="Decrypt", command=self.on_decrypt).pack(side="left")

        ttk.Label(self, text="Output:").pack(anchor="w")
        self.text_out = tk.Text(self, height=12, wrap="word", bg="#0d1222", fg=DARK_FG, insertbackground=DARK_FG)
        self.text_out.pack(fill="both", expand=False, padx=4, pady=4)
        out_bar = ttk.Frame(self); out_bar.pack(fill="x")
        ttk.Button(out_bar, text="Copy Output", command=self.copy_output).pack(side="left", padx=4)
        ttk.Button(out_bar, text="Save Output…", command=self.save_output_text).pack(side="left", padx=4)

        self.mode.trace_add("write", lambda *_: self.update_mode_visibility())
        self.update_mode_visibility()

    def browse_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)

    def toggle_key(self):
        self.showing = not self.showing
        self.key_entry.configure(show="" if self.showing else "*")

    def copy_key(self):
        copy_to_clipboard(self.root, self.key_var.get())
        messagebox.showinfo("Copied", "Key copied to clipboard.")

    def copy_output(self):
        copy_to_clipboard(self.root, self.text_out.get("1.0", "end-1c"))
        messagebox.showinfo("Copied", "Output copied to clipboard.")

    def save_output_text(self):
        data_text = self.text_out.get("1.0", "end-1c")
        if not data_text.strip():
            messagebox.showwarning("Nothing to save", "Output area is empty.")
            return
        path = filedialog.asksaveasfilename()
        if path:
            with open(path, "wb") as f:
                f.write(data_text.encode("utf-8"))
            messagebox.showinfo("Saved", f"Saved to:\n{path}")

    def update_mode_visibility(self):
        is_text = self.mode.get() == "text"
        self.text_in.configure(state="normal" if is_text else "disabled")

    def on_decrypt(self):
        key = sanitize_key(self.key_var.get())
        try:
            validate_key_or_raise(key)
        except ValueError as e:
            messagebox.showerror("Invalid key", str(e)); return

        if self.mode.get() == "text":
            pkg = self.text_in.get("1.0", "end-1c")
            if not pkg.strip():
                messagebox.showwarning("Missing input", "Please paste the encrypted text.")
                return
            try:
                salt, cipher = unpackage_text(pkg, DELIM)
                plain = decrypt_bytes(salt, cipher, key)
                self.text_out.delete("1.0", "end")
                # decode as UTF-8 for display, but keep replacement to avoid errors
                self.text_out.insert("1.0", plain.decode("utf-8", errors="replace"))
                messagebox.showinfo("Done", "Decryption complete.")
            except Exception:
                messagebox.showerror("Error", "Decryption failed. Wrong key or corrupted input.")
        else:
            path = self.file_path.get()
            if not path:
                messagebox.showwarning("Missing file", "Please select an encrypted file.")
                return
            try:
                pkg_text = read_file(path).decode("utf-8")
                salt, cipher = unpackage_text(pkg_text, DELIM)
                plain = decrypt_bytes(salt, cipher, key)
                save = filedialog.asksaveasfilename()
                if save:
                    write_file(save, plain)
                    messagebox.showinfo("Saved", f"Decrypted file saved to:\n{save}")
            except Exception:
                messagebox.showerror("Error", "Decryption failed. Wrong key or corrupted file.")

if __name__ == "__main__":
    App().mainloop()
