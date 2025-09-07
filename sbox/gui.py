"""
Interact with the Secret Box using a GUI.
"""

import os
import tkinter as tk
from tkinter import messagebox, simpledialog

from sbox.config import ENCRYPTED_FILE, CONFIRM_PHRASE
from sbox.core import encrypt_data, decrypt_data, secure_delete


class TheSecretBox:
    """
    A Tkinter-based password manager that encrypts and stores password entries
    in a secure file, protected by a master password.

    Parameters
    ----------
    root : tk.Tk
        The root window object for the Tkinter application.
    """

    def __init__(self, root):
        """
        Initialize the Secret Box application and build the login screen.

        Parameters
        ----------
        root : tk.Tk
            The root window of the Tkinter GUI.
        """
        self.root = root
        self.root.title("The Secret Box")
        self.root.geometry("500x420")

        self.build_login_screen()

    def build_login_screen(self):
        """
        Build the login screen UI where the user enters their master password
        to unlock the Secret Box.
        """
        self.clear_root()

        tk.Label(self.root, text="Enter your master password:").pack(pady=(60, 10))
        self.password_entry = tk.Entry(self.root, show="*", width=40)
        self.password_entry.pack()
        self.password_entry.focus_set()

        tk.Label(self.root, text="Press Enter or click 'Unlock Secret Box'", fg="gray").pack(pady=(5, 15))

        # bind 'Enter' key to the unlock handler
        self.password_entry.bind("<Return>", lambda event: self.handle_unlock())

        tk.Button(self.root, text="Unlock Secret Box", command=self.handle_unlock).pack(pady=20)

        # spacer for visual clarity
        tk.Label(self.root, text="").pack(expand=True)

        tk.Button(self.root, text="Create New Secret Box", fg="green", command=self.create_sbox).pack(pady=1)

        tk.Button(self.root, text="Delete Secret Box", fg="red", command=self.handle_delete_vault).pack(pady=(10, 15))

    def create_sbox(self):
        """
        Create a new Secret Box by asking the user to enter and confirm a master password.
        Encrypts and stores an empty password dictionary.
        """
        if os.path.exists(ENCRYPTED_FILE):
            messagebox.showerror(
                "Error", 
                "A Secret Box already exists. Please delete it if you want to create a new one."
            )
            return

        pw = simpledialog.askstring(
            "Create Secret Box", 
            "Please enter the master password for your Secret Box:",
            show="*"
        )

        if not pw:
            messagebox.showerror("Error", "Please enter a valid password.")
            return
        
        pw2 = simpledialog.askstring(
            "Create Secret Box", 
            "Please re-enter the master password:",
            show="*"
        )

        if pw != pw2:
            messagebox.showerror("Error", "Passwords did not match.")
            del pw
            del pw2
            return
        
        del pw2

        # encrypt empty password dictionary using the entered password
        encrypt_data({}, pw)
        del pw

        messagebox.showinfo("Secret Box Created", "New Secret Box created successfully.")
        self.build_vault_editor({})

    def handle_unlock(self):
        """
        Handle unlocking the Secret Box by validating the master password.
        If successful, displays the password vault editor.
        """
        password = self.password_entry.get()
        self.password_entry.delete(0, tk.END)

        # handle empty passwords
        if not password:
            messagebox.showerror("Error", "Please enter your password.")
            self.password_entry.focus_set()
            return

        # handle non-existent vaults
        if not os.path.exists(ENCRYPTED_FILE):
            messagebox.showerror(
                "Error", "No Secret Box found. Please create a new one using the 'Create New Secret Box' button."
            )
            del password
            self.password_entry.focus_set()
            return

        try:
            data = decrypt_data(password)
            del password
            self.build_vault_editor(data)
        except Exception:
            del password
            messagebox.showerror("Failed to Decrypt", "The password is incorrect, or the file is corrupted.")
            self.password_entry.focus_set()
            return

    def build_vault_editor(self, data: dict):
        """
        Build the vault editor UI where users can view, add, edit, or delete passwords.

        Parameters
        ----------
        data : dict
            The decrypted password data where keys are contexts and values are passwords.
        """
        self.clear_root()

        tk.Label(self.root, text="Passwords:").pack(pady=(10, 5))

        self.rows_frame = tk.Frame(self.root)
        self.rows_frame.pack(pady=10)

        tk.Label(self.rows_frame, text="Context", width=25, anchor="center",
                font=("Arial", 10, "bold")).grid(row=0, column=0, padx=5, pady=2)
        tk.Label(self.rows_frame, text="Password", width=25, anchor="center",
                font=("Arial", 10, "bold")).grid(row=0, column=1, padx=5, pady=2)

        self.entry_rows = []
        self.current_row = 1

        for site, password in data.items():
            self.add_row(site, password)

        tk.Button(self.root, text="+ Add Password", command=self.add_row).pack(pady=10)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=10)

        tk.Button(btn_frame, text="Save and Encrypt", command=self.handle_save).pack(side=tk.LEFT, padx=10)
        tk.Button(btn_frame, text="Exit Secret Box", command=self.root.quit).pack(side=tk.LEFT, padx=10)

    def handle_delete_vault(self):
        """
        Handle deletion of the encrypted Secret Box file after user confirmation.
        """
        if not os.path.exists(ENCRYPTED_FILE):
            messagebox.showinfo(
                "Secret Box Not Found", 
                "There is no existing Secret Box to delete."
            )
            return

        confirm = messagebox.askyesno(
            "Warning",
            "Deleting your Secret Box is permanent and cannot be undone.\n\n"
            "Are you sure you want to proceed?"
        )

        if not confirm:
            return

        user_input = simpledialog.askstring(
            "Removal Confirmation",
            "To permanently delete the Secret Box, type:\n\n"
            f"'{CONFIRM_PHRASE}'"
        )

        if user_input != CONFIRM_PHRASE:
            messagebox.showwarning(
                "Not Confirmed", 
                "Secret Box was not deleted. Confirmation phrase was incorrect."
            )
            return

        try:
            secure_delete(path=ENCRYPTED_FILE)
            messagebox.showinfo(
                "Secret Box Deleted", 
                "Your Secret Box has been permanently deleted."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete the Secret Box.\n{e}")

    def add_row(self, context: str = "", password: str = ""):
        """
        Add a new row to the vault editor for entering or modifying a password.

        Parameters
        ----------
        context : str, optional
            The context or label for the password (e.g., site name). Default is an empty 
            string.
        password : str, optional
            The actual password associated with the context. Default is an empty string.
        """
        row_index = self.current_row

        context_entry = tk.Entry(self.rows_frame, width=30)
        context_entry.grid(row=row_index, column=0, padx=5, pady=2)
        context_entry.insert(0, context)

        password_entry = tk.Entry(self.rows_frame, width=30)
        password_entry.grid(row=row_index, column=1, padx=5, pady=2)
        password_entry.insert(0, password)

        def remove_row():
            """Remove a row from the UI."""
            context_entry.destroy()
            password_entry.destroy()
            remove_btn.destroy()
            self.entry_rows.remove((context_entry, password_entry))

        remove_btn = tk.Button(self.rows_frame, text="Delete", command=remove_row)
        remove_btn.grid(row=row_index, column=2, padx=5)

        self.entry_rows.append((context_entry, password_entry))
        self.current_row += 1

    def handle_save(self):
        """
        Encrypt and save all password entries using the master password.
        """
        password = simpledialog.askstring(
            "Password Required", 
            "Re-enter your master password to encrypt the Secret Box:", 
            show="*"
        )
        if not password:
            messagebox.showerror("Error", "Password is required to encrypt.")
            return

        try:
            data = {}
            for context_entry, password_entry in self.entry_rows:
                site = context_entry.get().strip()
                pwd = password_entry.get().strip()
                if site:
                    data[site] = pwd

            encrypt_data(data, password)

            del password
            del data

            messagebox.showinfo(
                "Success", 
                "Secret Box encrypted and saved.\nYou may now safely exit the app."
            )
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed.\n{e}")

    def clear_root(self):
        """
        Clear all widgets from the root window.
        """
        for widget in self.root.winfo_children():
            widget.destroy()
