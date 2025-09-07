"""
Run the app locally.
"""

import os
import sys

import tkinter as tk

from sbox.gui import TheSecretBox


def get_icon_path():
    """Utility to get the icon path."""
    
    if getattr(sys, "frozen", False):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(__file__)
    return os.path.join(base_path, "app.ico")


if __name__ == "__main__":
    root = tk.Tk()
    root.iconbitmap(get_icon_path())
    app = TheSecretBox(root)
    root.mainloop()
