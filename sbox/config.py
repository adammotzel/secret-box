"""
App config.
"""

import os


APP_DIR_NAME = "tsb"
BOX_NAME = "the.sbox"
CONFIRM_PHRASE = "The inner machinations of my mind are an enigma"
SALT_SIZE = 16          # bytes
IV_SIZE = 12            # recommended size for AES-GCM
KEY_SIZE = 32           # AES-256 requires a 32-byte key
TIME_COST = 10          # Argon2 time cost (number of iterations)
MEMORY_COST = 512000    # Argon2 memory cost in KB (500 MB)
PARALLELISM = 2         # number of threads used in Argon2

# only works for Windows OS
base = os.getenv("LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
path = os.path.join(base, APP_DIR_NAME)
os.makedirs(path, exist_ok=True)

ENCRYPTED_FILE = os.path.join(path, BOX_NAME)
