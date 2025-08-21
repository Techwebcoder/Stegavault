from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os


HIDDEN_PASSWORD_FOR_DECRYPTION = "MySecureVaultKey123!" # Choose a strong password

# Modified to accept an optional output_path
def encrypt_file(file_path, key, output_path=None):
    try:
        if not os.path.exists(file_path):
            print(f"Error: File to encrypt '{file_path}' not found.")
            return

        with open(file_path, 'rb') as f:
            data = f.read()

        cipher_key = pad(key.encode(), AES.block_size)
        cipher = AES.new(cipher_key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, AES.block_size))

        # Determine output path
        final_output_path = output_path if output_path else file_path + '.enc'

        with open(final_output_path, 'wb') as f:
            f.write(encrypted)
        print(f"File '{file_path}' encrypted and saved to '{final_output_path}'")
    except Exception as e:
        print(f"An error occurred during encryption: {e}")
        raise # Re-raise to be caught by main.py's messagebox

def decrypt_file(file_path, key):
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Encrypted file '{file_path}' not found.")

        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        cipher_key = pad(key.encode(), AES.block_size)
        cipher = AES.new(cipher_key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        return decrypted
    except ValueError as e:
        if "Padding is incorrect" in str(e) or "Ciphertext length must be multiple of 16" in str(e):
            raise ValueError("Incorrect key or corrupted data.")
        else:
            raise e
    except Exception as e:
        print(f"An unexpected error occurred during decryption: {e}")
        raise e

if __name__ == "__main__":
    # Ensure the vault directory exists
    if not os.path.exists("vault"):
        os.makedirs("vault")

    SECRET_FILE_NAME = "secret_file.txt"
    SECRET_FILE_PATH = os.path.join("vault", SECRET_FILE_NAME)
    ENCRYPTED_FILE_PATH = SECRET_FILE_PATH + '.enc'

    # Create a dummy secret_file.txt if it doesn't exist
    if not os.path.exists(SECRET_FILE_PATH):
        print(f"'{SECRET_FILE_PATH}' not found. Creating a dummy file.")
        with open(SECRET_FILE_PATH, 'w') as f:
            f.write("This is the highly confidential secret message from the main vault.\n")
            f.write("This file is automatically placed here by the setup script.\n")
            f.write("You can add other files and encrypt them with different passwords.")

    print(f"Attempting to encrypt '{SECRET_FILE_PATH}'...")
    encrypt_file(SECRET_FILE_PATH, HIDDEN_PASSWORD_FOR_DECRYPTION)