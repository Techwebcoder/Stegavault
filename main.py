from tkinter import *
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from stegano import lsb
from encrypt_decrypt import decrypt_file, encrypt_file
import os
import subprocess
import sys

WINDOW_WIDTH = 700
WINDOW_HEIGHT = 500
WINDOW_GEOMETRY = f"{WINDOW_WIDTH}x{WINDOW_HEIGHT}"

ACCESS_PASSWORD = "firstpass"

HIDDEN_IMAGE_PATH = "static/hidden_image.png"
VAULT_DIRECTORY = "vault"

def open_file_externally(filepath):
    try:
        if sys.platform == "win32":
            os.startfile(filepath)
        elif sys.platform == "darwin": # macOS
            subprocess.run(["open", filepath])
        else: # linux variants
            subprocess.run(["xdg-open", filepath])
    except Exception as e:
        messagebox.showerror("File Open Error", f"Could not open file: {e}")

def verify_initial_password():
    if entry.get() == ACCESS_PASSWORD:
        root.destroy()
        show_image_window()
    else:
        result_label.config(text="Wrong password!", fg="red")

def show_image_window():
    image_window = Tk()
    image_window.title("Hidden Vault Access Key")
    image_window.geometry(WINDOW_GEOMETRY)

   
    image_frame = Frame(image_window)
    image_frame.pack(expand=True) 

    def on_click(event):
        
        x, y = event.x, event.y
        print(f"Clicked at: {x}, {y}")

        hotspot_x, hotspot_y = 150, 150
        radius = 50

        if (hotspot_x - radius < x < hotspot_x + radius) and \
           (hotspot_y - radius < y < hotspot_y + radius):
            try:
                print("Clicked within the password zone. Attempting to reveal vault key...")
                vault_access_key = lsb.reveal(HIDDEN_IMAGE_PATH)
                
                if vault_access_key:
                    print(f"Vault access key revealed. Length: {len(vault_access_key)}")
                    image_window.destroy()
                    show_vault_manager(vault_access_key)
                else:
                    print("No hidden key found in the image. Ensure it was embedded.")
                    messagebox.showerror("Steganography Error", "No hidden key found in the image.")
            except Exception as e:
                if "Impossible to detect message" in str(e):
                    messagebox.showerror("Access Error", f"No hidden key found in '{HIDDEN_IMAGE_PATH}'.\n"
                                                              "Please ensure 'stego.py' was run to embed the key.")
                else:
                    messagebox.showerror("Error", f"An unexpected error occurred during vault access: {e}")
        else:
            print("Clicked outside the password zone. Please click within the target area.")

    try:
        img = Image.open(HIDDEN_IMAGE_PATH)
        img = img.resize((300, 300), Image.Resampling.LANCZOS)
        photo = ImageTk.PhotoImage(img)

        label = Label(image_frame, image=photo) 
        label.image = photo # Keep a reference to prevent garbage collection
        label.pack() # Pack within the image_frame
        label.bind("<Button-1>", on_click)
    except FileNotFoundError:
        messagebox.showerror("File Error", f"Error: Image '{HIDDEN_IMAGE_PATH}' not found. "
                                           "Please ensure it exists and 'stego.py' was run to create it.")
        image_window.destroy()
    except Exception as e:
        messagebox.showerror("Image Error", f"Error loading image: {e}")
        image_window.destroy()

    image_window.mainloop()


def show_vault_manager(vault_access_key):
    vault_manager_window = Tk()
    vault_manager_window.title("Secure Vault Manager")
    vault_manager_window.geometry(WINDOW_GEOMETRY) # Set consistent size

    file_list_frame = LabelFrame(vault_manager_window, text="Files in Your Vault", padx=10, pady=10)
    file_list_frame.pack(padx=20, pady=10, fill="both", expand=True)

    file_listbox = Listbox(file_list_frame, font=('Arial', 10)) # Let pack expand fill it
    file_listbox.pack(side="left", fill="both", expand=True)

    scrollbar = Scrollbar(file_list_frame, orient="vertical", command=file_listbox.yview)
    scrollbar.pack(side="right", fill="y")
    file_listbox.config(yscrollcommand=scrollbar.set)

    def refresh_file_list():
        file_listbox.delete(0, END) # Clear existing entries
        if not os.path.exists(VAULT_DIRECTORY):
            os.makedirs(VAULT_DIRECTORY) # Create vault if it doesn't exist

        files_in_vault = sorted(os.listdir(VAULT_DIRECTORY))
        if not files_in_vault:
            file_listbox.insert(END, "Vault is empty. Add new files below.")
            file_listbox.config(state=DISABLED) # Make it unselectable if empty
        else:
            file_listbox.config(state=NORMAL)
            for filename in files_in_vault:
                # Display original name for .enc files, otherwise full name
                display_name = filename.replace(".enc", "") if filename.endswith(".enc") else filename
                status = "(Encrypted)" if filename.endswith(".enc") else "(Regular File)"
                file_listbox.insert(END, f"{display_name} {status}")
                
    refresh_file_list() # Load files initially

    def on_file_click(event):
        selected_index = file_listbox.curselection()
        if selected_index:
            display_text = file_listbox.get(selected_index[0])
            if "Vault is empty" in display_text:
                return # Do nothing if placeholder is clicked

            # Extract the actual filename from the display text
            actual_filename_in_vault = display_text.split('(')[0].strip()
            # Append .enc if it was originally an encrypted file
            if "(Encrypted)" in display_text:
                actual_filename_in_vault += ".enc"

            full_filepath = os.path.join(VAULT_DIRECTORY, actual_filename_in_vault)

            if actual_filename_in_vault.endswith(".enc"):
                # It's an encrypted file, prompt for password
                password = simpledialog.askstring("Decryption Password", f"Enter password for '{os.path.basename(full_filepath).replace('.enc', '')}':", show='*', parent=vault_manager_window)
                if password:
                    try:
                        decrypted_content = decrypt_file(full_filepath, password)
                        
                        # Save decrypted content to a temporary file and open it
                        temp_dir = "temp_decrypted"
                        if not os.path.exists(temp_dir):
                            os.makedirs(temp_dir)
                        
                        # Construct a safe temporary filename
                        temp_filename = os.path.basename(full_filepath).replace(".enc", "")
                        temp_filepath = os.path.join(temp_dir, temp_filename)
                        
                        # Handle potential existing temp file by appending a number
                        counter = 1
                        while os.path.exists(temp_filepath):
                            name, ext = os.path.splitext(os.path.basename(full_filepath).replace(".enc", ""))
                            temp_filename = f"{name}_temp{counter}{ext}"
                            temp_filepath = os.path.join(temp_dir, temp_filename)
                            counter += 1

                        with open(temp_filepath, 'wb') as f:
                            f.write(decrypted_content)
                        
                        messagebox.showinfo("Decryption Success", f"File decrypted to temporary location and will be opened:\n{temp_filepath}", parent=vault_manager_window)
                        open_file_externally(temp_filepath)

                    except ValueError: # Catches "Incorrect key or corrupted data."
                        messagebox.showerror("Decryption Failed", "Incorrect password for this file.", parent=vault_manager_window)
                    except FileNotFoundError:
                        messagebox.showerror("File Error", f"Encrypted file not found: {full_filepath}", parent=vault_manager_window)
                    except Exception as e:
                        messagebox.showerror("Decryption Error", f"An error occurred during decryption: {e}", parent=vault_manager_window)
                else:
                    messagebox.showwarning("Decryption Cancelled", "Password not provided.", parent=vault_manager_window)
            else:
                # It's a regular file, open it directly
                messagebox.showinfo("Opening File", f"Opening '{os.path.basename(full_filepath)}'...", parent=vault_manager_window)
                open_file_externally(full_filepath)

    file_listbox.bind("<<ListboxSelect>>", on_file_click)

    # --- Buttons for managing files ---
    button_frame = Frame(vault_manager_window, pady=10)
    button_frame.pack(pady=10)

    def add_new_file_to_vault():
        filepath = filedialog.askopenfilename(title="Select File to Add to Vault")
        if filepath:
            password = simpledialog.askstring("Encrypt File", f"Enter password for '{os.path.basename(filepath)}':", show='*', parent=vault_manager_window)
            if password:
                try:
                    output_file_name = os.path.basename(filepath) + ".enc"
                    target_vault_path = os.path.join(VAULT_DIRECTORY, output_file_name)
                    
                    encrypt_file(filepath, password, output_path=target_vault_path)
                    messagebox.showinfo("Success", f"File '{os.path.basename(filepath)}' encrypted and added to vault!", parent=vault_manager_window)
                    refresh_file_list()
                except Exception as e:
                    messagebox.showerror("Encryption Error", f"Failed to encrypt and add file: {e}", parent=vault_manager_window)
            else:
                messagebox.showwarning("Encryption Cancelled", "Password not provided.", parent=vault_manager_window)

    Button(button_frame, text="Add New File to Vault (Encrypt)", command=add_new_file_to_vault, padx=10, pady=5).pack(side=LEFT, padx=10)

    def delete_selected_file():
        selected_index = file_listbox.curselection()
        if not selected_index:
            messagebox.showwarning("No Selection", "Please select a file to delete.", parent=vault_manager_window)
            return
        
        display_text = file_listbox.get(selected_index[0])
        if "Vault is empty" in display_text:
            return

        actual_filename_in_vault = display_text.split('(')[0].strip()
        if "(Encrypted)" in display_text:
            actual_filename_in_vault += ".enc"

        full_filepath = os.path.join(VAULT_DIRECTORY, actual_filename_in_vault)

        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete '{display_text}' from the vault?", parent=vault_manager_window):
            try:
                os.remove(full_filepath)
                messagebox.showinfo("Deleted", f"'{display_text}' removed from vault.", parent=vault_manager_window)
                refresh_file_list()
            except OSError as e:
                messagebox.showerror("Delete Error", f"Could not delete file: {e}", parent=vault_manager_window)

    Button(button_frame, text="Delete Selected File", command=delete_selected_file, padx=10, pady=5).pack(side=LEFT, padx=10)

    vault_manager_window.mainloop()

if __name__ == "__main__":
    root = Tk()
    root.title("Secure Vault Access")
    root.geometry(WINDOW_GEOMETRY)

    root.grid_rowconfigure(0, weight=1)
    root.grid_rowconfigure(4, weight=1)
    root.grid_columnconfigure(0, weight=1)

    Label(root, text="Enter Initial Password to Access Vault:", font=('Arial', 12)).grid(row=1, column=0, pady=10)
    entry = Entry(root, show="*", width=30, font=('Arial', 12))
    entry.grid(row=2, column=0, pady=5)
    entry.focus_set()

    Button(root, text="Submit", command=verify_initial_password, padx=15, pady=5, font=('Arial', 10)).grid(row=3, column=0, pady=10)
    result_label = Label(root, text="", fg="red", font=('Arial', 10))
    result_label.grid(row=4, column=0, pady=5)

    root.mainloop()