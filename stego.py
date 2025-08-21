from stegano import lsb
from PIL import Image

HIDDEN_PASSWORD_FOR_DECRYPTION = "MySecureVaultKey123!" 

def embed_password(image_path, password, output_path):
    try:
        # Check if the image exists
        if not os.path.exists(image_path):
            print(f"Error: Cover image '{image_path}' not found.")
            print("Please ensure you have a PNG image in your 'static' folder (e.g., 'static/my_cover_image.png').")
            return

        img = Image.open(image_path)
        if img.mode not in ('RGB', 'RGBA'):
            img = img.convert('RGB')
        
        secret = lsb.hide(img, password) 
        secret.save(output_path)
        print(f"Password embedded successfully in '{image_path}' and saved to '{output_path}'")
    except Exception as e:
        print(f"An error occurred while embedding the password: {e}")

if __name__ == "__main__":
    import os
    # Ensure the static directory exists
    if not os.path.exists("static"):
        os.makedirs("static")

    COVER_IMAGE_NAME = "my_cover_image.png" # <<< CHANGE THIS to your actual image name
    COVER_IMAGE_PATH = os.path.join("static", COVER_IMAGE_NAME)
    OUTPUT_IMAGE_PATH = "static/hidden_image.png"

    print(f"Attempting to embed password into {COVER_IMAGE_PATH}...")
    embed_password(COVER_IMAGE_PATH, HIDDEN_PASSWORD_FOR_DECRYPTION, OUTPUT_IMAGE_PATH)