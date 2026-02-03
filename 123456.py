import streamlit as st
import base64
import os
import qrcode
import cv2
import numpy as np
from io import BytesIO
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

# --- CORE LOGIC FUNCTIONS ---

def generate_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# --- STREAMLIT UI ---

st.set_page_config(page_title="Secure QR Vault", page_icon="🔐")
st.title("🔐 Secure QR genrator with encryption")

tab1, tab2 = st.tabs(["🔐Create QR", "Read/Decrypt QR"])

# --- TAB 1: GENERATION ---
with tab1:
    st.header("Generate Encrypted QR")
    data_to_hide = st.text_area("Message to Encrypt:")
    gen_password = st.text_input("Set Password:", type="password", key="gen_pass")

    if st.button("Generate Secure QR"):
        if data_to_hide and gen_password:
            # Encryption Process
            salt = os.urandom(16)
            key = generate_key(gen_password, salt)
            cipher = Fernet(key)
            encrypted_data = cipher.encrypt(data_to_hide.encode())
            
            # Combine salt and data
            final_payload = base64.urlsafe_b64encode(salt + encrypted_data).decode()
            
            # Generate QR
            qr_img = qrcode.make(final_payload)
            
            # Convert to displayable format
            buf = BytesIO()
            qr_img.save(buf, format="PNG")
            
            st.image(buf, caption="Encrypted QR Code")
            st.download_button("Download QR Code", buf.getvalue(), "secure_qr.png", "image/png")
        else:
            st.warning("Please provide both text and a password.")

# --- TAB 2: DECRYPTION ---
with tab2:
    st.header("Decrypt QR Code")
    uploaded_file = st.file_uploader("Upload your Secure QR image", type=['png', 'jpg', 'jpeg'])
    dec_password = st.text_input("Enter Decryption Password:", type="password", key="dec_pass")

    if uploaded_file and dec_password:
        # Convert uploaded file to OpenCV format
        file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
        img = cv2.imdecode(file_bytes, 1)
        
        # Detect QR
        detector = cv2.QRCodeDetector()
        data, _, _ = detector.detectAndDecode(img)
        
        if data:
            try:
                # Process Data
                decoded_payload = base64.urlsafe_b64decode(data.encode())
                salt = decoded_payload[:16]
                encrypted_text = decoded_payload[16:]
                
                # Derive Key and Decrypt
                key = generate_key(dec_password, salt)
                cipher = Fernet(key)
                decrypted_message = cipher.decrypt(encrypted_text).decode()
                
                st.success("Decryption Successful!")
                st.info(f"Hidden Message: {decrypted_message}")
            except Exception:
                st.error("Incorrect password or corrupted QR code.")
        else:
            st.error("No QR Code detected in the image.")
