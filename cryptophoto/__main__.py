from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

class AES:
    def __init__(self, key=None):
        """
        Initializes the encryptor with AES-256 key.
        
        Args:
            key (bytes, optional): 32-byte key. If None, generates a new one.
        """
        if key is None:
            self.key = get_random_bytes(32)
        elif len(key) == 32:
            self.key = key
        else:
            raise ValueError("Key must be 32 bytes for AES-256")
    
    def encrypt(self, input_path, output_path):
        """
        Encrypts an image using AES-256 CBC.
        
        Args:
            input_path (str): Path to the original image
            output_path (str): Path to save the encrypted image
        
        Returns:
            bytes: IV used for encryption
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        # Read image data
        with open(input_path, 'rb') as f:
            image_data = f.read()
        
        # Generate IV and create cipher
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        
        # Encrypt with padding
        encrypted_data = cipher.encrypt(pad(image_data, AES.block_size))
        
        # Save IV + encrypted data
        with open(output_path, 'wb') as f:
            f.write(iv + encrypted_data)
        
        return iv
    
    def decrypt(self, input_path, output_path):
        """
        Decrypts an encrypted image.
        
        Args:
            input_path (str): Path to the encrypted image
            output_path (str): Path to save the decrypted image
        """
        if not os.path.exists(input_path):
            raise FileNotFoundError(f"File not found: {input_path}")
        
        # Read encrypted file
        with open(input_path, 'rb') as f:
            data = f.read()
        
        # Extract IV (16 bytes) and encrypted data
        iv = data[:16]
        encrypted_data = data[16:]
        
        # Create cipher and decrypt
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        
        # Save decrypted image
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)
    
    def get_key(self):
        """
        Returns the encryption key.
        
        Returns:
            bytes: AES-256 key
        """
        return self.key
    
    def save_key(self, key_path):
        """
        Saves the key to a file.
        
        Args:
            key_path (str): Path to save the key
        """
        with open(key_path, 'wb') as f:
            f.write(self.key)
    
    @classmethod
    def load_from_keyfile(cls, key_path):
        """
        Creates instance by loading key from file.
        
        Args:
            key_path (str): Path to the key file
        
        Returns:
            AES: Instance with loaded key
        """
        with open(key_path, 'rb') as f:
            key = f.read()
        return cls(key)

    @classmethod
    def create_with_new_key(cls):
        """
        Creates a new instance with a randomly generated key.
        
        Returns:
            AES: New instance with random key
        """
        return cls()