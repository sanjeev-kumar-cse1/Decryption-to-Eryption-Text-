from Crypto.Cipher import AES, DES
import base64
import rsa

def pad(text, block_size):
    padding = ' ' * (block_size - len(text) % block_size)
    return text + padding

def aes_encrypt(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    encrypted_text = base64.b64encode(cipher.encrypt(pad(text, 16).encode('utf-8')))
    return encrypted_text.decode('utf-8')

def aes_decrypt(encrypted_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode('utf-8').strip()
    return decrypted_text

def des_encrypt(text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    encrypted_text = base64.b64encode(cipher.encrypt(pad(text, 8).encode('utf-8')))
    return encrypted_text.decode('utf-8')

def des_decrypt(encrypted_text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decrypted_text = cipher.decrypt(base64.b64decode(encrypted_text)).decode('utf-8').strip()
    return decrypted_text

def rsa_generate_keys():
    (public_key, private_key) = rsa.newkeys(512)
    return public_key, private_key

def rsa_encrypt(text, public_key):
    encrypted_text = rsa.encrypt(text.encode('utf-8'), public_key)
    return encrypted_text

def rsa_decrypt(encrypted_text, private_key):
    decrypted_text = rsa.decrypt(encrypted_text, private_key).decode('utf-8')
    return decrypted_text

def main():
    text = input("Enter the text to be encrypte in the (AES/DES/RSA): ")

    aes_key = "thisisaeskey1234"  
    aes_encrypted = aes_encrypt(text, aes_key)
    aes_decrypted = aes_decrypt(aes_encrypted, aes_key)
    print("\n=== AES ===")
    print(f"Encrypted (AES): {aes_encrypted}")
    print(f"Decrypted (AES): {aes_decrypted}")

    des_key = "deskey12"  
    des_encrypted = des_encrypt(text, des_key)
    des_decrypted = des_decrypt(des_encrypted, des_key)
    print("\n=== DES ===")
    print(f"Encrypted (DES): {des_encrypted}")
    print(f"Decrypted (DES): {des_decrypted}")

    rsa_public_key, rsa_private_key = rsa_generate_keys()
    rsa_encrypted = rsa_encrypt(text, rsa_public_key)
    rsa_decrypted = rsa_decrypt(rsa_encrypted, rsa_private_key)
    print("\n=== RSA ===")
    print(f"Encrypted (RSA): {rsa_encrypted.hex()}")
    print(f"Decrypted (RSA): {rsa_decrypted}")

if __name__ == "__main__":
    main()
