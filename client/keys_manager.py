from cryptography.hazmat.primitives import serialization
import requests

def load_server_public_key():
    response = requests.get('http://127.0.0.1:8000/get_public_key')
    public_key_pem = response.json()['public_key']
    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    
    print("Загруженный публичный ключ сервера:")
    print(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())
    
    return public_key

def load_client_private_key():
    with open("keys/client_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key