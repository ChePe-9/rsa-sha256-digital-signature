from cryptography.hazmat.primitives import serialization

def load_server_private_key(file_path):
    with open(file_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    return private_key

def load_server_public_key(file_path):
    with open(file_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())
    return public_key

def load_client_public_key(file_path):
    with open(file_path, "rb") as f:
        client_public_key = serialization.load_pem_public_key(f.read())
    return client_public_key