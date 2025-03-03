
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Генерация ключей для сервера
server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
server_public_key = server_private_key.public_key()

with open("keys/server_private.pem", "wb") as f:
    f.write(server_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("keys/server_public.pem", "wb") as f:
    f.write(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

# Генерация ключей для клиента
client_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
client_public_key = client_private_key.public_key()

with open("keys/client_private.pem", "wb") as f:
    f.write(client_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

with open("keys/client_public.pem", "wb") as f:
    f.write(client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))

print("Ключи успешно сгенерированы!")