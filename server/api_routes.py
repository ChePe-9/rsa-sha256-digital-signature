from fastapi import APIRouter, HTTPException
import logging
import os
from server import crypto_operations
from server.keys_manager import load_server_private_key, load_server_public_key, load_client_public_key
from server.crypto_operations import sign_message, verify_signature
from cryptography.hazmat.primitives import serialization

logging.basicConfig(level=logging.DEBUG)

router = APIRouter()

private_key = load_server_private_key("keys/server_private.pem")
public_key = load_server_public_key("keys/server_public.pem")
client_public_key = load_client_public_key("keys/client_public.pem")

@router.post("/verify")
async def verify_signature_route(data: dict):
    logging.debug(f"Received data: {data}")
    try:
        if 'message' not in data or 'signature' not in data:
            raise ValueError("Missing required fields: 'message' and 'signature'")
        encrypted_message = bytes.fromhex(data['message'])
        signature = bytes.fromhex(data['signature'])
        is_valid = verify_signature(client_public_key, encrypted_message, signature)
        if not is_valid:
            raise ValueError("Signature verification failed")
        decrypted_message = crypto_operations.decrypt_message(private_key, encrypted_message)
        logging.debug(f"Decrypted Message: {decrypted_message.decode()}")

        return {"status": "success", "decrypted_message": decrypted_message.decode()}
    except Exception as e:
        logging.error(f"Error during verification: {e}")
        raise HTTPException(status_code=400, detail={"status": "failure", "error": str(e)})

@router.get("/generate_message")
async def generate_message():
    original_message = b"Hello, Client!"
    encrypted_message = crypto_operations.encrypt_message(client_public_key, original_message)
    signature = sign_message(private_key, encrypted_message)

    return {
        "message": encrypted_message.hex(),
        "signature": signature.hex()
    }

@router.get("/get_public_key")
async def get_public_key():
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return {"public_key": pem.decode()}