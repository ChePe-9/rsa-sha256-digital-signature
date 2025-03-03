import requests

def send_verification_request(message_hex, signature_hex):
    response = requests.post('http://127.0.0.1:8000/verify', json={
        "message": message_hex,
        "signature": signature_hex
    })
    return response.json()

def get_server_message():
    response = requests.get('http://127.0.0.1:8000/generate_message')
    data = response.json()
    return bytes.fromhex(data['message']), bytes.fromhex(data['signature'])