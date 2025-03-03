import keys_manager
import crypto_operations
import network_operations

if __name__ == '__main__':
    # Сценарий 1
    private_key = keys_manager.load_client_private_key()
    message = b"Hello, Server!"
    signature = crypto_operations.sign_message(private_key, message)

    if not isinstance(message, bytes) or not isinstance(signature, bytes):
        print("Ошибка: Некорректный формат данных.")
        exit(1)

    message_hex = message.hex()
    signature_hex = signature.hex()

    print("Отправляемые данные:")
    print(f"Message (hex): {message_hex}")
    print(f"Signature (hex): {signature_hex}")

    response_data = network_operations.send_verification_request(message_hex, signature_hex)
    print("Сценарий 1:", response_data)

    # Сценарий 2
    server_public_key = keys_manager.load_server_public_key()
    message, signature = network_operations.get_server_message()

    is_valid = crypto_operations.verify_signature(server_public_key, message, signature)
    print("Сценарий 2:", "Подпись верна" if is_valid else "Подпись неверна")