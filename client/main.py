import keys_manager
import crypto_operations
import network_operations

if __name__ == '__main__':
    # Сценарий 1: Шифрование и подпись сообщения
    private_key = keys_manager.load_client_private_key()
    server_public_key = keys_manager.load_server_public_key()

    original_message = b"Hello, Server!"

    # Шифрование сообщения с помощью публичного ключа сервера
    encrypted_message = crypto_operations.encrypt_message(server_public_key, original_message)

    # Подпись зашифрованного сообщения
    signature = crypto_operations.sign_message(private_key, encrypted_message)

    # Преобразование в hex для передачи
    encrypted_message_hex = encrypted_message.hex()
    signature_hex = signature.hex()

    print("Отправляемые данные:")
    print(f"Encrypted Message (hex): {encrypted_message_hex}")
    print(f"Signature (hex): {signature_hex}")

    # Отправка данных на сервер
    response_data = network_operations.send_verification_request(encrypted_message_hex, signature_hex)
    print("Сценарий 1:", response_data)

    # Сценарий 2: Получение и дешифрование сообщения от сервера
    encrypted_message, signature = network_operations.get_server_message()

    # Проверка подписи
    is_valid = crypto_operations.verify_signature(server_public_key, encrypted_message, signature)
    if not is_valid:
        print("Сценарий 2: Подпись неверна")
    else:
        # Дешифрование сообщения с помощью приватного ключа клиента
        decrypted_message = crypto_operations.decrypt_message(private_key, encrypted_message)
        print("Сценарий 2: Подпись верна")
        print(f"Decrypted Message: {decrypted_message.decode()}")