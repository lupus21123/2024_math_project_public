import json
import binascii
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import logging

possible_shared_secrets = range(1, 1000)

def aes_decrypt(encrypted_message_base64, shared_secret):
    try:
        encrypted_message = binascii.a2b_base64(encrypted_message_base64)
        shared_secret_bytes = shared_secret.to_bytes(2, byteorder="big")
        key = (shared_secret_bytes * 16)[:32]
        cipher = AES.new(key, AES.MODE_ECB)
        decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
        return decrypted.decode()
    except (ValueError, binascii.Error):
        return None

log_file_path = 'adv_protocol_three.log'

with open(log_file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line:
            try:
                log_entry = json.loads(line)
                opcode = log_entry.get("opcode")

                if opcode == 0:
                    print(f"Diffie-Hellman initialization: {log_entry}")
                elif opcode == 1:
                    print(f"Public key exchange: {log_entry}")
                elif opcode == 2 and "encryption" in log_entry:
                    encrypted_message = log_entry["encryption"]
                    decrypted_success = False

                    for guess in possible_shared_secrets:
                        decrypted_message = aes_decrypt(encrypted_message, guess)
                        if decrypted_message:
                            print(f"Shared secret found (shared_secret={guess}): {decrypted_message}")
                            decrypted_success = True
                            break

                    if not decrypted_success:
                        print("Failed to decrypt message with all guesses.")
                else:
                    print(f"Other log entry: {log_entry}")
            except json.JSONDecodeError:
                print(f"Failed to parse line: {line}")
