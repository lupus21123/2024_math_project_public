import socket
import base64
import json
import logging
import argparse
from Crypto.Cipher import AES
import random

def generate_symmetric_key():
    key = random.randbytes(32)
    return key

def rsa_encrypt(public_key,parameter, data):
    encrypted_data = pow(data, public_key, parameter)
    return encrypted_data

BLOCK_SIZE = 16

def aes_encrypt(message, symmetric_key):
    pad = BLOCK_SIZE - len(message)
    message = message + pad * chr(pad)
    aes = AES.new(symmetric_key, AES.MODE_ECB)
    encrypted = aes.encrypt(message.encode())    
    return base64.b64encode(encrypted).decode('utf-8')

def aes_decrypt(encrypted_message, symmetric_key):
    aes = AES.new(symmetric_key, AES.MODE_ECB)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted = aes.decrypt(encrypted_message)
    pad = decrypted[-1]
    decrypted = decrypted[:-pad].decode('utf-8') 
    return decrypted

def handle_bob_connection(sock, input_message):

    initial_message = json.dumps({
        "opcode": 0,
        "type": "RSA"
    })
    sock.sendall(initial_message.encode('utf-8'))
    logging.info("[*] Sent initial RSA key exchange request to Bob.")

    logging.info("[*] Waiting to receive RSA public key from Bob...")
    message = sock.recv(4096).decode('utf-8')
    logging.info(f"[*] Received message from Bob: {message}")

    try:
        data = json.loads(message)
    except json.JSONDecodeError as e:
        logging.error(f"[!] Failed to decode JSON message: {e}")
        return

    if data.get("opcode") == 1 and data.get("type") == "RSA":
        public_key = data["public"]
        n = data["parameter"]["n"]
        logging.info("[*] Received RSA public key from Bob.")

        symmetric_key = generate_symmetric_key()
        int_values = list(symmetric_key)

        logging.info(f"[*] Generated symmetric key from: {symmetric_key}")
        encrypted_symmetric_key = []
        for i in range(len(int_values)):
            encrypted_symmetric_key.append(rsa_encrypt(public_key, n, int_values[i]))
        response = json.dumps({
            "opcode": 2,
            "type": "RSA",
            "encrypted_key": encrypted_symmetric_key
        })
        sock.sendall(response.encode('utf-8'))
        logging.info("[*] Sent encrypted symmetric key to Bob.")

        message = sock.recv(4096).decode('utf-8')
        logging.info(f"[*] Received AES-encrypted message from Bob: {message}")

        data = json.loads(message)
        if data.get("opcode") == 2 and data.get("type") == "AES":
            encrypted_message = data["encryption"]
            decrypted_message = aes_decrypt(encrypted_message, symmetric_key)
            logging.info(f"[*] Decrypted AES message from Bob: {decrypted_message}")

        encrypted_message_for_bob = aes_encrypt(input_message, symmetric_key)

        response_to_bob = json.dumps({
            "opcode": 2,
            "type": "AES",
            "encryption": encrypted_message_for_bob
        })
        sock.sendall(response_to_bob.encode('utf-8'))
        logging.info("[*] Sent AES-encrypted message to Bob.")

def run_alice(addr, port, input_message):
    alice_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_socket.connect((addr, port))
    logging.info(f"[*] Alice connected to Bob on {addr}:{port}")

    handle_bob_connection(alice_socket, input_message)
    alice_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", type=str, required=True, help="Bob's IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", type=str, default="DEBUG", help="Logging level")
    parser.add_argument("-m", "--message", type=str, required=True, help="Input message to encrypt")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run_alice(args.addr, args.port, args.message)
