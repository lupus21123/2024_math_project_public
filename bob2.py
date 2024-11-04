import socket
import base64
import json
import logging
import argparse
from Crypto.Cipher import AES
import random
import math

def isprime(p):
    if p < 2:
        return False

    limit_p = int(math.sqrt(p)) + 1

    for i in range(2, limit_p):
        if p % i == 0:
            return False
    return True

def generate_small_prime():
    while True:
        candidate = random.randint(400, 500)
        if isprime(candidate):
            return candidate

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(e, phi):
    gcd, x, y = extended_gcd(e, phi)
    return x % phi

def generate_rsa_keypair():
    p = generate_small_prime()
    q = generate_small_prime()
    while p == q:
        q = generate_small_prime()
    n = p * q
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randrange(3, phi, 2)
        result = extended_gcd(e, phi)
        if result[0] == 1:
            break

    d = modular_inverse(e, phi)

    private_key = d
    public_key = e

    return private_key, public_key, n


def rsa_decrypt(private_key, parameter, encrypted_data):
    decrypted_data = pow(encrypted_data, private_key, parameter)
    return decrypted_data

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


def handle_alice_connection(sock, private_key, parameter, input_message):
    logging.info("[*] Waiting to receive data from Alice...")
    message = sock.recv(4096).decode('utf-8')
    logging.info(f"[*] Received data from Alice: {message}")

    try:
        data = json.loads(message)
    except json.JSONDecodeError as e:
        logging.error(f"[!] Failed to decode JSON message: {e}")
        return

    if data.get("opcode") == 2 and data.get("type") == "RSA":
        logging.info("[*] Received RSA-encrypted symmetric key from Alice.")
        encrypted_key = data["encrypted_key"]
        decrypted_key = []
        for i in range(len(encrypted_key)):
            decrypted_key.append(rsa_decrypt(private_key, parameter, encrypted_key[i]))
        symmetric_key = bytes(decrypted_key)

        logging.info(f"[*] Decrypted symmetric key: {symmetric_key}")

        encrypted_message = aes_encrypt(input_message, symmetric_key)

        response = json.dumps({
            "opcode": 2,
            "type": "AES",
            "encryption": encrypted_message
        })
        sock.sendall(response.encode('utf-8'))
        logging.info("[*] Sent AES-encrypted message to Alice.")

        message_from_alice = sock.recv(4096).decode('utf-8')
        logging.info(f"[*] Received AES-encrypted message from Alice: {message_from_alice}")

        data_from_alice = json.loads(message_from_alice)
        if data_from_alice.get("opcode") == 2 and data_from_alice.get("type") == "AES":
            encrypted_message_from_alice = data_from_alice["encryption"]
            decrypted_message = aes_decrypt(encrypted_message_from_alice, symmetric_key)
            logging.info(f"[*] Decrypted AES message from Alice: {decrypted_message}")


def run_bob(addr, port, input_message):
    bob_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob_socket.bind((addr, port))
    bob_socket.listen(1)
    logging.info(f"[*] Bob is listening on {addr}:{port}")

    logging.info("[*] Waiting for initial message from Alice...")
    conn, _ = bob_socket.accept()
    logging.info("[*] Connection accepted from Alice.")
    
    message = conn.recv(4096).decode('utf-8')
    logging.info(f"[*] Received initial message from Alice: {message}")
    
    data = json.loads(message)
    if data.get("opcode") == 0 and data.get("type") == "RSA":
        logging.info("[*] Generating RSA key pair after receiving Alice's request...")
        private_key, public_key, n = generate_rsa_keypair()
        rsa_keypair = {"private key": private_key, "public key": public_key, "parameter": n}
        logging.info(f"[*] Generated RSA key pair : {rsa_keypair}")

        public_key_message = json.dumps({
            "opcode": 1,
            "type": "RSA",
            "public": public_key,
            "parameter": {"n": n}
        })
        conn.sendall(public_key_message.encode('utf-8'))
        logging.info("[*] Sent RSA public key to Alice.")
    
        handle_alice_connection(conn, private_key, n, input_message)
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", type=str, default="0.0.0.0", help="Bob's IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", type=str, default="DEBUG", help="Logging level")
    parser.add_argument("-m", "--message", type=str, required=True, help="Input message to encrypt")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run_bob(args.addr, args.port, args.message)