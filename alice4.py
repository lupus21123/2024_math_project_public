import socket
import argparse
import logging
import json
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import sympy  # Import sympy to check if a number is prime
import math

### AES Encryption and Decryption for Alice
# AES Encryption function
def aes_encrypt(shared_secret, message):
    key = (str(shared_secret).encode() * 16)[:32]  # Repeat the shared secret to make a 32-byte key
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted

# AES Decryption function
def aes_decrypt(shared_secret, encrypted_message):
    key = (str(shared_secret).encode() * 16)[:32]  # Repeat the shared secret to make a 32-byte key
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted.decode()

def is_prime(n):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def is_generator(n, g):
    if g==1: 
        return False
    modulo = []
    for i in range(1, n):
        a = g ** i % n
        modulo.append(a)
        if a in modulo: 
            return False
    return True

### Run Function for Alice
def run(addr, port):
    # Connect to Bob
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("Alice connected to Bob at {}:{}".format(addr, port))

    # Receive p and g from Bob
    response = alice.recv(1024).decode()
    logging.info("Alice received response: {}".format(response))
    response_json = json.loads(response)
    opcode = response_json.get("opcode")

    if opcode == 0:  # Received p and g from Bob
        received_p = response_json.get("p")
        received_g = response_json.get("g")

        # Step 1: Validate if p is a prime number
        if not is_prime(received_p):
            error_message = json.dumps({"opcode": 3, "error": "incorrect prime number"})
            alice.sendall(error_message.encode())
            logging.error("Received p is not a prime number")
            alice.close()
            return

        # Step 2: Validate if g is a generator
        if not is_generator(received_p, received_g):
            error_message = json.dumps({"opcode": 3, "error": "incorrect generator"})
            alice.sendall(error_message.encode())
            logging.error("Received g is not a valid generator")
            alice.close()
            return

        # If both checks pass, proceed with Diffie-Hellman key pair generation
        private_key = random.randint(1, received_p - 1)  # a
        public_key = pow(received_g, private_key, received_p)  # g^a mod p

        # Send DH public key to Bob
        message = json.dumps({"opcode": 1, "type": "DH", "public": public_key})
        logging.info("Alice sending DH public key: {}".format(message))
        alice.sendall(message.encode())

    # Communication loop for handling further messages
    while True:
        response = alice.recv(1024).decode()
        if not response:
            break

        logging.info("Alice received response: {}".format(response))
        response_json = json.loads(response)
        opcode = response_json.get("opcode")

        if opcode == 1:  # Received DH public key from Bob
            bob_public_key = response_json["public"]

            # Create shared secret
            shared_secret = pow(bob_public_key, private_key, received_p)  # g^ab mod p
            logging.info("Alice created shared secret: {}".format(shared_secret))

            # Encrypt and send message to Bob
            message_to_bob = input("Enter a message to send to Bob: ")
            encrypted_message = aes_encrypt(shared_secret, message_to_bob).hex()
            if message_to_bob.lower() == "exit":
                aes_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_message})
                alice.sendall(aes_message.encode())
                logging.info('You quit the chat')
                break
            else:
                aes_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_message})
                logging.info("Alice sending AES-encrypted message: {}".format(aes_message))
                alice.sendall(aes_message.encode())

        elif opcode == 2:  # Received AES-encrypted response from Bob
            encrypted_response = bytes.fromhex(response_json["encryption"])
            decrypted_response = aes_decrypt(shared_secret, encrypted_response)
            logging.info("Decrypted response from Bob: {}".format(decrypted_response))
            message_to_bob = input("Enter a message to send to Bob: ")
            encrypted_message = aes_encrypt(shared_secret, message_to_bob).hex()
            if message_to_bob.lower() == "exit":
                aes_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_message})
                alice.sendall(aes_message.encode())
                logging.info('You quit the chat')
                break
            else:
                aes_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_message})
                logging.info("Alice sending AES-encrypted message: {}".format(aes_message))
                alice.sendall(aes_message.encode())

        elif opcode == 3:  # Quit chat
            logging.info("Bob quit the chat")
            break

    alice.close()

### Command Line Argument Parsing for Alice
# Command line argument parsing
def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, required=True)
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

### Main Function for Alice
# Main function
def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.addr, args.port)

if __name__ == "__main__":
    main()
