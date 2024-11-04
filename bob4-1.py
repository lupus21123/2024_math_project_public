### Bob's Code
import socket
import threading
import argparse
import logging
import json
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
import sympy  # Import sympy to check if a number is prime
import math
import sys

### Prime and Generator Utilities for Bob
# Function to check if a number is prime
def is_special(p):
    if p < 2:
        return False

    limit_p = int(math.sqrt(p)) + 1

    for i in range(2, limit_p):
        if p % i == 0:
            return False
    return True

# Function to find a generator for prime p
def check_generator(p):
    while True: 
        remainders = set()
        g = random.randint(1, p - 1)
        # 1부터 p-1까지의 거듭제곱을 반복
        for exponent in range(1, p):
            remainder = pow(g, exponent, p)  # g^(1~p-1) % p 계산
            remainders.add(remainder)        # 나머지 값을 리스트에 추가.
        # 1부터 p-1까지의 모든 값을 포함하는지 확인
        if remainders == set(range(1, p)):
            return g

# Function to generate a large prime number
def generate_large_prime():
    min_val = 400
    max_val = 500

    while True:
        candidate = random.randint(min_val, max_val)
        if sympy.isprime(candidate):
            return candidate

### Diffie-Hellman Key Exchange for Bob
# Function to generate a Diffie-Hellman key pair
def generate_dh_keypair(PRIME, generator):
    private_key = random.randint(1, PRIME - 1) # b
    public_key = pow(generator, private_key, PRIME) # g^b mod p 
    return private_key, public_key

# Function to create the shared secret
def create_shared_secret(private_key, other_public_key, PRIME):
    return pow(other_public_key, private_key, PRIME)

### AES Encryption and Decryption for Bob
# AES Encryption function
def aes_encrypt(shared_secret, message):
    key = (str(shared_secret).encode() * 16)[:32]  # Repeat the shared secret to make a 32-byte key
    logging.info('key: ', key)
    logging.info('shared_secret', shared_secret)
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    return encrypted

# AES Decryption function
def aes_decrypt(shared_secret, encrypted_message):
    key = (str(shared_secret).encode() * 16)[:32]  # Repeat the shared secret to make a 32-byte key
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted.decode()

### Handler for Bob
# Handler function for Bob
def handler(sock):
    PRIME = generate_large_prime()  # 4-byte prime number
    generator = check_generator(PRIME)  # Generator
    logging.info('Generator: {}'.format(generator))

    private_key, public_key = generate_dh_keypair(PRIME, generator) # b, g^b mod p

    # Print p and g
    logging.info("Bob using p (prime): {} and g (generator): {}".format(PRIME, generator))

    # Send p and g to Alice
    init_message = json.dumps({"opcode": 0, "p": PRIME, "g": generator})
    logging.info("Bob sending p and g to Alice: {}".format(init_message))
    sock.sendall(init_message.encode())

    # Communication loop
    while True:
        data = sock.recv(1024).decode()
        if not data:
            break

        logging.info("Bob received data: {}".format(data))
        data_json = json.loads(data)
        opcode = data_json.get("opcode")

        if opcode == 1:  # DH public key exchange
            alice_public_key = int(data_json["public"])  # g^a mod p

            # Create shared secret
            shared_secret = create_shared_secret(private_key, alice_public_key, PRIME)  # g^ab mod p
            logging.info("Bob created shared secret: {}".format(shared_secret))

            # Send Bob's DH public key
            response = json.dumps({"opcode": 1, "type": "DH", "public": public_key})
            logging.info("Bob sending DH public key: {}".format(response))
            sock.sendall(response.encode())

        elif opcode == 2:  # AES-encrypted message from Alice
            encrypted_message = bytes.fromhex(data_json["encryption"])

            # Decrypt the message
            decrypted_message = aes_decrypt(shared_secret, encrypted_message)
            logging.info("Decrypted message from Alice: {}".format(decrypted_message))
            
            message_to_alice = input("Enter a message to send to Alice: ")

            # Encrypt a response message using AES
            encrypted_response = aes_encrypt(shared_secret, message_to_alice).hex()
            if message_to_alice.lower() == "exit":
                response_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_response})
                sock.sendall(response_message.encode())
                logging.info("You quit the chat")
                sys.exit()
                break
            else: 
                response_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_response})
                logging.info("Bob sending AES-encrypted response: {}".format(response_message))
                sock.sendall(response_message.encode())

        elif opcode == 3:  # Error or quit message from Alice
            if "error" in data_json:
                # Print the error message from Alice
                error_message = data_json["error"]
                logging.error("Error from Alice: {}".format(error_message))
            else:
                logging.info("Alice quit the chat")
            sys.exit()
            break

### Run Function for Bob
# Run function for Bob
def run(addr, port):
    bob = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bob.bind((addr, port))
    bob.listen(5)
    logging.info("Bob is listening on {}:{}".format(addr, port))

    while True:
        conn, info = bob.accept()
        logging.info("Bob accepted a connection from {}:{}".format(info[0], info[1]))
        threading.Thread(target=handler, args=(conn, )).start()

### Command Line Argument Parsing for Bob
# Command line argument parsing
def command_line_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", metavar="<bob's address>", help="Bob's address", type=str, default="0.0.0.0")
    parser.add_argument("-p", "--port", metavar="<bob's port>", help="Bob's port", type=int, required=True)
    parser.add_argument("-l", "--log", metavar="<log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)>", help="Log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)", type=str, default="INFO")
    args = parser.parse_args()
    return args

### Main Function for Bob
# Main function
def main():
    args = command_line_args()
    log_level = args.log
    logging.basicConfig(level=log_level)
    run(args.addr, args.port)

if __name__ == "__main__":
    main()
