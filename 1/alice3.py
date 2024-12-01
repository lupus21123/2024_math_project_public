import socket
import argparse
import logging
import base64
import binascii
import json
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import math

### AES Encryption and Decryption for Alice
# AES Encryption function
def aes_encrypt(shared_secret, message):
    # 숫자 형태의 shared_secret을 바이트로 변환하고, 2바이트로 인코딩
    shared_secret_bytes = shared_secret.to_bytes(2, byteorder="big")
    
    # 32바이트 키 생성 (repeat shared secret)
    key = (shared_secret_bytes * 16)[:32]  # Repeat the shared secret to make a 32-byte key

    # AES 암호화
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(message.encode(), AES.block_size))
    
    return base64.b64encode(encrypted).decode()

## AES Decryption function
# def aes_decrypt(shared_secret, encrypted_message):
#     key = (str(shared_secret).encode() * 16)[:32]  # Repeat the shared secret to make a 32-byte key
#     cipher = AES.new(key, AES.MODE_ECB)
#     decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
#     return decrypted.decode()

def aes_decrypt(shared_secret, encrypted_message):
    # 숫자 형태의 shared_secret을 바이트로 변환하고, 2바이트로 인코딩
    shared_secret_bytes = shared_secret.to_bytes(2, byteorder="big")
    # 32바이트 키 생성 (repeat shared secret)
    key = (shared_secret_bytes * 16)[:32]  # Repeat the shared secret to make a 32-byte key
    # AES 복호화
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    
    return decrypted.decode()

### Run Function for Alice
# Run function for Alice
def run(addr, port):
    # Connect to Bob
    message_to_bob = input("Enter a message to send to Bob: ")
    alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice.connect((addr, port))
    logging.info("Alice connected to Bob at {}:{}".format(addr, port))
    # send basic opcode
    request = json.dumps({"opcode":0, "type": "DH"})
    logging.info("Alice sends opcode 0: {}".format(request))
    alice.sendall(request.encode())


    # Receive p and g from Bob
    #while True:
    response = alice.recv(1024).decode()
    logging.info("check: {}".format(response))
    
    response_json = json.loads(response)
    logging.info("Alice received response: {}".format(response_json))
    bob_public_key = response_json["public"]

    #response_json = json.loads(response)
    opcode = response_json.get("opcode")

    if opcode == 1:  # Received p and g from Bob
        received_p = response_json.get("parameter", {}).get("p")
        received_g = response_json.get("parameter", {}).get("g")

        # Generate DH key pair
        private_key = random.randint(1, received_p - 1)  # a
        public_key = pow(received_g, private_key, received_p)  # g^a mod p

        # Send DH public key
        message = json.dumps({"opcode": 1, "type": "DH", "public": public_key})
        logging.info("Alice sending DH public key: {}".format(message))
        alice.sendall(message.encode()) # g^a mod p
        
        # 기다림
        response = alice.recv(1024).decode()
        logging.info("error test: {}".format(response))
        response_json = json.loads(response)
        #logging.info("error test: {}".format(bob_public_key))
        
        # Create shared secret
        shared_secret = pow(bob_public_key, private_key, received_p)  # g^ab mod p
        logging.info("Alice created shared secret: {}".format(shared_secret))
        logging.info("Bob encryption: {}".format(response_json["encryption"]))
        #encrypted_message = response_json["encryption"]
        encrypted_message = binascii.a2b_base64(response_json["encryption"])
        #encrypted_message = base64.b64decode(response_json["encryption"])
        decrypted_message = aes_decrypt(shared_secret, encrypted_message)
        logging.info("Decrypted message from Bob: {}".format(decrypted_message))

        #message_to_bob = input("Enter a message to send to Bob: ")

        #Encrypt a message using AES
        encrypted_message = aes_encrypt(shared_secret, message_to_bob)
        # if message_to_bob.lower() == "exit":
        #     aes_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_message})
        #     alice.sendall(aes_message.encode())
        #     logging.info('You quit the chat')
            # else:
        aes_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_message})
        logging.info("Alice sending AES-encrypted message: {}".format(aes_message))
        alice.sendall(aes_message.encode())


    # Communication loop
    while True:
        response = alice.recv(1024).decode()
        if not response:
            break

        logging.info("Alice received response: {}".format(response))
        response_json = json.loads(response)
        opcode = response_json.get("opcode")

        # if opcode == 1:  # Received DH public key from Bob 
        #     bob_public_key = response_json["public"]

        #     # Create shared secret
        #     shared_secret = pow(bob_public_key, private_key, received_p)  # g^ab mod p
        #     logging.info("Alice created shared secret: {}".format(shared_secret))

        #     message_to_bob = input("Enter a message to send to Bob: ")

        #     # Encrypt a message using AES
        #     encrypted_message = aes_encrypt(shared_secret, message_to_bob).hex()
        #     if message_to_bob.lower() == "exit":
        #         aes_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_message})
        #         alice.sendall(aes_message.encode())
        #         logging.info('You quit the chat')
        #         break
        #     else:
        #         aes_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_message})
        #         logging.info("Alice sending AES-encrypted message: {}".format(aes_message))
        #         alice.sendall(aes_message.encode())

        #elif opcode == 2:  # Received AES-encrypted response from Bob
        encrypted_response = binascii.a2b_base64(response_json["encryption"])
        decrypted_response = aes_decrypt(shared_secret, encrypted_response)
        logging.info("Decrypted response from Bob: {}".format(decrypted_response))
        message_to_bob = input("Enter a message to send to Bob: ")
        encrypted_message = aes_encrypt(shared_secret, message_to_bob)
        if message_to_bob.lower() == "exit":
            aes_message = json.dumps({"opcode": 3, "type": "AES", "encryption": encrypted_message})
            alice.sendall(aes_message.encode())
            logging.info('You quit the chat')
            break
        else:
            aes_message = json.dumps({"opcode": 2, "type": "AES", "encryption": encrypted_message})
            logging.info("Alice sending AES-encrypted message: {}".format(aes_message))
            alice.sendall(aes_message.encode())

        # elif opcode == 3:  # Quit chat 나중에 추가할수있으면 추가.
        #     logging.info("Bob quit the chat")
        #     break

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
