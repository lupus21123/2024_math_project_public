import socket
import json
import logging
import argparse

import math

def isprime(p):
    if p < 2:
        return False

    limit_p = int(math.sqrt(p)) + 1

    for i in range(2, limit_p):
        if p % i == 0:
            return False
    return True

def verify_rsa(d, e, p, q):
    result = (e *  d) % ((p-1) * (q-1))
    if result == 1:
        return True
    else:
        return False

def handle_bob_connection(sock):

    initial_message = json.dumps({
        "opcode": 0,
        "type": "RSAKey"
    })
    sock.sendall(initial_message.encode('utf-8'))
    logging.info("[*] Sent initial RSA key exchange request to Bob.")

    logging.info("[*] Waiting to receive the prime numbers and the keys from Bob...")
    message = sock.recv(4096).decode('utf-8')
    logging.info(f"[*] Received message from Bob: {message}")

    try:
        data = json.loads(message)
    except json.JSONDecodeError as e:
        logging.error(f"[!] Failed to decode JSON message: {e}")
        return

    if data.get("opcode") == 0 and data.get("type") == "RSAKey":
        private_key = data["private"]
        public_key = data["public"]
        p = data["parameter"]["p"]
        q = data["parameter"]["q"]
        logging.info("[*] Received the prime numbers and the keys from Bob.")

    if isprime(p) and isprime(q):
        logging.info("[*] p and q are prime numbers.")
    elif isprime(p) == True and isprime(q) == False:
        logging.info("[*] p is prime number but q is not prime numbers.")
    elif isprime(p) == False and isprime(q) == True:
        logging.info("[*] q is prime number but p is not prime numbers.")
    else:
        logging.info("[*] p and q are not prime numbers.")

    if verify_rsa(private_key, public_key, p, q) == True:
        logging.info("[*] The RSA keypair is correct.")
        logging.info(f"[*] private key is {private_key} and public key is {public_key}")


def run_alice(addr, port):
    alice_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    alice_socket.connect((addr, port))
    logging.info(f"[*] Alice connected to Bob on {addr}:{port}")

    handle_bob_connection(alice_socket)
    alice_socket.close()
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", type=str, required=True, help="Bob's IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", type=str, default="DEBUG", help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run_alice(args.addr, args.port)