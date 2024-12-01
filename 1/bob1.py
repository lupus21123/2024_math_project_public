import socket
import json
import logging
import argparse
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
    phi = (p - 1) * (q - 1)
    while True:
        e = random.randrange(3, phi, 2)
        result = extended_gcd(e, phi)
        if result[0] == 1:
            break

    d = modular_inverse(e, phi)

    private_key = d
    public_key = e

    return private_key, public_key, p, q

def run_bob(addr, port):
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
    if data.get("opcode") == 0 and data.get("type") == "RSAKey":
        logging.info("[*] Generating RSA key pair after receiving Alice's request...")
        private_key, public_key, p, q = generate_rsa_keypair()
        rsa_keypair = {"private key": private_key, "public key": public_key, "p": p, "q":q}
        logging.info(f"[*] Generated RSA key pair : {rsa_keypair}")

        public_key_message = json.dumps({
            "opcode": 0,
            "type": "RSAKey",
            "private":private_key,
            "public": public_key,
            "parameter": {"p": p, "q":q}
        })
        conn.sendall(public_key_message.encode('utf-8'))
        logging.info("[*] Sent RSA public key to Alice.")
        conn.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--addr", type=str, default="0.0.0.0", help="Bob's IP address")
    parser.add_argument("-p", "--port", type=int, required=True, help="Bob's port")
    parser.add_argument("-l", "--log", type=str, default="DEBUG", help="Logging level")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log.upper()))
    run_bob(args.addr, args.port)