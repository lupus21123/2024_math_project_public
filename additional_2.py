import json
import base64
import sys
from Crypto.Cipher import AES

file_path = sys.argv[1] if len(sys.argv) > 1 else 'adv_protocol_two.log'

data = []
with open(file_path, 'r') as file:
    for line in file:
        line = line.strip()
        if line: 
            try:
                data.append(json.loads(line)) 
            except json.JSONDecodeError as e:
                print(f"Error decoding line: {line}\n{e}")

def rsa_decrypt(private_key, parameter, encrypted_data):
    decrypted_data = pow(encrypted_data, private_key, parameter)
    return decrypted_data

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modular_inverse(d, phi):
    gcd, x, y = extended_gcd(d, phi)
    return x % phi

def prime_factors(n):
    factors = []
    divisor = 2

    while n > 1:
        while n % divisor == 0:
            factors.append(divisor) 
            n //= divisor
        divisor += 1

    return factors

def aes_decrypt(encrypted_message, symmetric_key):
    aes = AES.new(symmetric_key, AES.MODE_ECB)
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted = aes.decrypt(encrypted_message)
    pad = decrypted[-1]
    decrypted = decrypted[:-pad].decode('utf-8') 
    return decrypted

public_key = data[1]['public']
n = data[1]['parameter']['n']
parameters = prime_factors(n)
phi = (parameters[0]-1)*(parameters[1]-1)
private_key = modular_inverse(public_key, phi)

encrypted_key = data[2]['encrypted_key']
decrypted_key = []
for i in range(len(encrypted_key)):
    decrypted_key.append(rsa_decrypt(private_key, n, encrypted_key[i]))
symmetric_key = bytes(decrypted_key)

encrypted_message = data[3]['encryption']
decrypted_message = aes_decrypt(encrypted_message, symmetric_key)
print(f'The message is "{decrypted_message}"')